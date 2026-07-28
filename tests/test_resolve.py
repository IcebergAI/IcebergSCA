"""Version ordering, range matching and registry resolution."""

from __future__ import annotations

import httpx
import pytest

from icebergsca.cache import Cache
from icebergsca.core.models import Dependency, EcosystemId, PackageRef, Pin, Scope
from icebergsca.core.versions import compare, is_newer, parse
from icebergsca.registry import RegistryClient, version_list_url
from icebergsca.resolve import Resolver, best_match, satisfies
from tests.conftest import MockTransport, make_dependency

NPM = EcosystemId.NPM
PYPI = EcosystemId.PYPI
CARGO = EcosystemId.CARGO
GEM = EcosystemId.RUBYGEMS
NUGET = EcosystemId.NUGET
GO = EcosystemId.GO


# ---------------------------------------------------------------------------
# Version ordering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ecosystem", "lower", "higher"),
    [
        (NPM, "1.0.0", "1.0.1"),
        (NPM, "1.9.0", "1.10.0"),
        (NPM, "1.0.0-rc.1", "1.0.0"),
        (NPM, "1.0.0-alpha", "1.0.0-beta"),
        (PYPI, "1.0.0rc1", "1.0.0"),
        (PYPI, "2.0", "10.0"),
        (GO, "v1.2.3", "v1.3.0"),
        (GEM, "1.2.3", "1.2.10"),
    ],
)
def test_ordering(ecosystem: EcosystemId, lower: str, higher: str) -> None:
    assert compare(ecosystem, lower, higher) == -1
    assert is_newer(ecosystem, higher, lower)


def test_build_metadata_does_not_affect_precedence() -> None:
    assert compare(NPM, "1.0.0+build1", "1.0.0+build2") == 0


def test_unorderable_versions_return_none_rather_than_guessing() -> None:
    """A commit hash is not a version; treating it as one would order it wrongly."""
    assert compare(GO, "abcdef123456", "v1.0.0") is None
    assert parse(NPM, "not-a-version") is None
    assert is_newer(GO, "abcdef", "v1.0.0") is False


# ---------------------------------------------------------------------------
# semver ranges
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("constraint", "version", "expected"),
    [
        ("^1.2.3", "1.2.3", True),
        ("^1.2.3", "1.9.9", True),
        ("^1.2.3", "2.0.0", False),
        ("^1.2.3", "1.2.2", False),
        # Pre-1.0 packages treat the minor as the breaking-change marker.
        ("^0.2.3", "0.2.9", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.0.3", "0.0.3", True),
        ("^0.0.3", "0.0.4", False),
        ("~1.2.3", "1.2.9", True),
        ("~1.2.3", "1.3.0", False),
        ("~1.2", "1.2.9", True),
        ("~1.2", "1.3.0", False),
        (">=1.0.0 <2.0.0", "1.5.0", True),
        (">=1.0.0 <2.0.0", "2.0.0", False),
        ("1.2.x", "1.2.7", True),
        ("1.2.x", "1.3.0", False),
        ("1.x", "1.9.0", True),
        ("1.x", "2.0.0", False),
        ("*", "9.9.9", True),
        ("1.2.3", "1.2.3", True),
        ("1.2.3", "1.2.4", False),
        ("1.2.3 - 2.3.4", "2.0.0", True),
        ("1.2.3 - 2.3.4", "2.4.0", False),
        ("^1.0.0 || ^2.0.0", "2.5.0", True),
        ("^1.0.0 || ^2.0.0", "3.0.0", False),
    ],
)
def test_npm_ranges(constraint: str, version: str, expected: bool) -> None:
    assert satisfies(NPM, version, constraint) is expected


def test_cargo_bare_version_means_caret() -> None:
    """Cargo's "1.2.3" is npm's "^1.2.3", and getting this backwards under-reports."""
    assert satisfies(CARGO, "1.9.0", "1.2.3") is True
    assert satisfies(CARGO, "2.0.0", "1.2.3") is False
    # npm reads the same string as an exact pin.
    assert satisfies(NPM, "1.9.0", "1.2.3") is False


@pytest.mark.parametrize(
    ("constraint", "version", "expected"),
    [
        ("~> 1.2", "1.9.0", True),
        ("~> 1.2", "2.0.0", False),
        ("~> 1.2.3", "1.2.9", True),
        ("~> 1.2.3", "1.3.0", False),
        (">= 2.0", "3.0.0", True),
    ],
)
def test_rubygems_pessimistic_operator(
    constraint: str, version: str, expected: bool
) -> None:
    assert satisfies(GEM, version, constraint) is expected


@pytest.mark.parametrize(
    ("constraint", "version", "expected"),
    [
        ("[1.0,2.0)", "1.5.0", True),
        ("[1.0,2.0)", "2.0.0", False),
        ("[1.0,2.0]", "2.0.0", True),
        ("(1.0,2.0)", "1.0.0", False),
        ("[1.0]", "1.0.0", True),
        ("[1.0]", "1.1.0", False),
        ("(,2.0]", "1.0.0", True),
        ("1.0", "2.0.0", True),  # a bare NuGet version means "this or newer"
    ],
)
def test_nuget_intervals(constraint: str, version: str, expected: bool) -> None:
    assert satisfies(NUGET, version, constraint) is expected


def test_pep440_is_delegated_to_packaging() -> None:
    assert satisfies(PYPI, "2.31.0", ">=2.0,<3.0") is True
    assert satisfies(PYPI, "3.0.0", ">=2.0,<3.0") is False
    assert satisfies(PYPI, "1.2.5", "==1.2.*") is True


def test_unparseable_constraint_returns_none_not_false() -> None:
    """ "We cannot tell" must not be confused with "it does not match"."""
    assert satisfies(NPM, "1.0.0", "not a range at all") is None
    assert satisfies(PYPI, "1.0.0", ">>>garbage") is None


# ---------------------------------------------------------------------------
# best_match
# ---------------------------------------------------------------------------


def test_best_match_picks_the_highest_satisfying_version() -> None:
    versions = ["1.0.0", "1.2.0", "1.9.3", "2.0.0"]
    assert best_match(NPM, versions, "^1.0.0") == "1.9.3"


def test_best_match_skips_prereleases_by_default() -> None:
    """Recommending 3.0.0-rc1 as "what you would install" would simply be wrong."""
    versions = ["2.0.0", "3.0.0-rc.1"]
    assert best_match(NPM, versions, ">=1.0.0") == "2.0.0"


def test_best_match_allows_prereleases_when_asked_for() -> None:
    versions = ["2.0.0", "3.0.0-rc.1"]
    assert best_match(NPM, versions, ">=3.0.0-rc.1") == "3.0.0-rc.1"


def test_best_match_without_a_constraint_takes_the_newest() -> None:
    assert best_match(PYPI, ["1.0", "2.0", "1.5"], None) == "2.0"


def test_best_match_returns_none_when_nothing_satisfies() -> None:
    assert best_match(NPM, ["1.0.0"], "^9.0.0") is None


def test_best_match_ignores_unparseable_versions() -> None:
    assert best_match(NPM, ["garbage", "1.0.0"], "*") == "1.0.0"


# ---------------------------------------------------------------------------
# Registry URLs and name validation
# ---------------------------------------------------------------------------


def test_go_module_paths_are_case_escaped() -> None:
    """The proxy lowercases paths, so uppercase becomes !lowercase."""
    url = version_list_url(GO, "github.com/BurntSushi/toml")
    assert url is not None
    assert "!burnt!sushi" in url


def test_scoped_npm_names_keep_their_at_sign() -> None:
    url = version_list_url(NPM, "@angular/core")
    assert url == "https://registry.npmjs.org/@angular/core"


def test_nuget_names_are_lowercased_for_flat_container() -> None:
    url = version_list_url(NUGET, "Newtonsoft.Json")
    assert url is not None
    assert url.endswith("/newtonsoft.json/index.json")


async def test_path_traversal_in_a_package_name_is_refused() -> None:
    """Names come from files in a scanned repo — untrusted input reaching a URL."""
    transport = MockTransport({})
    client = RegistryClient(httpx.AsyncClient(transport=transport), Cache.memory())

    assert await client.versions(PYPI, "../../etc/passwd") is None
    assert transport.calls == []


async def test_registry_parses_each_response_shape() -> None:
    cases = [
        (PYPI, "requests", {"versions": ["2.30.0", "2.31.0"]}, ["2.30.0", "2.31.0"]),
        (
            NPM,
            "lodash",
            {"versions": {"4.17.20": {}, "4.17.21": {}}},
            ["4.17.20", "4.17.21"],
        ),
        (
            CARGO,
            "serde",
            {"versions": [{"num": "1.0.1"}, {"num": "1.0.2", "yanked": True}]},
            ["1.0.1"],
        ),
        (NUGET, "Serilog", {"versions": ["3.0.0"]}, ["3.0.0"]),
        (GEM, "rails", [{"number": "7.1.0"}], ["7.1.0"]),
    ]
    for ecosystem, name, payload, expected in cases:
        url = version_list_url(ecosystem, name)
        assert url is not None
        transport = MockTransport({f"GET:{url}": payload})
        client = RegistryClient(httpx.AsyncClient(transport=transport), Cache.memory())
        assert await client.versions(ecosystem, name) == expected


async def test_registry_yanked_crates_are_excluded() -> None:
    """A yanked release is installable by exact pin but never freshly resolved to."""
    url = version_list_url(CARGO, "serde")
    assert url is not None
    payload = {"versions": [{"num": "1.0.2", "yanked": True}, {"num": "1.0.1"}]}
    client = RegistryClient(
        httpx.AsyncClient(transport=MockTransport({f"GET:{url}": payload})),
        Cache.memory(),
    )
    assert await client.versions(CARGO, "serde") == ["1.0.1"]


async def test_registry_caches_between_calls() -> None:
    url = version_list_url(PYPI, "requests")
    assert url is not None
    transport = MockTransport({f"GET:{url}": {"versions": ["2.31.0"]}})
    cache = Cache.memory()

    first = RegistryClient(httpx.AsyncClient(transport=transport), cache)
    await first.versions(PYPI, "requests")
    second = RegistryClient(httpx.AsyncClient(transport=transport), cache)
    await second.versions(PYPI, "requests")

    assert len(transport.calls) == 1


async def test_registry_unknown_package_returns_none_not_empty() -> None:
    """None means "we do not know"; [] would mean "it has no releases"."""
    client = RegistryClient(
        httpx.AsyncClient(transport=MockTransport({})), Cache.memory()
    )
    assert await client.versions(PYPI, "nonexistent-package") is None


async def test_registry_offline_makes_no_requests() -> None:
    transport = MockTransport({})
    client = RegistryClient(
        httpx.AsyncClient(transport=transport), Cache.memory(), offline=True
    )
    assert await client.versions(PYPI, "requests") is None
    assert transport.calls == []


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


def unpinned(name: str, constraint: str, ecosystem: EcosystemId = PYPI) -> Dependency:
    return Dependency(
        ref=PackageRef(ecosystem, name, None),
        scope=Scope.RUNTIME,
        direct=True,
        source=make_dependency().source,
        pin=Pin.UNRESOLVED,
        constraint=constraint,
    )


def resolver_for(responses: dict[str, object]) -> Resolver:
    return Resolver(
        RegistryClient(
            httpx.AsyncClient(transport=MockTransport(responses)), Cache.memory()
        )
    )


async def test_resolver_fills_in_a_version_and_marks_it_resolved() -> None:
    url = version_list_url(PYPI, "flask")
    assert url is not None
    result = await resolver_for(
        {f"GET:{url}": {"versions": ["2.0.0", "2.3.3", "3.0.0"]}}
    ).resolve((unpinned("flask", ">=2.0,<3.0"),))

    dep = result.dependencies[0]
    assert dep.ref.version == "2.3.3"
    # RESOLVED, not PINNED: this is what a fresh install would get, not what runs.
    assert dep.pin is Pin.RESOLVED
    assert result.resolved == 1


async def test_resolver_leaves_pinned_dependencies_alone() -> None:
    """A lockfile is a stronger statement than anything a registry says today."""
    pinned = make_dependency("requests", "2.31.0")
    result = await resolver_for({}).resolve((pinned,))
    assert result.dependencies[0] is pinned


async def test_unresolvable_constraint_stays_unresolved_and_is_counted() -> None:
    result = await resolver_for({}).resolve((unpinned("flask", ">=2.0"),))
    dep = result.dependencies[0]
    assert dep.ref.version is None
    assert dep.pin is Pin.UNRESOLVED
    assert result.unresolved == 1


async def test_resolver_queries_each_package_once() -> None:
    url = version_list_url(PYPI, "flask")
    assert url is not None
    transport = MockTransport({f"GET:{url}": {"versions": ["3.0.0"]}})
    resolver = Resolver(
        RegistryClient(httpx.AsyncClient(transport=transport), Cache.memory())
    )
    await resolver.resolve(
        (
            unpinned("flask", ">=2.0"),
            unpinned("flask", ">=2.0"),
            unpinned("flask", ">=2.0"),
        )
    )
    assert len(transport.calls) == 1
