"""Resolving declared version constraints into concrete versions.

Only needed when a project has no lockfile. Anything resolved this way is marked
:attr:`~icebergsca.core.models.Pin.RESOLVED` rather than ``PINNED``, because it
answers "what would a fresh install get today" — not "what is deployed".
"""

from icebergsca.resolve.ranges import best_match, satisfies
from icebergsca.resolve.resolver import Resolver

__all__ = ["Resolver", "best_match", "satisfies"]
