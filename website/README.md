# IcebergSCA documentation site

The public docs site — built with [Zensical](https://zensical.org/) (the
Material-based static site generator) from `docs/` + `zensical.toml`, styled to
the shared Iceberg design system (`docs/stylesheets/iceberg.css`, self-hosted
fonts).

Deployed to GitHub Pages by `.github/workflows/docs.yml` on every push to
`main` touching `website/**` (Settings → Pages → Source = "GitHub Actions").
The build pins `zensical==0.0.50` — bump deliberately, in step with the sibling
Iceberg sites.

Preview locally:

```bash
pip install zensical==0.0.50
cd website
zensical serve          # http://localhost:8000, live reload
zensical build --clean  # writes site/ (gitignored)
```

Notes:

- `docs/changelog.md` snippet-includes the repo-root `CHANGELOG.md`, so the
  workflow rebuilds on a changelog-only commit too. `check_paths = true` means
  a moved file fails the build rather than emitting an empty page.
- `docs/assets/scan-table.svg` and `scan-multi.svg` are copies of the terminal
  captures in `../docs/img/`. Regenerate those first, then re-copy.
- Nothing is loaded from a CDN: fonts are self-hosted (`font = false` disables
  Google Fonts) and the mermaid fence is configured but deliberately unused,
  since the theme lazy-loads mermaid from unpkg. A supply chain scanner's own
  site should not quietly take a third-party runtime dependency.
- `docs/stylesheets/iceberg.css` carries the family design tokens verbatim from
  the Iceberg (CTI) sheet. Edit them there first, then copy across.
