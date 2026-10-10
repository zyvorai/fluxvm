# Social assets

Palette (apple.com style): white `#ffffff` / `#f5f5f7`, ink `#1d1d1f`, secondary `#6e6e73`,
hairline `#d2d2d7`, blue `#0071e3` to `#2997ff`. Dark variant: `#000` / `#0b0b0f`, text `#f5f5f7`,
cards `#1c1c1e`, blue `#2997ff`. Orange (`#ff6a2a`) appears once, as a dot on the in-tree
FluxVM hypervisor card; the Zyvor logo file keeps its brand colour.

| File | What it is | Rebuild |
|---|---|---|
| `../assets/social-preview.svg` / `.png` / `@2x.png` | 1280x640 README hero, light | `python3 docs/social/build-social-svg.py docs/assets` then `rsvg-convert -w 1280 docs/assets/social-preview.svg -o docs/assets/social-preview.png` (`-w 2560` for `@2x`) |
| `../assets/social-preview-dark.svg` / `.png` / `@2x.png` | Same card for GitHub's dark theme | same, with `social-preview-dark` |
| `fluxvm-share-card.png` | 1200x630 Open Graph / repository social preview; copied to `website/static/img/` as the site's `themeConfig.image` | `./docs/social/build-social-card.sh`, then `cp docs/social/fluxvm-share-card.png website/static/img/` |
| `fluxvm-hero-dark.html` / `.jpg` | 2400x1260 README hero (five backends, including `vz`) | `./docs/social/build-hero-dark.sh` |
| `../assets/mac-cloud.svg` | Animated Mac cloud illustration (README, website, share card); same file as `website/static/img/mac-cloud.svg` | Hand-written SVG; edit one and copy it over the other |
| `fluxvm-social-card.html` / `.jpg` | 1600x900 LinkedIn / X | same script |

`build-social-svg.py` holds the light and dark palettes and generates both SVGs from one layout, so
they cannot drift apart. `rsvg-convert` (librsvg) renders the PNGs; the HTML cards need Google Chrome
and macOS `sips`.

## GitHub repository social preview

GitHub's repository **Social preview** is not settable through the API or `gh`. After changing the
card, upload `docs/social/fluxvm-share-card.png` by hand: repository **Settings > General > Social
preview > Edit > Upload an image**.
