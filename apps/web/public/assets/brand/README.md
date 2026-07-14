# TraceHawk website icons

The project-owner-provided TraceHawk mark is published in two theme-specific variants:

- `tracehawk-icon-light.png`: black mark on a light background;
- `tracehawk-icon-dark.png`: white mark on a dark background.

`index.html` selects the 64 px favicon variant with `prefers-color-scheme`. The dark variant is
also the source for the fallback ICO, Apple touch icon, and web app manifest icons.

Derived files can be rebuilt from the checked-in 512 px masters with ImageMagick:

```bash
magick tracehawk-icon-light.png -resize 64x64 -strip favicon-light.png
magick tracehawk-icon-dark.png -resize 64x64 -strip favicon-dark.png
magick tracehawk-icon-dark.png -resize 180x180 -strip apple-touch-icon.png
magick tracehawk-icon-dark.png -resize 192x192 -strip icon-192.png
magick tracehawk-icon-dark.png -define icon:auto-resize=64,48,32,16 favicon.ico
```
