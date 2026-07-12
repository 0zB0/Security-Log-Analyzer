#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "docs/assets/demo"
SOURCES = [
    DEMO / "01-upload-analysis.png",
    DEMO / "02-incident-correlation.png",
    DEMO / "03-report-export.png",
    DEMO / "04-case-correlation.png",
]
OUTPUT = DEMO / "tracehawk-demo.gif"
SIZE = (1280, 720)


def main() -> int:
    images = [Image.open(path).convert("RGB").resize(SIZE, Image.Resampling.LANCZOS) for path in SOURCES]
    frames: list[Image.Image] = []
    durations: list[int] = []
    for index, image in enumerate(images):
        frames.append(image)
        durations.append(1200)
        if index == len(images) - 1:
            continue
        target = images[index + 1]
        for step in range(1, 5):
            frames.append(Image.blend(image, target, step / 5))
            durations.append(120)

    frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"demo_gif=ok frames={len(frames)} size={SIZE[0]}x{SIZE[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
