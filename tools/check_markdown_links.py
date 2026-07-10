#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def check_markdown_links(root: Path) -> list[str]:
    root = root.resolve()
    failures: list[str] = []
    for markdown in sorted(root.rglob("*.md")):
        if any(part in {".git", ".venv", "node_modules"} for part in markdown.parts):
            continue
        relative_parts = markdown.relative_to(root).parts
        if relative_parts[:2] == ("public", "github"):
            # Overlay documents are validated after export at their destination paths.
            continue
        text = markdown.read_text(encoding="utf-8")
        for raw_target in LINK_PATTERN.findall(text):
            target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            relative_path = Path(unquote(parsed.path))
            resolved = (markdown.parent / relative_path).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                failures.append(f"{markdown.relative_to(root)}: link escapes repository: {target}")
                continue
            if not resolved.exists():
                failures.append(f"{markdown.relative_to(root)}: missing target: {target}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Check local Markdown link targets.")
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    failures = check_markdown_links(args.root)
    if failures:
        print("\n".join(failures))
        return 1
    print("markdown_links=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
