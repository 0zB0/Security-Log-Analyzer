#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
H1_PATTERN = re.compile(r"^# [^#].+$", re.MULTILINE)

CANONICAL_REQUIREMENTS = {
    "product-spec.md": ("## Non-Goals", "## Success Criteria", "## Current Boundaries"),
    "architecture.md": ("## Architectural Invariants", "## Verification Map", "## Limitations"),
    "event-processing-pipeline.md": (
        "## Implementation And Verification Map",
        "## Security Invariants",
        "## Limitations",
    ),
    "persistence-evidence-lifecycle.md": (
        "## Security And Privacy Invariants",
        "## Implementation And Verification Map",
        "## Failure Modes",
        "## Production Gaps",
    ),
    "frontend-architecture.md": (
        "## Implementation And Verification Map",
        "## Current Testing Gap",
        "## Limitations",
    ),
    "testing-strategy.md": ("## Claim Matrix", "## Known Gaps And Priorities"),
    "engineering-portfolio-guide.md": ("## Recommended Live Review",),
}

PRIVATE_MARKERS = ("/home/", "192.168.", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY")


def _local_markdown_targets(text: str) -> set[str]:
    targets: set[str] = set()
    for raw_target in LINK_PATTERN.findall(text):
        target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
        if "://" in target or target.startswith("#"):
            continue
        path = target.split("#", 1)[0]
        if path:
            targets.add(path)
    return targets


def check_docs_structure(root: Path) -> list[str]:
    root = root.resolve()
    docs = root / "docs"
    hub = docs / "README.md"
    failures: list[str] = []

    if not hub.is_file():
        return ["docs/README.md: documentation hub is missing"]

    hub_targets = _local_markdown_targets(hub.read_text(encoding="utf-8"))
    for markdown in sorted(docs.glob("*.md")):
        if markdown.name == "README.md":
            continue
        if markdown.name not in hub_targets:
            failures.append(f"docs/{markdown.name}: not linked directly from docs/README.md")

    for filename, required_sections in CANONICAL_REQUIREMENTS.items():
        path = docs / filename
        if not path.is_file():
            failures.append(f"docs/{filename}: canonical document is missing")
            continue
        text = path.read_text(encoding="utf-8")
        headings = H1_PATTERN.findall(text)
        if len(headings) != 1:
            failures.append(f"docs/{filename}: expected exactly one H1, found {len(headings)}")
        for section in required_sections:
            if section not in text:
                failures.append(f"docs/{filename}: missing required section {section}")
        for marker in PRIVATE_MARKERS:
            if marker in text:
                failures.append(f"docs/{filename}: contains private marker {marker!r}")
        if re.search(r"\b(?:TODO|TBD)\b", text, re.IGNORECASE):
            failures.append(f"docs/{filename}: contains unresolved TODO/TBD marker")

    public_export = (root / "PUBLIC_EXPORT.json").is_file()
    required_paths = [docs / "proof-pack", docs / "releases"]
    if not public_export:
        required_paths.extend((docs / "plans" / "active", root / "ROADMAP.md"))
    for path in required_paths:
        if not path.exists():
            failures.append(f"{path.relative_to(root)}: required documentation path is missing")

    return failures


def main() -> int:
    root = Path.cwd()
    failures = check_docs_structure(root)
    if failures:
        print("\n".join(failures))
        return 1
    print("docs_structure=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
