from hashlib import sha256
from pathlib import Path

from tracehawk_api.models.domain import RawLogLine


def build_raw_lines(path: Path, source_id: str) -> list[RawLogLine]:
    return build_raw_lines_from_text(path.read_text(), source_id)


def build_raw_lines_from_text(text: str, source_id: str) -> list[RawLogLine]:
    lines: list[RawLogLine] = []
    for line_number, raw_text in enumerate(text.splitlines(), start=1):
        if not raw_text.strip():
            continue
        lines.append(
            RawLogLine(
                id=f"{source_id}:line:{line_number}",
                source_id=source_id,
                line_number=line_number,
                raw_text=raw_text,
                content_hash=sha256(raw_text.encode("utf-8")).hexdigest(),
            )
        )
    return lines
