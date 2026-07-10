from pathlib import Path
from typing import Any

import yaml

from tracehawk_api.models.domain import DetectionRule


def load_rule(path: Path) -> DetectionRule:
    data: dict[str, Any] = yaml.safe_load(path.read_text())
    return DetectionRule.model_validate(data)


def load_rules(root: Path) -> list[DetectionRule]:
    return [load_rule(path) for path in sorted(root.rglob("*.yml"))]

