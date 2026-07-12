import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/check_docs_structure.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_docs_structure", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_canonical_documentation_structure_is_complete() -> None:
    checker = _load_checker()

    assert checker.check_docs_structure(ROOT) == []
