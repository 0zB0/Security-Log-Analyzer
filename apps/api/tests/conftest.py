from collections.abc import Iterator
from pathlib import Path

import pytest

from tracehawk_api.config import settings
from tracehawk_api.database import configure_database, init_db


@pytest.fixture(autouse=True)
def isolated_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Give every test a clean database and never touch the developer/runtime database."""
    original_path = settings.db_path
    test_path = tmp_path / "tracehawk-test.db"
    monkeypatch.setattr(settings, "db_path", str(test_path))
    configure_database(str(test_path))
    init_db()

    yield test_path

    configure_database(original_path)
