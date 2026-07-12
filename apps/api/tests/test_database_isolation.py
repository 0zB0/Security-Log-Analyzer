from pathlib import Path

from sqlalchemy import inspect

from tracehawk_api import database
from tracehawk_api.config import settings


def test_backend_tests_use_a_temporary_database(isolated_database: Path) -> None:
    assert Path(settings.db_path) == isolated_database
    assert isolated_database.name == "tracehawk-test.db"
    assert isolated_database.parent != Path.cwd()

    database.init_db()

    assert isolated_database.exists()
    assert "analysis_runs" in inspect(database.engine).get_table_names()
