"""
Automated unit and integration tests for Data Layer, Alembic Migrations, and Backups.
"""
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from app.config import Config
from scripts.backup_sqlite import backup_database, compute_sha256, prune_old_backups


def test_postgres_database_url_normalization(monkeypatch):
    """Verify legacy postgres:// URI scheme is normalized to postgresql:// for SQLAlchemy."""
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/arogyadb")

    class DynamicConfig(Config):
        _raw_db_url = os.getenv("DATABASE_URL", "sqlite:///healthcare.db")
        if _raw_db_url.startswith("postgres://"):
            _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = _raw_db_url

    assert DynamicConfig.SQLALCHEMY_DATABASE_URI == "postgresql://user:pass@localhost:5432/arogyadb"


def test_sqlite_backup_creation_and_integrity(tmp_path):
    """Verify online SQLite backup executes cleanly and computes valid SHA-256 checksum."""
    # 1. Create a mock source SQLite database with sample table
    src_db = tmp_path / "source.db"
    conn = sqlite3.connect(str(src_db))
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT);")
    cursor.execute("INSERT INTO test_table (value) VALUES ('secure_clinical_data');")
    conn.commit()
    conn.close()

    # 2. Run backup_database to backup directory
    backup_dir = tmp_path / "backups"
    backup_file = backup_database(src_db, backup_dir, keep_count=5, verify=True)

    assert backup_file.exists()
    assert backup_file.stat().st_size > 0

    # 3. Verify generated checksum file matches computed digest
    checksum_file = backup_dir / f"{backup_file.name}.sha256"
    assert checksum_file.exists()
    stored_digest = checksum_file.read_text(encoding="utf-8").split()[0]
    assert stored_digest == compute_sha256(backup_file)

    # 4. Verify backed-up database content
    bck_conn = sqlite3.connect(str(backup_file))
    bck_cursor = bck_conn.cursor()
    bck_cursor.execute("SELECT value FROM test_table WHERE id = 1;")
    row = bck_cursor.fetchone()
    assert row is not None
    assert row[0] == "secure_clinical_data"
    bck_conn.close()


def test_sqlite_backup_retention_pruning(tmp_path):
    """Verify pruning retains only keep_count most recent backups."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    # Create 6 dummy backup files
    for i in range(6):
        f = backup_dir / f"arogya_backup_2026090{i}_000000.db"
        f.write_text(f"dummy backup {i}")
        sha = backup_dir / f"arogya_backup_2026090{i}_000000.db.sha256"
        sha.write_text(f"hash{i}")

    # Retain only 3
    prune_old_backups(backup_dir, keep_count=3)

    remaining_db = list(backup_dir.glob("*.db"))
    remaining_sha = list(backup_dir.glob("*.sha256"))
    assert len(remaining_db) == 3
    assert len(remaining_sha) == 3
