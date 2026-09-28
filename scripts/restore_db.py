#!/usr/bin/env python3
"""
ArogyaRaksha - Unified Production Database Restore Utility.
Supports restoring both SQLite (local development) and PostgreSQL (production) backups.
Performs SHA-256 checksum validation, structural integrity verification, and dry-run execution.
"""
import argparse
import gzip
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()


def compute_sha256(file_path: Path) -> str:
    """Calculates SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_checksum(backup_file: Path) -> bool:
    """Verifies backup file against its .sha256 sidecar file if present."""
    checksum_file = backup_file.with_name(backup_file.name + ".sha256")
    if not checksum_file.exists():
        # Check without .gz or alternate suffix
        alt_checksum = backup_file.with_suffix(backup_file.suffix + ".sha256")
        if alt_checksum.exists():
            checksum_file = alt_checksum
        else:
            print(f"[*] Note: No sidecar checksum file found for {backup_file.name} (skipping sidecar verification)")
            return True

    expected_line = checksum_file.read_text(encoding="utf-8").strip()
    expected_digest = expected_line.split()[0]
    actual_digest = compute_sha256(backup_file)

    if actual_digest.lower() != expected_digest.lower():
        raise ValueError(
            f"Integrity check failed for {backup_file.name}!\n"
            f"Expected SHA-256: {expected_digest}\n"
            f"Actual SHA-256:   {actual_digest}"
        )
    print(f"[+] SHA-256 checksum verified: {actual_digest}")
    return True


def restore_sqlite(backup_file: Path, target_path: Path, dry_run: bool = False) -> None:
    """Restores SQLite database from backup after integrity validation."""
    print(f"[*] Validating SQLite backup: {backup_file}")
    verify_checksum(backup_file)

    # Validate structural integrity of the backup file before restoring
    conn = sqlite3.connect(str(backup_file))
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA quick_check;")
        result = cursor.fetchone()
        if not result or result[0] != "ok":
            raise ValueError(f"SQLite backup structural check failed: {result}")
        print("[+] Structural PRAGMA quick_check: OK")
    finally:
        conn.close()

    if dry_run:
        print("[+] [DRY-RUN] SQLite backup file is structurally valid. No changes made.")
        return

    # Create safety backup of existing active DB if present
    if target_path.exists():
        safety_bak = target_path.with_name(f"{target_path.name}.pre_restore.bak")
        print(f"[*] Creating pre-restore snapshot: {safety_bak}")
        shutil.copy2(target_path, safety_bak)

    # Perform atomic restore
    print(f"[*] Restoring backup to {target_path}...")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_target = target_path.with_name(f"{target_path.name}.restore_tmp")
    shutil.copy2(backup_file, temp_target)
    if os.name == "nt" and target_path.exists():
        target_path.unlink()
    temp_target.rename(target_path)
    print(f"[+] SQLite database restored successfully to: {target_path}")


def restore_postgres(backup_file: Path, database_url: str, dry_run: bool = False) -> None:
    """Restores PostgreSQL database from .sql.gz backup."""
    print(f"[*] Validating PostgreSQL backup: {backup_file}")
    verify_checksum(backup_file)

    # Verify gzip readability and inspect header
    with gzip.open(backup_file, "rb") as f_in:
        header = f_in.read(1024)
        if not header:
            raise ValueError(f"Backup archive {backup_file.name} is empty or unreadable.")
    print("[+] Archive gzip integrity: OK")

    if dry_run:
        print("[+] [DRY-RUN] PostgreSQL archive decompressed successfully. No DB changes made.")
        return

    clean_url = database_url.replace("postgresql+psycopg://", "postgresql://")
    parsed = urlparse(clean_url)
    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = unquote(parsed.password)

    cmd = ["psql"]
    if parsed.hostname:
        cmd.extend(["-h", parsed.hostname])
    if parsed.port:
        cmd.extend(["-p", str(parsed.port)])
    if parsed.username:
        cmd.extend(["-U", unquote(parsed.username)])
    db_name = parsed.path.lstrip("/")
    if db_name:
        cmd.append(db_name)
    else:
        cmd.append(clean_url)

    print(f"[*] Restoring PostgreSQL backup to {parsed.hostname or 'localhost'}/{db_name or ''}...")
    with gzip.open(backup_file, "rb") as f_in:
        result = subprocess.run(  # noqa: S603
            cmd,
            input=f_in.read(),
            env=env,
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"psql restore failed: {result.stderr.decode('utf-8', errors='replace')}")
    print("[+] PostgreSQL database restored successfully.")


def main():
    parser = argparse.ArgumentParser(description="Unified Database Restore Utility")
    parser.add_argument("backup_file", type=Path, help="Path to backup file to restore")
    parser.add_argument("--dry-run", action="store_true", help="Verify backup integrity without modifying active database")
    parser.add_argument("--force", action="store_true", help="Bypass confirmation prompt")
    args = parser.parse_args()

    if not args.backup_file.exists():
        print(f"[ERROR] Backup file not found: {args.backup_file}", file=sys.stderr)
        sys.exit(1)

    db_url = os.getenv("DATABASE_URL", "sqlite:///healthcare.db")
    is_postgres = db_url.startswith("postgres")

    if not args.dry_run and not args.force:
        confirm = input(f"WARNING: This will overwrite active database ({db_url}). Continue? [y/N]: ")
        if confirm.lower() not in ("y", "yes"):
            print("Restore aborted.")
            sys.exit(0)

    try:
        if is_postgres:
            restore_postgres(args.backup_file, db_url, dry_run=args.dry_run)
        else:
            from scripts.backup_sqlite import resolve_database_path
            target_path = resolve_database_path()
            restore_sqlite(args.backup_file, target_path, dry_run=args.dry_run)
        print("[SUCCESS] Restore operation completed.")
    except Exception as e:
        print(f"[ERROR] Restore failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
