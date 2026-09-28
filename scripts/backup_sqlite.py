#!/usr/bin/env python3
"""
ArogyaRaksha - Automated SQLite Database Backup Utility (Cron-friendly)

Creates a live, transactionally consistent, zero-lock online backup of the
SQLite healthcare database using the native sqlite3 online backup API.
Computes and records SHA-256 integrity digests and enforces backup retention.

Usage:
  python scripts/backup_sqlite.py                      # Default: saves to backups/, keeps 10
  python scripts/backup_sqlite.py --dest-dir /var/backups/arogya --keep 14
  python scripts/backup_sqlite.py --verify             # Performs integrity verification
"""
import argparse
import hashlib
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# Ensure app directory is discoverable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()


def resolve_database_path() -> Path:
    """Resolves local SQLite database file from configuration."""
    db_uri = os.getenv("DATABASE_URL", "sqlite:///healthcare.db")

    if not db_uri.startswith("sqlite:"):
        print(f"[!] Configured DATABASE_URL is not SQLite ({db_uri}).")
        print("    Automated SQLite backup is only applicable for SQLite deployments.")
        print("    For PostgreSQL, please utilize pg_dump or managed cloud backups.")
        sys.exit(0)

    # Strip sqlite:/// prefix
    clean_path = db_uri.replace("sqlite:///", "").split("?")[0]

    # Handle relative paths: check instance directory or root
    candidate = Path(clean_path)
    if candidate.is_absolute() and candidate.exists():
        return candidate

    instance_candidate = Path("instance") / clean_path
    if instance_candidate.exists():
        return instance_candidate.resolve()

    if candidate.exists():
        return candidate.resolve()

    # If file doesn't exist yet, check instance/healthcare.db default
    fallback = Path("instance") / "healthcare.db"
    if fallback.exists():
        return fallback.resolve()

    return candidate.resolve()


def compute_sha256(file_path: Path) -> str:
    """Calculates SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def backup_database(db_path: Path, dest_dir: Path, keep_count: int, verify: bool = True) -> Path:
    """Executes online live backup of SQLite database."""
    if not db_path.exists():
        raise FileNotFoundError(f"Source database file not found at: {db_path}")

    dest_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"arogya_backup_{timestamp}.db"
    backup_path = dest_dir / backup_filename
    checksum_path = dest_dir / f"{backup_filename}.sha256"

    print(f"[*] Starting live online backup of: {db_path}")
    print(f"[*] Target backup destination: {backup_path}")

    # Use SQLite online backup API for zero-lock, transactionally consistent snapshot
    src_conn = sqlite3.connect(str(db_path))
    dst_conn = sqlite3.connect(str(backup_path))

    try:
        with dst_conn:
            src_conn.backup(dst_conn, pages=100)
    finally:
        dst_conn.close()
        src_conn.close()

    # Calculate and store cryptographic checksum
    digest = compute_sha256(backup_path)
    checksum_path.write_text(f"{digest}  {backup_filename}\n", encoding="utf-8")
    print(f"[+] Backup created successfully ({backup_path.stat().st_size:,} bytes)")
    print(f"[+] SHA-256 Checksum: {digest}")

    if verify:
        verify_backup(backup_path, digest)

    # Prune older backups according to retention policy
    prune_old_backups(dest_dir, keep_count)

    return backup_path


def verify_backup(backup_path: Path, expected_digest: str) -> None:
    """Verifies cryptographic checksum and structural integrity of the backup file."""
    print(f"[*] Verifying backup integrity: {backup_path.name}...")

    # 1. Verify SHA-256
    actual_digest = compute_sha256(backup_path)
    if actual_digest != expected_digest:
        raise ValueError(
            f"Integrity check failed! SHA-256 mismatch.\n"
            f"Expected: {expected_digest}\nActual:   {actual_digest}"
        )

    # 2. Verify SQLite structural integrity via PRAGMA quick_check
    conn = sqlite3.connect(str(backup_path))
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA quick_check;")
        result = cursor.fetchone()
        if not result or result[0] != "ok":
            raise ValueError(f"SQLite structural integrity check failed: {result}")
        print("[+] Structural integrity check: OK")
    finally:
        conn.close()


def prune_old_backups(dest_dir: Path, keep_count: int) -> None:
    """Prunes older backups to maintain the retention window."""
    if keep_count <= 0:
        return

    backups = sorted(
        dest_dir.glob("arogya_backup_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    if len(backups) > keep_count:
        excess = backups[keep_count:]
        print(f"[*] Pruning {len(excess)} backup(s) exceeding retention limit of {keep_count}...")
        for old_backup in excess:
            try:
                old_backup.unlink()
                old_checksum = old_backup.with_suffix(".db.sha256")
                if old_checksum.exists():
                    old_checksum.unlink()
                print(f"[-] Removed expired backup: {old_backup.name}")
            except Exception as e:
                print(f"[!] Failed to remove {old_backup.name}: {e}")


def main():
    parser = argparse.ArgumentParser(description="ArogyaRaksha SQLite Backup Utility")
    parser.add_argument(
        "--dest-dir",
        type=Path,
        default=Path("backups"),
        help="Directory to store backup files (default: backups/)"
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=10,
        help="Number of most recent backups to retain (default: 10)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        default=True,
        help="Perform cryptographic and SQLite quick_check integrity checks"
    )
    args = parser.parse_args()

    db_path = resolve_database_path()
    try:
        backup_database(db_path, args.dest_dir, args.keep, args.verify)
        print("[SUCCESS] Backup process completed cleanly.")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Backup failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
