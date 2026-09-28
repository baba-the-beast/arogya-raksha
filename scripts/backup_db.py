#!/usr/bin/env python3
"""
ArogyaRaksha - Unified Production Database Backup Utility.
Supports both SQLite (local development) and PostgreSQL (production).
Computes SHA-256 checksums, supports compression, and enforces retention.
"""
import argparse
import gzip
import hashlib
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

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


def backup_postgres(database_url: str, dest_dir: Path, keep_count: int) -> Path:
    """Performs pg_dump on PostgreSQL database using gzip compression without shell=True."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = dest_dir / f"arogya_pg_backup_{timestamp}.sql.gz"
    checksum_file = dest_dir / f"arogya_pg_backup_{timestamp}.sql.gz.sha256"

    print(f"[*] Starting PostgreSQL backup to {backup_file}...")

    # Strip custom SQLAlchemy driver prefixes
    clean_url = database_url.replace("postgresql+psycopg://", "postgresql://")

    from urllib.parse import unquote, urlparse
    parsed = urlparse(clean_url)
    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = unquote(parsed.password)

    cmd = ["pg_dump"]
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

    with gzip.open(backup_file, "wb") as f_out:
        result = subprocess.run(  # noqa: S603
            cmd,
            env=env,
            stdout=f_out,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        if backup_file.exists():
            backup_file.unlink()
        raise RuntimeError(f"pg_dump failed: {result.stderr.decode('utf-8', errors='replace')}")

    digest = compute_sha256(backup_file)
    checksum_file.write_text(f"{digest}  {backup_file.name}\n", encoding="utf-8")
    print(f"[+] PostgreSQL backup complete. Size: {backup_file.stat().st_size:,} bytes")
    print(f"[+] SHA-256: {digest}")

    prune_backups(dest_dir, "arogya_pg_backup_*.sql.gz", keep_count)
    return backup_file


def prune_backups(dest_dir: Path, pattern: str, keep_count: int) -> None:
    """Retains the most recent keep_count backups."""
    if keep_count <= 0:
        return
    backups = sorted(dest_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    if len(backups) > keep_count:
        for old in backups[keep_count:]:
            try:
                old.unlink()
                chk = old.with_name(old.name + ".sha256")
                if chk.exists():
                    chk.unlink()
                print(f"[-] Pruned old backup: {old.name}")
            except Exception as e:
                print(f"[!] Warning: failed to prune {old.name}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Unified Database Backup Utility")
    parser.add_argument("--dest-dir", type=Path, default=Path("backups"), help="Destination directory")
    parser.add_argument("--keep", type=int, default=10, help="Retention count (default: 10)")
    args = parser.parse_args()

    db_url = os.getenv("DATABASE_URL", "sqlite:///healthcare.db")
    if db_url.startswith("postgres"):
        backup_postgres(db_url, args.dest_dir, args.keep)
    else:
        from scripts.backup_sqlite import backup_database, resolve_database_path
        db_path = resolve_database_path()
        backup_database(db_path, args.dest_dir, args.keep, verify=True)


if __name__ == "__main__":
    main()
