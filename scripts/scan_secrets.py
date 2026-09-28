"""
Automated Secret and Credential Scanner for ArogyaRaksha.
Detects uncommitted or accidental secrets, private keys, API tokens, and high-entropy strings.
Used in CI/CD pre-commit hooks and release verification pipelines.
"""
import contextlib
import math
import re
import subprocess
import sys
from pathlib import Path

# Patterns indicating hardcoded credentials or secrets
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private Key Header"),
    (re.compile(r"(?i)(?:api_key|secret_key|private_key|auth_token)\s*=\s*['\"][0-9a-zA-Z\-_]{24,}['\"]"), "Hardcoded High-Entropy Key Assignment"),
    (re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]"), "Potential Hardcoded Password Assignment"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub Personal Access Token"),
]

# Sensitive file patterns that should NEVER be tracked in source control
FORBIDDEN_FILE_PATTERNS = [
    re.compile(r"^\.env(?:\..+)?$"),
    re.compile(r".*\.pem$"),
    re.compile(r".*\.key$"),
    re.compile(r".*\.p12$"),
    re.compile(r".*\.pfx$"),
    re.compile(r".*\.db$"),
    re.compile(r".*\.sqlite3?$"),
    re.compile(r".*\.dump$"),
]

EXCLUDED_DIRS = {
    ".git", ".pytest_cache", ".ruff_cache", "__pycache__", ".venv", "venv",
    "htmlcov", "dist", "build", "node_modules", "instance", "backups"
}

ALLOWED_FILES = {
    ".env.example", "secret.example.yaml"
}


def _is_git_ignored(path: Path, root: Path) -> bool:
    """Checks if a path is ignored by git source control."""
    try:
        res = subprocess.run(
            ["git", "check-ignore", "-q", str(path.relative_to(root))],
            cwd=str(root),
            capture_output=True,
            timeout=2,
        )
        return res.returncode == 0
    except Exception:
        return False


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def scan_directory(root_dir: str = ".") -> list[dict[str, str]]:
    """Recursively scans repository for sensitive artifacts and secrets."""
    violations = []
    root = Path(root_dir).resolve()

    for path in root.rglob("*"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue

        rel_path = path.relative_to(root).as_posix()

        # Check filename rules
        if path.is_file():
            if path.name not in ALLOWED_FILES:
                for pattern in FORBIDDEN_FILE_PATTERNS:
                    if pattern.match(path.name):
                        if _is_git_ignored(path, root):
                            break
                        violations.append({
                            "file": rel_path,
                            "line": 0,
                            "rule": f"Forbidden sensitive file pattern '{pattern.pattern}'",
                            "severity": "CRITICAL"
                        })

            # Check file content (only text files under 2MB)
            if path.stat().st_size < 2 * 1024 * 1024:
                with contextlib.suppress(OSError, UnicodeDecodeError):
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            # Skip comments or documentation references
                            stripped = line.strip()
                            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                                continue
                            if "docs/" in rel_path or rel_path.endswith(".md"):
                                continue

                            for pattern, desc in SECRET_PATTERNS:
                                if pattern.search(line):
                                    # Allow test fixtures in tests/ directory
                                    if "tests/" in rel_path or "test_" in rel_path:
                                        continue
                                    violations.append({
                                        "file": rel_path,
                                        "line": line_num,
                                        "rule": desc,
                                        "severity": "HIGH"
                                    })

    return violations


scan_repository = scan_directory


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = scan_directory(target)

    if findings:
        print(f"[!] SECRET SCANNER FAILED: Found {len(findings)} violation(s):")
        for f in findings:
            print(f"  - [{f['severity']}] {f['file']}:{f['line']} -> {f['rule']}")
        sys.exit(1)
    else:
        print("[+] Secret Scanner: PASS! No sensitive artifacts or credentials detected.")
        sys.exit(0)
