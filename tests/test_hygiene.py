import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Generic security patterns to detect leaks without storing sensitive strings
KEY_PATTERNS = [
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"(?i)c:[/\\]temp"),
    re.compile(r"(?i)\.awsapps\.com"),
    re.compile(r"(?i)(password|secret|apikey|access_key)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]"),
]


def test_no_hardcoded_secrets_or_internal_paths():
    """Verify no hardcoded keys, Windows temp paths, or internal SSO domains exist."""
    findings = []
    for root, _dirs, files in os.walk(REPO_ROOT):
        if any(d in root for d in [".git", "tests", ".pytest_cache", "__pycache__"]):
            continue
        for f in files:
            fp = Path(root) / f
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                for pattern in KEY_PATTERNS:
                    match = pattern.search(content)
                    if match:
                        findings.append((str(fp.relative_to(REPO_ROOT)), match.group(0)))
            except Exception:
                pass

    assert not findings, f"Found hardcoded secrets or internal path patterns: {findings}"


def test_all_cli_scripts_help():
    """Verify that every CLI tool executes --help cleanly with exit code 0."""
    failures = []
    for root, _dirs, files in os.walk(REPO_ROOT):
        if any(d in root for d in [".git", "tests", ".pytest_cache", "__pycache__"]):
            continue
        for f in files:
            if f.endswith(".py") and f != "__init__.py":
                fp = Path(root) / f
                try:
                    res = subprocess.run(
                        [sys.executable, str(fp), "--help"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=str(fp.parent),
                    )
                    if res.returncode != 0:
                        failures.append((str(fp.relative_to(REPO_ROOT)), res.stderr))
                except Exception as e:
                    failures.append((str(fp.relative_to(REPO_ROOT)), str(e)))

    assert not failures, f"CLI scripts failed --help execution: {failures}"
