#!/usr/bin/env python3
import os
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VERSION_FILE = BASE_DIR / "version.py"


def get_version() -> str:
    if not VERSION_FILE.exists():
        return "2.1.4"
    content = VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*["\'](\d+)\.(\d+)\.(\d+)["\']', content)
    if not match:
        return "2.1.4"
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def bump() -> str:
    if not VERSION_FILE.exists():
        VERSION_FILE.write_text('__version__ = "2.1.4"\n', encoding="utf-8")
        return "2.1.4"

    content = VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*["\'](\d+)\.(\d+)\.(\d+)["\']', content)
    if not match:
        raise ValueError("Fant ikke gyldig versjonsstreng i version.py")

    major, minor, patch = map(int, match.groups())
    patch += 1
    if patch >= 100:
        minor += 1
        patch = 0
        if minor >= 100:
            major += 1
            minor = 0

    new_version = f"{major}.{minor}.{patch}"
    new_content = re.sub(
        r'(__version__\s*=\s*["\'])\d+\.\d+\.\d+(["\'])',
        rf'\g<1>{new_version}\g<2>',
        content
    )
    VERSION_FILE.write_text(new_content, encoding="utf-8")
    return new_version


def collect_source_mtimes() -> dict:
    """Collect modification times for project source files (excluding version.py, db, logs, cache)."""
    watch_exts = {".py", ".html", ".js", ".css"}
    ignore_dirs = {".git", "__pycache__", "venv", ".venv", "node_modules", "uploads", "screenshots", ".agents", ".vscode"}
    ignore_files = {"version.py", "bump_version.py"}
    mtimes = {}

    for root, dirs, files in os.walk(BASE_DIR):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for fname in files:
            if fname in ignore_files:
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext not in watch_exts:
                continue
            fpath = os.path.join(root, fname)
            try:
                mtimes[fpath] = os.path.getmtime(fpath)
            except OSError:
                pass
    return mtimes


if __name__ == "__main__":
    print(f"Versjon oppdatert til: {bump()}")
