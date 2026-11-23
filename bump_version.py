#!/usr/bin/env python3
import re
from pathlib import Path

VERSION_FILE = Path("version.py")

def bump():
    if not VERSION_FILE.exists():
        VERSION_FILE.write_text('__version__ = "0.0.1"\n', encoding="utf-8")
        return "0.0.1"

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

if __name__ == "__main__":
    print(f"Versjon oppdatert til: {bump()}")
