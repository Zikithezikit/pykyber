#!/usr/bin/env python3
"""Download the external test vectors named in tests/vectors/manifest.json.

External vectors are never committed. Each file is fetched from the pinned
commit of its upstream repository into tests/vectors/external/<source>/ (which
is gitignored) and checked against the SHA-256 in the manifest. A file that is
already present and matches is left alone; a file that does not match is
never written and the script fails, so a changed upstream file or a changed
pin is never used silently. Standard library only.
"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests" / "vectors" / "manifest.json"
EXTERNAL = ROOT / "tests" / "vectors" / "external"
RAW_URL = "https://raw.githubusercontent.com/{repository}/{commit}/{directory}/{path}"
TIMEOUT_SECONDS = 60


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fetch(name, source):
    failures = 0
    for path, expected in source["files"].items():
        target = EXTERNAL / name / path
        if target.exists() and sha256(target.read_bytes()) == expected:
            continue
        url = RAW_URL.format(path=path, **source)
        print("fetching " + url)
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            data = response.read()
        actual = sha256(data)
        if actual != expected:
            print("SHA-256 mismatch for %s: expected %s, got %s" % (url, expected, actual))
            failures += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return failures


def main():
    manifest = json.loads(MANIFEST.read_text())
    failures = sum(fetch(name, source) for name, source in manifest.items())
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
