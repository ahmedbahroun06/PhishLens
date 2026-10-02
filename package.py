#!/usr/bin/env python3
"""Build a clean, secret-free ZIP of PhishLens to send to a teammate.

Usage:
    python package.py

Produces ../phishlens_share.zip (next to the project folder, so it isn't included
in itself). It EXCLUDES every secret and local-only file:
  .env, api key.txt, *.key, cache.db, *.sqlite*, __pycache__, .git, virtualenvs, etc.

The teammate unzips it, copies .env.example to .env, pastes THEIR own keys, and runs
`docker compose up --build`. See README.md.
"""
from __future__ import annotations

import fnmatch
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT.parent / "phishlens_share.zip"

# Files/dirs that must NEVER be shared.
EXCLUDE_NAMES = {
    ".env", "api key.txt", "cache.db", "phishlens_share.zip",
    ".git", ".venv", "venv", "env", ".idea", ".vscode",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    ".DS_Store", "Thumbs.db",
}
EXCLUDE_GLOBS = ["*.key", "*.pyc", "*.pyo", "*.sqlite", "*.sqlite3", "*.sqlite-*"]


def _excluded(path: Path) -> bool:
    for part in path.relative_to(ROOT).parts:
        if part in EXCLUDE_NAMES:
            return True
    name = path.name
    return any(fnmatch.fnmatch(name, g) for g in EXCLUDE_GLOBS)


def main() -> None:
    if OUT.exists():
        OUT.unlink()

    added, skipped_secret = [], []
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(ROOT.rglob("*")):
            if path.is_dir():
                continue
            if _excluded(path):
                if path.name in ("api key.txt", ".env") or path.suffix == ".key":
                    skipped_secret.append(path.name)
                continue
            arc = Path("phishlens") / path.relative_to(ROOT)
            zf.write(path, arc.as_posix())
            added.append(arc.as_posix())

    print(f"Created {OUT}  ({OUT.stat().st_size // 1024} KB, {len(added)} files)")
    print("\nIncluded:")
    for a in added:
        print("  +", a)
    if skipped_secret:
        print("\nExcluded as secret (NOT shared):")
        for s in sorted(set(skipped_secret)):
            print("  -", s)
    # Safety assertion: no secret slipped in.
    with zipfile.ZipFile(OUT) as zf:
        names = zf.namelist()
    bad = [n for n in names if n.endswith("/.env") or n.endswith("api key.txt")
           or n.endswith(".key") or "cache.db" in n]
    if bad:
        raise SystemExit(f"ABORT: secret file found in package: {bad}")
    print("\n✓ Verified: no secrets in the package. Safe to send.")


if __name__ == "__main__":
    main()
