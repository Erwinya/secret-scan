#!/usr/bin/env python3
"""Walk a directory and list text files that will be scanned for secrets."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", ".idea"}
TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".md", ".txt", ".xml", ".properties",
}


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {".env", "Dockerfile"}:
            continue
        files.append(path)
    return sorted(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="List text files under a path (secret matching lands next)"
    )
    parser.add_argument("--path", default=".", help="Directory to walk")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    files = iter_files(root)
    print(f"files={len(files)} root={root}")
    for path in files:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
