#!/usr/bin/env python3
"""Scan text files for a first set of secret patterns."""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", ".idea"}
TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".md", ".txt", ".xml", ".properties",
}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    snippet: str


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


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings
    for i, line in enumerate(text.splitlines(), 1):
        for rule, pattern in PATTERNS:
            if pattern.search(line):
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                findings.append(Finding(str(path), i, rule, snippet))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a directory for secret-like strings")
    parser.add_argument("--path", default=".", help="Directory to scan")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for file_path in iter_files(root):
        findings.extend(scan_file(file_path))

    if not findings:
        print("No secrets detected.")
        return 0

    print(f"Found {len(findings)} potential secret(s):")
    for f in findings:
        snippet = f.snippet.lstrip("\ufeff")
        print(f"  {f.path}:{f.line} [{f.rule}] {snippet}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
