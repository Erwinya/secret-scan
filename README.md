# secret-scan

Scan a directory for common secret patterns (API keys, tokens, private keys).

Intended as a local pre-commit / hygiene helper — not a replacement for enterprise DLP.

## Status

Project scaffolding is in place. Scanner rules, CLI options, and sample fixtures will land in follow-up commits.

## Goals

- Walk a project tree and skip build/cache directories
- Match common secret patterns with clear rule names
- Text and JSON reports
- Non-zero exit when findings are present

## Requirements

- Python 3.10+
- Standard library only

## License

MIT
