# secret-scan

Scan a directory for common secret patterns (API keys, tokens, private keys).

Intended as a local pre-commit / hygiene helper — not a replacement for enterprise DLP.

## Status

Directory walking and text-file discovery are in place. Matching rules, JSON output, and sample fixtures will land in follow-up commits.

## Run (current)

```powershell
python src\secret_scan.py --path .
```

Lists candidate text files under `--path` (skips `.git`, `node_modules`, build caches, etc.).

## Requirements

- Python 3.10+
- Standard library only

## License

MIT
