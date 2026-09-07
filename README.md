# secret-scan

Scan a directory for common secret patterns (API keys, tokens, private keys).

Intended as a local pre-commit / hygiene helper — not a replacement for enterprise DLP.

## Status

Directory walking plus the first matching rules are live:

- `aws_access_key` — `AKIA…` access key ids
- `private_key` — PEM / OpenSSH private key headers

More rules, JSON output, and sample fixtures will land in follow-up commits.

## Run

```powershell
python src\secret_scan.py --path .
```

## Exit codes

- `0` — no findings
- `1` — one or more potential secrets
- `2` — path not found / usage error

## Requirements

- Python 3.10+
- Standard library only

## License

MIT
