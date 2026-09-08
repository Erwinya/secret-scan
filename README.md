# secret-scan

Scan a directory for common secret patterns (API keys, tokens, private keys).

Intended as a local pre-commit / hygiene helper — not a replacement for enterprise DLP.

## Rules

- `aws_access_key`
- `github_pat`
- `slack_token`
- `generic_api_key`
- `private_key`
- `jwt`

Sample fixtures and allowlist support will land in follow-up commits.

## Run

```powershell
python src\secret_scan.py --path .
python src\secret_scan.py --path . --json
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
