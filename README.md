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

## Run

```powershell
python src\secret_scan.py --path samples
python src\secret_scan.py --path samples --json
```

`samples/leaks.txt` contains **intentionally fake** placeholders for demos.  
`samples/clean.txt` should report no findings.

### Allowlist (`.secretignore`)

Place a `.secretignore` file in the scan root (or pass `--ignore-file`) to skip known demo/fixture paths:

```text
# one pattern per line
samples/leaks.txt
**/fixtures/*
```

`samples/.secretignore` skips `samples/leaks.txt` when scanning that folder.

## False positives

Pattern matching is heuristic. Treat findings as candidates to review, not confirmed leaks.  
Common noise sources: example docs, test fixtures, and long base64 blobs.

## Exit codes

- `0` — no findings
- `1` — one or more potential secrets
- `2` — path not found / usage error

## Requirements

- Python 3.10+
- Standard library only

## License

MIT
