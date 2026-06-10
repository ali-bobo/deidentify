# Security Policy

## Intended Use

This tool is designed for **local, offline use only**. It processes potentially
sensitive log files on your machine and outputs de-identified copies that are
safe to share externally. The tool itself makes no network connections during
processing.

## What Is Safe to Push / Upload

| Item | Safe? |
|------|-------|
| `deidentify.py`, `setup_and_run.py`, `README.md` | ✅ Source code only |
| `*_deidentified.*` (output folder) | ✅ After human review |
| `*_mapping.json` (mapping folder) | ❌ **Never. Contains original values.** |
| Original log files (`*.log`, `*.csv`, etc.) | ❌ Keep local |

## Reporting a Vulnerability

If you discover a security issue in this tool (e.g. a bypass that causes
sensitive data to appear in de-identified output), please **do not** open a
public GitHub issue. Instead, open a **private security advisory** via the
GitHub repository's Security tab, or contact the author directly.

## Known Limitations

- Detection is pattern-based and heuristic — not guaranteed 100% recall.
- Always review the audit summary and spot-check output before sharing.
- Passwords and tokens are redacted but **must also be rotated**; redaction
  alone does not protect against credential re-use.

## Dependencies Security

Runtime dependencies (`presidio-analyzer`, `presidio-anonymizer`, `spaCy`,
`click`) are installed from official PyPI on first run. If you operate in a
controlled environment, pin exact versions and audit them before deployment.
