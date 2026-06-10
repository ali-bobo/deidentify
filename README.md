# Log De-identification Tool

A privacy-protection tool for security analysts that replaces sensitive identifiers in log files with consistent pseudonyms before uploading to external analysis platforms.

Designed to be **EDR/platform-agnostic** — works with any structured or unstructured log format. Built-in structured pipeline for EDR threat export CSVs (threat/host/events layout).

Supports: Chinese text (CJK), IPv4/v6/CIDR, domains, emails, OS usernames, employee IDs, company names, Taiwan phone numbers, Taiwan National IDs, credit card numbers, JWT tokens, AWS/GitHub tokens, and generic secrets/passwords — with a local reversible mapping file kept for reference.

---

## Requirements

- Python 3.9 or higher
- Internet access on first run (to install dependencies from PyPI)

Dependencies installed automatically: `presidio-analyzer`, `presidio-anonymizer`, `spacy`, `click`

---

## Quick Start

Place `setup_and_run.py` and `deidentify.py` in the same folder, then:

```bash
# First run — installs dependencies and verifies compatibility
python setup_and_run.py

# Process a file
python setup_and_run.py your_file.log
```

---

## Usage

```bash
python setup_and_run.py <file> [options]
```

Supported formats: `.txt` `.log` `.json` `.csv` (anything else treated as plain text)

EDR-style CSV exports with a `Threat Information` section are automatically detected and processed through a structured parse → dedup → de-identify pipeline.

### Options

| Option | Description |
|--------|-------------|
| `--keep-public-ip` | Retain public IPs (useful when analyzing external C2 sources) |
| `-w KEYWORD` | Manually specify additional terms to redact (repeatable) |
| `--custom-id-pattern REGEX` | Register an extra regex as a custom ID entity (repeatable) |
| `--redact-uuid` | Enable UUID redaction (off by default — UUIDs are usually event IDs) |
| `--no-dedup` | Disable duplicate event filtering for EDR-style CSVs |
| `--max-mb N` | Output file size limit in MB, default 10 (auto-splits if exceeded) |
| `--output-dir DIR` | Folder for de-identified output (default: `deidentified_output/`) |
| `--mapping-dir DIR` | Folder for reversal mapping files (default: `deidentify_mapping/`) |
| `--yes` | Skip install confirmation prompt (for CI/automation) |

### Examples

```bash
# Basic
python setup_and_run.py incident.log

# Keep public IPs for C2 analysis
python setup_and_run.py incident.log --keep-public-ip

# Redact custom keywords
python setup_and_run.py incident.log -w "ProjectAlpha" -w "SERVER-LAB01"

# Redact a custom ID format with regex (e.g. internal asset tags like AB123456)
python setup_and_run.py incident.log --custom-id-pattern "\bAB\d{6}\b"

# Multiple files
python setup_and_run.py *.csv --redact-uuid
```

---

## Output Files

| File | Purpose | Safe to Upload |
|------|---------|----------------|
| `<name>_deidentified.json` | De-identified result | ✅ Yes |
| `<name>_mapping.json` | Reversal mapping table | ❌ **Never upload** |

After processing, an audit summary is printed showing how many unique values were replaced per entity type.

---

## What Gets Detected

| Entity | Notes |
|--------|-------|
| CJK characters | All Chinese/full-width text |
| IPv4 | Internal and external; browser version strings excluded |
| IPv6 | Including `fe80::` link-local addresses |
| CIDR notation | Both v4 and v6 |
| Domains | Real TLD anchoring; major public domains (google.com, microsoft.com, etc.) preserved |
| Email addresses | All redacted |
| OS usernames | `\Users\NAME\` (Windows), `/Users/NAME/` (macOS), `/home/NAME/` (Linux) |
| Employee IDs | Pattern: 1 letter + 6–8 digits (e.g. `N1410360`) |
| Company names | Suffix-anchored: Ltd, Corp, Inc, GmbH, LLC, etc. |
| Taiwan phone numbers | `09xx` and `+886-9xx` formats with length validation |
| Taiwan National ID | With checksum validation |
| Credit card numbers | With Luhn algorithm validation |
| Passwords / Tokens | Redacted; triggers a **rotation warning** |
| JWT tokens | Detected by header pattern (`eyJ…`) |
| AWS/GitHub tokens | `AKIA…`, `ghp_…`, `github_pat_…` patterns |
| Custom ID patterns | User-supplied via `--custom-id-pattern REGEX` |
| UUID | Off by default; enable with `--redact-uuid` |

JSON processing: only values are redacted, keys are preserved.  
CSV processing: header row preserved; sensitive key names in data cells also detected.

---

## Pre-Upload Checklist

```
□ Uploading the _deidentified file, not the original
□ Audit summary replacement counts look reasonable
□ _mapping.json stays local — not uploaded
□ If password/token warning appeared → rotate those credentials
```

---

## Limitations

- **Company name detection is suffix-anchored** — names without Ltd/Corp/Inc etc. will not be caught. Use `-w` to add them manually.
- **Custom internal ID formats** (asset tags, site codes, ticket numbers) need explicit `--custom-id-pattern` to be covered.
- **Pure numbers are not redacted** — timestamps and sequence numbers are preserved intentionally.
- **Automatic detection is not 100%** — always review the audit summary and spot-check known sensitive values before uploading.

---

## Customizing Detection Rules

Open `deidentify.py` — the detection rules are defined at the top of the file:

- Company name suffixes → `CORP_SUFFIX`
- Employee ID format → `EMPID_PATTERN`
- Public domain whitelist → `PUBLIC_DOMAIN_WHITELIST`
- Hostname/device field names in CSVs → `NEXT_CELL_REDACT_KEYS`

For one-off patterns you'd rather not hardcode, use `--custom-id-pattern` at runtime.

---

## License

MIT
