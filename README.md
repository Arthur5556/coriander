English | [简体中文](README.zh-CN.md)

# CVE Monitor

Near real-time CVE monitor running on GitHub Actions every 5 minutes. It matches CVE items against keywords from cve_targets.txt and either sends email alerts via SMTP or writes matches to the cve_reports/ directory when email is not configured.

## Features
- 5-minute schedule using GitHub Actions (cron: */5 * * * *)
- Uses the CIRCL CVE feed for freshness; filters with a 10-minute sliding time window to tolerate scheduler drift
- Keyword-based matching from cve_targets.txt (case-insensitive)
- Email alerts via SMTP when EMAIL_* secrets are configured
- File-output fallback when email is not configured or fails: writes to cve_reports/ (latest.json, timestamped snapshots like YYYYMMDD_HHMM_matches.json, and a latest.md summary)

## Repository structure
- scripts/cve_monitor.py — main monitor script
- .github/workflows/cve-monitor.yml — GitHub Actions workflow (runs every 5 minutes and supports manual dispatch)
- cve_targets.txt — list of keywords to match (one per line; lines starting with # are comments)
- cve_reports/ — output directory created by the job or local runs when writing files

## Setup
1) Add keywords to cve_targets.txt
- One keyword per line
- Lines starting with # are comments and ignored

2) Configure GitHub Secrets (for email alerts; optional if relying on file-output fallback)
- EMAIL_HOST: SMTP server host
- EMAIL_PORT: SMTP server port (e.g., 587 for STARTTLS, 465 for SSL)
- EMAIL_USER: SMTP username
- EMAIL_PASS: SMTP password or app password
- EMAIL_FROM: From address (e.g., cve-bot@example.com)
- EMAIL_TO: Comma- or semicolon-separated list of recipients
- Optional: NVD_API_KEY (reserved for future use; not currently used by the script)

## Running locally
Requirements: Python 3.11+ recommended (GitHub Actions uses 3.11) and requests.

Example steps:

```
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install requests

# Optional (only if you want email locally):
export EMAIL_HOST="smtp.example.com"
export EMAIL_PORT="587"
export EMAIL_USER="username"
export EMAIL_PASS="password_or_app_password"
export EMAIL_FROM="cve-bot@example.com"
export EMAIL_TO="alice@example.com,bob@example.com"

# Optional (reserved, not used yet):
export NVD_API_KEY="..."

python scripts/cve_monitor.py
```

Behavior when run locally:
- If email variables are fully configured, the script will send an email summary
- Otherwise, it writes files under cve_reports/: latest.json (raw matches), a timestamped *_matches.json snapshot, and latest.md (human-readable summary)

## GitHub Actions
- Schedule: */5 * * * * (every 5 minutes)
- Manual trigger: workflow_dispatch
- permissions: contents: write (needed to commit file-output changes under cve_reports/)
- The workflow will commit and push changes in cve_reports/ when new matches are written

## Configuration details
- Matching behavior: case-insensitive substring match on either the CVE ID or the summary/description against each keyword from cve_targets.txt
- Time window: a 10-minute UTC sliding window is used to tolerate scheduler drift; since the job runs every 5 minutes, duplicates across runs are possible when a CVE appears near the window boundary; within a single run, duplicates are de-duplicated by CVE ID
- Email behavior: email is sent only when all EMAIL_* variables are set; recipients can be separated by commas or semicolons; default SMTP port is 587 if not provided
- File outputs:
  - cve_reports/latest.json — raw CIRCL items for the current run that matched keywords and fell within the time window
  - cve_reports/YYYYMMDD_HHMM_matches.json — compact summary of matched CVEs for that run
  - cve_reports/latest.md — human-readable summary for quick viewing

## Troubleshooting
- Rate limiting or API errors:
  - The script queries CIRCL and will try multiple sizes (200 → 100 → 50) to improve the chance of success; if CIRCL is unavailable or throttling, runs may produce no results and will log why
- No results:
  - Ensure keywords exist in cve_targets.txt and are relevant
  - Remember the 10-minute window; CVEs outside the window will be ignored until the next run
  - Check the Actions logs to see how many items were fetched and how many matched
- SMTP issues:
  - Verify EMAIL_* values are correct; check TLS/SSL port (587 vs 465)
  - Look for log lines like "Email not fully configured; missing: ..." or SMTP error messages
  - Ensure EMAIL_TO is comma- or semicolon-separated and addresses are valid

## License
TBD (to be determined). MIT may be adopted later.

Looking for the Simplified Chinese version? See README.zh-CN.md.
