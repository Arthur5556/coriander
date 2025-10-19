#!/usr/bin/env python3
import os
import sys
import json
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple

import requests

CIRCL_LAST_URL = "https://cve.circl.lu/api/last/{count}"


def log(msg: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    print(f"[{now}] {msg}")


def find_targets_file() -> str:
    # Prefer override via environment variable
    override = os.getenv("CVE_TARGETS_FILE")
    if override and os.path.isfile(override):
        return override

    # Try current working directory
    cwd_path = os.path.join(os.getcwd(), "cve_targets.txt")
    if os.path.isfile(cwd_path):
        return cwd_path

    # Try repository root (parent of this script's directory)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, os.pardir))
    root_path = os.path.join(repo_root, "cve_targets.txt")
    if os.path.isfile(root_path):
        return root_path

    # Fall back to just the plain filename
    return "cve_targets.txt"


def read_keywords(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            keywords = []
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                keywords.append(s)
            return keywords
    except FileNotFoundError:
        log(f"Targets file not found: {path}. No keywords to search.")
        return []


# -------------------- CIRCL helpers --------------------

def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse datetime strings from CIRCL. Make timezone-aware in UTC when possible."""
    if not value:
        return None
    try:
        # Handle trailing Z
        v = value
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        # If there's no timezone, assume UTC
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        # Try common formats
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None


def fetch_recent_circl_cves() -> List[dict]:
    """Fetch the most recent CVEs from CIRCL, trying larger counts first and
    gracefully degrading on errors or rate limits.
    """
    for count in (200, 100, 50):
        url = CIRCL_LAST_URL.format(count=count)
        try:
            resp = requests.get(url, timeout=30)
        except Exception as e:
            log(f"Error querying CIRCL {url}: {e}")
            continue

        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    return data
                # Some responses might wrap differently, attempt to normalize
                if isinstance(data, dict) and "cves" in data and isinstance(data["cves"], list):
                    return data["cves"]
                # Fallback: unknown format
                log("CIRCL response JSON format was not a list; proceeding with empty list.")
                return []
            except json.JSONDecodeError:
                log("Failed to decode CIRCL response as JSON")
                return []
        else:
            preview = resp.text[:300] if resp.text else ""
            log(f"CIRCL API returned status {resp.status_code} for {url}. {preview}")
            # Try next smaller count on 4xx/5xx
            continue

    # If all attempts failed
    return []


def extract_circl_summary(item: dict) -> Optional[Dict[str, Optional[str]]]:
    """Extract the fields we need from a CIRCL CVE item."""
    cve_id = item.get("id") or item.get("cve")
    if not cve_id:
        return None

    published_raw = item.get("Published") or item.get("published")
    published_dt = _parse_datetime(published_raw)
    published_str = None
    if published_dt:
        published_str = published_dt.astimezone(timezone.utc).isoformat()

    summary = item.get("summary") or item.get("description") or ""

    # References can be a list of URLs
    references = item.get("references") or []
    ref_url = None
    if isinstance(references, list) and references:
        ref_url = str(references[0])
    elif isinstance(references, str):
        ref_url = references

    # Scores
    cvss3 = item.get("cvss3")
    cvss2 = item.get("cvss")

    score_val = None
    sev_label = None
    # Prefer cvss3 if present
    if cvss3 is not None:
        try:
            score_val = float(cvss3)
        except (TypeError, ValueError):
            # sometimes provided as string with vector; best effort to extract number at start
            try:
                score_val = float(str(cvss3).split()[0])
            except Exception:
                score_val = None
        sev_label = f"CVSS3 {score_val}" if score_val is not None else "CVSS3"
    elif cvss2 is not None:
        try:
            score_val = float(cvss2)
        except (TypeError, ValueError):
            try:
                score_val = float(str(cvss2).split()[0])
            except Exception:
                score_val = None
        sev_label = f"CVSS {score_val}" if score_val is not None else "CVSS"

    return {
        "id": cve_id,
        "published": published_str or (published_raw or None),
        "score": f"{score_val}" if score_val is not None else None,
        "severity": sev_label,
        "description": summary,
        "url": ref_url,
    }


# -------------------- Email --------------------

def send_email(subject: str, body: str) -> bool:
    host = os.getenv("EMAIL_HOST")
    port = os.getenv("EMAIL_PORT")
    user = os.getenv("EMAIL_USER")
    password = os.getenv("EMAIL_PASS")
    from_addr = os.getenv("EMAIL_FROM")
    to_addrs_raw = os.getenv("EMAIL_TO")

    if not host or not from_addr or not to_addrs_raw:
        log("Email configuration missing (EMAIL_HOST, EMAIL_FROM, EMAIL_TO required). Skipping email.")
        return False

    try:
        port_i = int(port) if port else 587
    except ValueError:
        port_i = 587

    to_addrs = [addr.strip() for addr in to_addrs_raw.replace(";", ",").split(",") if addr.strip()]
    if not to_addrs:
        log("No valid recipients parsed from EMAIL_TO. Skipping email.")
        return False

    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        if port_i == 465:
            server = smtplib.SMTP_SSL(host, port_i, timeout=30)
        else:
            server = smtplib.SMTP(host, port_i, timeout=30)
        with server:
            server.ehlo()
            if port_i != 465:
                try:
                    server.starttls()
                except smtplib.SMTPException:
                    pass
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
        log("Email successfully sent")
        return True
    except Exception as e:
        log(f"Failed to send email: {e}")
        return False


# -------------------- Formatting --------------------

def _safe_parse_any_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return _parse_datetime(s)
    except Exception:
        return None


def build_email_content(keywords: List[str], start: datetime, end: datetime, cves: List[Dict[str, Optional[str]]]) -> Tuple[str, str]:
    end_s = end.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    start_s = start.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = f"CVE Monitor: {len(cves)} match(es) between {start_s} and {end_s}"

    lines: List[str] = []
    lines.append("CVE Monitor Summary")
    lines.append("")
    lines.append(f"Window: {start_s} -> {end_s}")
    if keywords:
        lines.append(f"Keywords: {', '.join(keywords)}")
    lines.append(f"Total unique CVEs found: {len(cves)}")
    lines.append("")

    # Sort by published date descending when available
    def sort_key(x):
        pub = x.get("published")
        dt = _safe_parse_any_iso(pub)
        return dt or datetime.min.replace(tzinfo=timezone.utc)

    for cve in sorted(cves, key=sort_key, reverse=True):
        cid = cve.get("id") or "(unknown)"
        sev = cve.get("severity") or "N/A"
        score = cve.get("score") or "N/A"
        pub = cve.get("published") or "N/A"
        desc = (cve.get("description") or "").strip()
        if len(desc) > 500:
            desc = desc[:497] + "..."
        url = cve.get("url") or "N/A"

        lines.append(f"- {cid} | Severity: {sev} | Score: {score}")
        lines.append(f"  Published: {pub}")
        if desc:
            lines.append(f"  Description: {desc}")
        lines.append(f"  Reference: {url}")
        lines.append("")

    body = "\n".join(lines)
    return subject, body


# -------------------- Main --------------------

def main() -> int:
    targets_file = find_targets_file()
    keywords = read_keywords(targets_file)
    log(f"Loaded {len(keywords)} keyword(s) from {targets_file}")

    # Compute 10-minute UTC window to tolerate scheduler drift
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(minutes=10)

    if not keywords:
        log("No keywords specified. Exiting without querying CIRCL.")
        return 0

    # Fetch recent CVEs from CIRCL
    log("Fetching recent CVEs from CIRCL (prioritizing freshness)...")
    items = fetch_recent_circl_cves()
    log(f"CIRCL returned {len(items)} CVE item(s)")

    # Filter: published within window and keyword match (id or summary)
    matches_map: Dict[str, Dict[str, Optional[str]]] = {}
    for item in items:
        try:
            published_raw = item.get("Published") or item.get("published")
            published_dt = _parse_datetime(published_raw)
            if not published_dt:
                continue
            if not (start_dt <= published_dt <= end_dt):
                continue

            cve_id = item.get("id") or item.get("cve") or ""
            summary = (item.get("summary") or item.get("description") or "").lower()
            id_lower = str(cve_id).lower()

            if not any(kw.lower() in id_lower or kw.lower() in summary for kw in keywords):
                continue

            summary_obj = extract_circl_summary(item)
            if not summary_obj:
                continue

            cid = summary_obj["id"]
            if cid not in matches_map:
                matches_map[cid] = summary_obj
        except Exception as e:
            # Robust handling: skip malformed entries
            log(f"Skipping malformed CVE item due to error: {e}")
            continue

    matches = list(matches_map.values())
    log(f"Filtered to {len(matches)} matching CVE(s) within the last 10 minutes")

    if matches:
        subject, body = build_email_content(keywords, start_dt, end_dt, matches)
        send_email(subject, body)
    else:
        log("No CVEs matched the keywords in the 10-minute window. No email will be sent.")

    # Always exit 0 to avoid failing the workflow on transient issues
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Catch-all to ensure non-failing exit per requirements
        log(f"Unexpected error: {e}")
        sys.exit(0)
