#!/usr/bin/env python3
import os
import sys
import time
import json
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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


def iso8601_utc_z(dt: datetime) -> str:
    # NVD expects ISO 8601 in UTC with a trailing 'Z'. Include milliseconds.
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"


def fetch_cves_for_keyword(keyword: str, start_iso: str, end_iso: str, api_key: Optional[str]) -> List[dict]:
    """Fetch all CVEs for a given keyword and time window, handling pagination."""
    headers = {}
    if api_key:
        # Support both common header names, though NVD uses 'apiKey'
        headers["apiKey"] = api_key
        headers["X-Api-Key"] = api_key

    results: List[dict] = []
    start_index = 0
    page_size = 2000  # Max allowed by NVD; minimizes pagination

    while True:
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_iso,
            "pubEndDate": end_iso,
            "startIndex": start_index,
            "resultsPerPage": page_size,
            "noRejected": "true",
        }
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        except Exception as e:
            log(f"Error querying NVD for '{keyword}': {e}")
            break

        if resp.status_code != 200:
            log(
                f"NVD API returned status {resp.status_code} for '{keyword}'. "
                f"Response: {resp.text[:300]}"
            )
            break

        try:
            data = resp.json()
        except json.JSONDecodeError:
            log("Failed to decode NVD response as JSON")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        results.extend(vulnerabilities)

        total = int(data.get("totalResults", len(results)))
        rpp = int(data.get("resultsPerPage", page_size))
        start_index += rpp

        if start_index >= total or not vulnerabilities:
            break

        # Be nice to the API if no key is provided
        if not api_key:
            time.sleep(1.2)

    return results


def extract_cve_summary(item: dict) -> Optional[Dict[str, Optional[str]]]:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    published = cve.get("published")

    # Description (prefer English)
    description = None
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en" and desc.get("value"):
            description = desc.get("value")
            break
    if not description and cve.get("descriptions"):
        description = (cve.get("descriptions")[0] or {}).get("value")

    # Metrics: prefer CVSS v3.1, then v3.0, then v2
    score: Optional[float] = None
    severity: Optional[str] = None
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            entry = arr[0]
            cvss = entry.get("cvssData") or {}
            score = cvss.get("baseScore")
            severity = entry.get("baseSeverity") or entry.get("severity")
            break

    # First reference URL if available
    ref_url = None
    for ref in cve.get("references", []) or []:
        url = ref.get("url")
        if url:
            ref_url = url
            break

    return {
        "id": cve_id,
        "published": published,
        "score": f"{score}" if score is not None else None,
        "severity": severity,
        "description": description,
        "url": ref_url,
    }


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


def build_email_content(keywords: List[str], start: datetime, end: datetime, cves: List[Dict[str, Optional[str]]]) -> Tuple[str, str]:
    end_s = end.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    start_s = start.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = f"CVE Monitor: {len(cves)} match(es) between {start_s} and {end_s}"

    lines = []
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
        try:
            # NVD format is ISO w/o timezone suffix sometimes; handle both
            if pub and pub.endswith("Z"):
                return datetime.strptime(pub, "%Y-%m-%dT%H:%M:%S.%fZ")
            elif pub:
                return datetime.strptime(pub, "%Y-%m-%dT%H:%M:%S.%f")
        except Exception:
            pass
        return datetime.min

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


def main() -> int:
    targets_file = find_targets_file()
    keywords = read_keywords(targets_file)
    log(f"Loaded {len(keywords)} keyword(s) from {targets_file}")

    # Compute 1-hour UTC window
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(hours=1)
    start_iso = iso8601_utc_z(start_dt)
    end_iso = iso8601_utc_z(end_dt)

    api_key = os.getenv("NVD_API_KEY")

    cve_map: Dict[str, Dict[str, Optional[str]]] = {}
    total_api_items = 0

    if not keywords:
        log("No keywords specified. Exiting without querying NVD.")
    else:
        for kw in keywords:
            log(f"Querying NVD for keyword '{kw}' within last hour...")
            items = fetch_cves_for_keyword(kw, start_iso, end_iso, api_key)
            total_api_items += len(items)
            for item in items:
                summary = extract_cve_summary(item)
                if not summary:
                    continue
                cve_id = summary["id"]
                if cve_id not in cve_map:
                    cve_map[cve_id] = summary

    cves = list(cve_map.values())
    log(f"NVD results: {total_api_items} item(s) returned across keywords; {len(cves)} unique CVE(s) after de-dup.")

    if cves:
        subject, body = build_email_content(keywords, start_dt, end_dt, cves)
        send_email(subject, body)
    else:
        log("No CVEs found in the last hour for the given keywords. No email will be sent.")

    # Always exit 0 to avoid failing the workflow
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Catch-all to ensure non-failing exit per requirements
        log(f"Unexpected error: {e}")
        sys.exit(0)
