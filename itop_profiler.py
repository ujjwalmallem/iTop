#!/usr/bin/env python3
"""
iTop Data Quality Profiler (REST API edition)
=============================================
Profiles EVERY attribute of the iTop classes you specify and produces a
data-quality scorecard: completeness, cardinality, value distributions,
date sanity, case-variant detection, and staleness.

Works against iTop 3.x REST/JSON API (also compatible with 2.7+).

Usage:
    python itop_profiler.py --url https://itop.example.com \
        --user rest_user --pwd 'secret' \
        --classes Server,VirtualMachine,PC,ApplicationSolution

    # Credentials can also come from environment variables:
    #   ITOP_URL, ITOP_USER, ITOP_PWD

Outputs (in ./itop_profile_output/):
    - profile_report.html   -> human-readable scorecard, worst attributes first
    - summary.csv           -> one row per (class, attribute) with all metrics
    - <Class>_records.csv   -> raw pulled data per class (optional, --dump-raw)

Requirements: pip install requests
"""

import argparse
import csv
import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_CLASSES = [
    "Server", "VirtualMachine", "PC", "NetworkDevice",
    "ApplicationSolution", "DBServer", "WebApplication",
]

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$")
NUM_RE = re.compile(r"^-?\d+(\.\d+)?$")

# Attributes that are noise for profiling purposes
SKIP_ATTRS = {"friendlyname", "finalclass"}

STALE_DAYS = 90          # last_update older than this => stale
BLANK_WARN_PCT = 10.0    # completeness warning threshold
EXPIRED_STATUSES = {"production", "implementation"}  # active statuses


# ---------------------------------------------------------------------------
# iTop REST client
# ---------------------------------------------------------------------------

class ITopClient:
    def __init__(self, url, user, pwd, api_version="1.3", verify_ssl=True):
        self.endpoint = url.rstrip("/") + "/webservices/rest.php"
        self.user = user
        self.pwd = pwd
        self.api_version = api_version
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

    def _post(self, json_data):
        resp = self.session.post(
            self.endpoint,
            params={"version": self.api_version},
            data={
                "auth_user": self.user,
                "auth_pwd": self.pwd,
                "json_data": json.dumps(json_data),
            },
            verify=self.verify_ssl,
            timeout=120,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("code", 0) != 0:
            raise RuntimeError(f"iTop API error {payload.get('code')}: {payload.get('message')}")
        return payload

    def fetch_all(self, itop_class, page_size=500):
        """Pull all records of a class, paginated. Returns list of field dicts."""
        records = []
        page = 1
        while True:
            payload = self._post({
                "operation": "core/get",
                "class": itop_class,
                "key": f"SELECT {itop_class}",
                "output_fields": "*",
                "limit": page_size,
                "page": page,
            })
            objects = payload.get("objects") or {}
            if not objects:
                break
            for _, obj in objects.items():
                fields = obj.get("fields", {})
                fields["_id"] = obj.get("key", "")
                records.append(fields)
            if len(objects) < page_size:
                break
            page += 1
        return records


# ---------------------------------------------------------------------------
# Profiling logic
# ---------------------------------------------------------------------------

def is_blank(v):
    return v is None or (isinstance(v, str) and v.strip() == "")


def scalarize(v):
    """Link sets / nested structures come back as lists/dicts: summarize them."""
    if isinstance(v, list):
        return f"<linkset:{len(v)} items>" if v else ""
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True)[:120]
    return v


def profile_attribute(name, values):
    """Compute metrics for one attribute given all its values."""
    total = len(values)
    scalars = [scalarize(v) for v in values]
    blanks = sum(1 for v in scalars if is_blank(v))
    non_blank = [str(v).strip() for v in scalars if not is_blank(v)]

    completeness = 100.0 * (total - blanks) / total if total else 0.0
    distinct = len(set(non_blank))
    counter = Counter(non_blank)
    top5 = counter.most_common(5)

    # Type detection on non-blank sample
    sample = non_blank[:200]
    n_dates = sum(1 for v in sample if DATE_RE.match(v))
    n_nums = sum(1 for v in sample if NUM_RE.match(v))
    if sample and n_dates / len(sample) > 0.8:
        dtype = "date"
    elif sample and n_nums / len(sample) > 0.8:
        dtype = "number"
    elif distinct and total and distinct <= max(15, total * 0.02):
        dtype = "enum-like"
    else:
        dtype = "text"

    vmin = vmax = ""
    if dtype in ("date", "number") and non_blank:
        try:
            if dtype == "number":
                nums = [float(v) for v in non_blank if NUM_RE.match(v)]
                vmin, vmax = min(nums), max(nums)
            else:
                dates = [v for v in non_blank if DATE_RE.match(v)]
                vmin, vmax = min(dates), max(dates)
        except ValueError:
            pass

    # ---- Flags (this is where confidence problems surface) ----
    flags = []
    if total and blanks:
        pct_blank = 100.0 * blanks / total
        if pct_blank >= BLANK_WARN_PCT:
            flags.append(f"{pct_blank:.0f}% blank/NULL")
        else:
            flags.append(f"{blanks} blank record(s)")
    if dtype == "enum-like":
        # Case-variant duplicates: 'Production' vs 'production'
        lowered = Counter(v.lower() for v in counter)
        variants = [k for k, c in lowered.items()
                    if c < sum(1 for x in counter if x.lower() == k) or
                    len({x for x in counter if x.lower() == k}) > 1]
        variant_groups = {}
        for v in counter:
            variant_groups.setdefault(v.lower(), set()).add(v)
        bad = {k: v for k, v in variant_groups.items() if len(v) > 1}
        if bad:
            examples = "; ".join(" / ".join(sorted(v)) for v in list(bad.values())[:3])
            flags.append(f"case-variant values: {examples}")
    if dtype == "date" and vmin:
        today = datetime.now().strftime("%Y-%m-%d")
        if str(vmin) < "1990-01-01":
            flags.append(f"suspicious old date: {vmin}")
        if str(vmax)[:10] > (datetime.now() + timedelta(days=3650)).strftime("%Y-%m-%d"):
            flags.append(f"suspicious future date: {vmax}")
    if total and distinct == 1 and blanks == 0:
        flags.append("single constant value (attribute may be unused/defaulted)")

    return {
        "attribute": name,
        "type": dtype,
        "total": total,
        "blanks": blanks,
        "completeness_pct": round(completeness, 1),
        "distinct": distinct,
        "min": vmin,
        "max": vmax,
        "top_values": "; ".join(f"{v} ({c})" for v, c in top5),
        "flags": " | ".join(flags),
        "flag_count": len(flags),
    }


def cross_checks(itop_class, records):
    """Class-level consistency checks that span multiple attributes."""
    issues = []
    total = len(records)
    if not total:
        return issues

    keys = records[0].keys()
    has = lambda k: k in keys  # noqa: E731
    today = datetime.now().strftime("%Y-%m-%d")

    # end_date < start_date
    if has("start_date") and has("end_date"):
        bad = [r["_id"] for r in records
               if not is_blank(r.get("start_date")) and not is_blank(r.get("end_date"))
               and str(r["end_date"]) < str(r["start_date"])]
        if bad:
            issues.append((f"{itop_class}: end_date earlier than start_date",
                           len(bad), bad[:20]))

    # expired end_date on active CI
    if has("end_date") and has("status"):
        bad = [r["_id"] for r in records
               if not is_blank(r.get("end_date"))
               and str(r["end_date"])[:10] < today
               and str(r.get("status", "")).lower() in EXPIRED_STATUSES]
        if bad:
            issues.append((f"{itop_class}: end_date in the past but status is active",
                           len(bad), bad[:20]))

    # staleness
    for f in ("last_update", "last_modified"):
        if has(f):
            cutoff = (datetime.now() - timedelta(days=STALE_DAYS)).strftime("%Y-%m-%d")
            stale = [r["_id"] for r in records
                     if not is_blank(r.get(f)) and str(r[f])[:10] < cutoff]
            if stale:
                issues.append((f"{itop_class}: not updated in {STALE_DAYS}+ days ({f})",
                               len(stale), stale[:20]))
            break

    # duplicate names
    if has("name"):
        names = Counter(str(r.get("name", "")).strip().lower()
                        for r in records if not is_blank(r.get("name")))
        dupes = {n: c for n, c in names.items() if c > 1}
        if dupes:
            ex = "; ".join(f"{n} (x{c})" for n, c in list(dupes.items())[:5])
            issues.append((f"{itop_class}: duplicate names -> {ex}",
                           sum(dupes.values()), []))

    return issues


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_summary_csv(path, rows):
    fields = ["class", "attribute", "type", "total", "blanks", "completeness_pct",
              "distinct", "min", "max", "top_values", "flags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_html_report(path, rows, all_issues, class_totals):
    def esc(x):
        return html.escape(str(x))

    flagged = sorted([r for r in rows if r["flag_count"]],
                     key=lambda r: (-r["flag_count"], r["completeness_pct"]))
    clean = [r for r in rows if not r["flag_count"]]

    css = """
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#222}
    h1{font-size:1.4em} h2{font-size:1.15em;margin-top:1.6em}
    table{border-collapse:collapse;width:100%;font-size:.85em}
    th,td{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top}
    th{background:#f2f2f2} tr:nth-child(even){background:#fafafa}
    .bad{background:#ffe9e9} .warn{background:#fff6e0}
    .pct-low{color:#b00020;font-weight:bold} .pct-ok{color:#1a7a1a}
    .flags{color:#b00020} .muted{color:#888}
    """
    parts = [f"<html><head><meta charset='utf-8'><title>iTop Data Quality Report</title>"
             f"<style>{css}</style></head><body>"]
    parts.append(f"<h1>iTop Data Quality Report</h1>"
                 f"<p class='muted'>Generated {datetime.now():%Y-%m-%d %H:%M} &middot; "
                 f"{sum(class_totals.values())} records across "
                 f"{len(class_totals)} classes</p>")

    parts.append("<h2>Record counts</h2><table><tr><th>Class</th><th>Records</th></tr>")
    for c, n in class_totals.items():
        parts.append(f"<tr><td>{esc(c)}</td><td>{n}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>Cross-attribute consistency issues</h2>")
    if all_issues:
        parts.append("<table><tr><th>Issue</th><th>Count</th><th>Sample record IDs</th></tr>")
        for desc, count, sample in all_issues:
            parts.append(f"<tr class='bad'><td>{esc(desc)}</td><td>{count}</td>"
                         f"<td>{esc(', '.join(map(str, sample)))}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p>None found.</p>")

    parts.append("<h2>Attributes with quality flags (worst first)</h2>")
    parts.append("<table><tr><th>Class</th><th>Attribute</th><th>Type</th>"
                 "<th>Complete %</th><th>Blanks</th><th>Distinct</th>"
                 "<th>Min</th><th>Max</th><th>Top values</th><th>Flags</th></tr>")
    for r in flagged:
        cls = "bad" if r["completeness_pct"] < 90 else "warn"
        pct_cls = "pct-low" if r["completeness_pct"] < 90 else ""
        parts.append(
            f"<tr class='{cls}'><td>{esc(r['class'])}</td><td>{esc(r['attribute'])}</td>"
            f"<td>{esc(r['type'])}</td><td class='{pct_cls}'>{r['completeness_pct']}</td>"
            f"<td>{r['blanks']}</td><td>{r['distinct']}</td>"
            f"<td>{esc(r['min'])}</td><td>{esc(r['max'])}</td>"
            f"<td>{esc(r['top_values'])}</td><td class='flags'>{esc(r['flags'])}</td></tr>")
    parts.append("</table>")

    parts.append(f"<h2>Clean attributes ({len(clean)})</h2>")
    parts.append("<table><tr><th>Class</th><th>Attribute</th><th>Type</th>"
                 "<th>Complete %</th><th>Distinct</th><th>Top values</th></tr>")
    for r in sorted(clean, key=lambda x: (x["class"], x["attribute"])):
        parts.append(f"<tr><td>{esc(r['class'])}</td><td>{esc(r['attribute'])}</td>"
                     f"<td>{esc(r['type'])}</td><td class='pct-ok'>{r['completeness_pct']}</td>"
                     f"<td>{r['distinct']}</td><td>{esc(r['top_values'])}</td></tr>")
    parts.append("</table></body></html>")

    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(parts))


def dump_raw_csv(path, records):
    if not records:
        return
    keys = sorted({k for r in records for k in r})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow({k: scalarize(v) for k, v in r.items()})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="iTop REST API data quality profiler")
    ap.add_argument("--url", default=os.environ.get("ITOP_URL"),
                    help="iTop base URL, e.g. https://itop.example.com")
    ap.add_argument("--user", default=os.environ.get("ITOP_USER"))
    ap.add_argument("--pwd", default=os.environ.get("ITOP_PWD"))
    ap.add_argument("--classes", default=",".join(DEFAULT_CLASSES),
                    help="Comma-separated iTop classes to profile")
    ap.add_argument("--api-version", default="1.3")
    ap.add_argument("--page-size", type=int, default=500)
    ap.add_argument("--no-verify-ssl", action="store_true",
                    help="Skip TLS certificate verification (self-signed certs)")
    ap.add_argument("--dump-raw", action="store_true",
                    help="Also dump raw records per class to CSV")
    ap.add_argument("--out", default="itop_profile_output")
    args = ap.parse_args()

    if not (args.url and args.user and args.pwd):
        ap.error("Provide --url/--user/--pwd or set ITOP_URL/ITOP_USER/ITOP_PWD")

    os.makedirs(args.out, exist_ok=True)
    client = ITopClient(args.url, args.user, args.pwd,
                        api_version=args.api_version,
                        verify_ssl=not args.no_verify_ssl)

    all_rows, all_issues, class_totals = [], [], {}

    for itop_class in [c.strip() for c in args.classes.split(",") if c.strip()]:
        print(f"[*] Fetching {itop_class} ...", flush=True)
        try:
            records = client.fetch_all(itop_class, page_size=args.page_size)
        except Exception as e:
            print(f"    !! Failed for {itop_class}: {e}")
            continue
        class_totals[itop_class] = len(records)
        print(f"    -> {len(records)} records")
        if not records:
            continue

        attrs = sorted({k for r in records for k in r} - SKIP_ATTRS - {"_id"})
        for attr in attrs:
            prof = profile_attribute(attr, [r.get(attr) for r in records])
            prof["class"] = itop_class
            all_rows.append(prof)

        all_issues.extend(cross_checks(itop_class, records))

        if args.dump_raw:
            dump_raw_csv(os.path.join(args.out, f"{itop_class}_records.csv"), records)

    if not all_rows:
        sys.exit("No data profiled — check credentials/classes.")

    write_summary_csv(os.path.join(args.out, "summary.csv"), all_rows)
    write_html_report(os.path.join(args.out, "profile_report.html"),
                      all_rows, all_issues, class_totals)

    n_flagged = sum(1 for r in all_rows if r["flag_count"])
    print(f"\n[OK] Profiled {len(all_rows)} attributes across {len(class_totals)} classes")
    print(f"     {n_flagged} attributes flagged, {len(all_issues)} cross-attribute issues")
    print(f"     Report: {os.path.join(args.out, 'profile_report.html')}")


if __name__ == "__main__":
    main()
