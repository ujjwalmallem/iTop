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
# Accuracy: configurable rule engine
# ---------------------------------------------------------------------------
# Rules file (JSON): { "Server": [ {rule}, {rule} ], "VirtualMachine": [...] }
# Supported checks:
#   not_blank        -> attribute must have a value
#   allowed_values   -> value must be in "values" list (case-insensitive);
#                       set "allow_blank": true to tolerate blanks
#   regex            -> non-blank values must match "pattern"
#   after            -> attribute (date) must be >= "other" attribute
#   not_past_if      -> attribute (date) must not be in the past when
#                       "other" attribute's value is in "values"
#   max_age_days     -> attribute (date) must be within last N "days"

def load_rules(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def apply_rules(itop_class, records, class_rules):
    """Returns list of violation dicts with per-record drill-down."""
    violations = []
    today = datetime.now().strftime("%Y-%m-%d")
    for rule in class_rules:
        attr = rule.get("attribute", "")
        check = rule.get("check", "")
        rname = rule.get("name") or f"{attr}: {check}"
        sev = rule.get("severity", "medium")
        for r in records:
            val = scalarize(r.get(attr))
            sval = "" if is_blank(val) else str(val).strip()
            bad, detail = False, ""

            if check == "not_blank":
                bad = is_blank(val)
                detail = "blank/NULL"
            elif check == "allowed_values":
                allowed = {str(v).strip().lower() for v in rule.get("values", [])}
                if is_blank(val):
                    bad = not rule.get("allow_blank", False)
                    detail = "blank/NULL"
                else:
                    bad = sval.lower() not in allowed
                    detail = f"value '{sval}' not in allowed list"
            elif check == "regex":
                if not is_blank(val):
                    bad = not re.match(rule.get("pattern", ".*"), sval)
                    detail = f"value '{sval}' does not match pattern"
            elif check == "after":
                other = scalarize(r.get(rule.get("other", "")))
                if not is_blank(val) and not is_blank(other):
                    bad = str(val)[:10] < str(other)[:10]
                    detail = f"{attr}={val} is before {rule.get('other')}={other}"
            elif check == "not_past_if":
                other = str(scalarize(r.get(rule.get("other", ""))) or "").strip().lower()
                trigger = {str(v).lower() for v in rule.get("values", [])}
                if not is_blank(val) and other in trigger:
                    bad = sval[:10] < today
                    detail = f"{attr}={val} is in the past while {rule.get('other')}='{other}'"
            elif check == "max_age_days":
                days = int(rule.get("days", 90))
                cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
                if not is_blank(val):
                    bad = sval[:10] < cutoff
                    detail = f"{attr}={val} older than {days} days"

            if bad:
                violations.append({
                    "class": itop_class,
                    "id": r.get("_id", ""),
                    "record_name": scalarize(r.get("name", "")) or "",
                    "rule": rname,
                    "severity": sev,
                    "attribute": attr,
                    "value": sval,
                    "detail": detail,
                })
    return violations


# ---------------------------------------------------------------------------
# Accuracy: reconciliation against an authoritative source (CSV)
# ---------------------------------------------------------------------------

def _norm(v):
    return str(v or "").strip().lower()


def reconcile(itop_class, records, csv_path, match_on, compare_fields):
    """Compare iTop records with an authoritative CSV export.

    Returns dict with:
      missing_in_itop  -> keys present in source but absent from iTop
      ghosts_in_itop   -> keys present in iTop but absent from source
      mismatches       -> per-field value differences for matched records
    """
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        src_rows = list(csv.DictReader(f))
    if not src_rows:
        raise ValueError(f"{csv_path} is empty")
    if match_on not in src_rows[0]:
        raise ValueError(f"Column '{match_on}' not found in {csv_path} "
                         f"(columns: {', '.join(src_rows[0].keys())})")

    src = {_norm(row.get(match_on)): row for row in src_rows
           if _norm(row.get(match_on))}
    itop = {_norm(r.get(match_on)): r for r in records
            if not is_blank(r.get(match_on))}

    missing = sorted(set(src) - set(itop))
    ghosts = sorted(set(itop) - set(src))

    mismatches = []
    for key in set(src) & set(itop):
        for field in compare_fields:
            sv, iv = _norm(src[key].get(field)), _norm(scalarize(itop[key].get(field)))
            if sv != iv:
                mismatches.append({
                    "class": itop_class,
                    "key": key,
                    "id": itop[key].get("_id", ""),
                    "field": field,
                    "itop_value": scalarize(itop[key].get(field)),
                    "source_value": src[key].get(field, ""),
                })

    matched = len(set(src) & set(itop))
    accuracy_pct = round(100.0 * (matched * len(compare_fields) - len(mismatches))
                         / (matched * len(compare_fields)), 1) if matched and compare_fields else None
    return {
        "class": itop_class,
        "source": os.path.basename(csv_path),
        "source_total": len(src),
        "itop_total": len(itop),
        "matched": matched,
        "missing_in_itop": missing,
        "ghosts_in_itop": ghosts,
        "mismatches": mismatches,
        "accuracy_pct": accuracy_pct,
    }


def write_violations_csv(path, violations):
    fields = ["class", "id", "record_name", "rule", "severity",
              "attribute", "value", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(violations)


def write_reconciliation_csv(path, recon_results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["class", "issue_type", "key", "itop_id", "field",
                    "itop_value", "source_value"])
        for rec in recon_results:
            for k in rec["missing_in_itop"]:
                w.writerow([rec["class"], "missing_in_itop", k, "", "", "", ""])
            for k in rec["ghosts_in_itop"]:
                w.writerow([rec["class"], "ghost_in_itop", k, "", "", "", ""])
            for m in rec["mismatches"]:
                w.writerow([rec["class"], "value_mismatch", m["key"], m["id"],
                            m["field"], m["itop_value"], m["source_value"]])


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


def write_html_report(path, rows, all_issues, class_totals,
                      violations=None, recon_results=None):
    violations = violations or []
    recon_results = recon_results or []

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

    # ---- Accuracy: rule violations (drill-down) ----
    if violations:
        by_rule = {}
        for v in violations:
            by_rule.setdefault((v["class"], v["rule"], v["severity"]), []).append(v)
        parts.append(f"<h2>Accuracy rule violations "
                     f"({len(violations)} records, drill-down in violations.csv)</h2>")
        parts.append("<table><tr><th>Class</th><th>Rule</th><th>Severity</th>"
                     "<th>Count</th><th>Sample records (id: name = value)</th></tr>")
        for (cls_, rule, sev), items in sorted(by_rule.items(),
                                               key=lambda kv: -len(kv[1])):
            sample = "; ".join(
                f"{i['id']}: {i['record_name'] or '?'} = '{i['value']}'"
                for i in items[:8])
            row_cls = "bad" if sev == "high" else "warn"
            parts.append(f"<tr class='{row_cls}'><td>{esc(cls_)}</td>"
                         f"<td>{esc(rule)}</td><td>{esc(sev)}</td>"
                         f"<td>{len(items)}</td><td>{esc(sample)}</td></tr>")
        parts.append("</table>")

    # ---- Accuracy: reconciliation vs authoritative source ----
    for rec in recon_results:
        acc = f" &middot; field accuracy {rec['accuracy_pct']}%" \
            if rec["accuracy_pct"] is not None else ""
        parts.append(f"<h2>Reconciliation: {esc(rec['class'])} vs "
                     f"{esc(rec['source'])}</h2>")
        parts.append(f"<p>Source: {rec['source_total']} &middot; "
                     f"iTop: {rec['itop_total']} &middot; "
                     f"matched: {rec['matched']} &middot; "
                     f"<b>missing in iTop: {len(rec['missing_in_itop'])}</b> &middot; "
                     f"<b>ghosts in iTop: {len(rec['ghosts_in_itop'])}</b> &middot; "
                     f"value mismatches: {len(rec['mismatches'])}{acc}</p>")
        if rec["missing_in_itop"]:
            parts.append("<p class='flags'>Missing in iTop (exists in source): "
                         + esc(", ".join(rec["missing_in_itop"][:30])) + "</p>")
        if rec["ghosts_in_itop"]:
            parts.append("<p class='flags'>Ghosts in iTop (not in source): "
                         + esc(", ".join(rec["ghosts_in_itop"][:30])) + "</p>")
        if rec["mismatches"]:
            parts.append("<table><tr><th>Key</th><th>iTop ID</th><th>Field</th>"
                         "<th>iTop value</th><th>Source value</th></tr>")
            for m in rec["mismatches"][:100]:
                parts.append(f"<tr class='warn'><td>{esc(m['key'])}</td>"
                             f"<td>{esc(m['id'])}</td><td>{esc(m['field'])}</td>"
                             f"<td>{esc(m['itop_value'])}</td>"
                             f"<td>{esc(m['source_value'])}</td></tr>")
            parts.append("</table>")

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
    ap.add_argument("--rules",
                    help="JSON rules file for accuracy checks (see example_rules.json)")
    ap.add_argument("--reconcile", action="append", default=[],
                    metavar="Class=source.csv",
                    help="Reconcile a class against an authoritative CSV export "
                         "(repeatable), e.g. --reconcile Server=aws_inventory.csv")
    ap.add_argument("--match-on", default="name",
                    help="Key column used to match iTop records to source rows")
    ap.add_argument("--compare", default="",
                    help="Comma-separated fields to compare during reconciliation, "
                         "e.g. managementip,osfamily,brand")
    ap.add_argument("--out", default="itop_profile_output")
    args = ap.parse_args()

    if not (args.url and args.user and args.pwd):
        ap.error("Provide --url/--user/--pwd or set ITOP_URL/ITOP_USER/ITOP_PWD")

    os.makedirs(args.out, exist_ok=True)
    if args.no_verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    client = ITopClient(args.url, args.user, args.pwd,
                        api_version=args.api_version,
                        verify_ssl=not args.no_verify_ssl)

    rules = load_rules(args.rules) if args.rules else {}
    recon_specs = {}
    for spec in args.reconcile:
        if "=" not in spec:
            ap.error(f"--reconcile expects Class=path.csv, got: {spec}")
        cls_, path_ = spec.split("=", 1)
        recon_specs[cls_.strip()] = path_.strip()
    compare_fields = [f.strip() for f in args.compare.split(",") if f.strip()]

    all_rows, all_issues, class_totals = [], [], {}
    all_violations, recon_results = [], []

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

        if itop_class in rules:
            v = apply_rules(itop_class, records, rules[itop_class])
            print(f"    -> {len(v)} rule violation(s)")
            all_violations.extend(v)

        if itop_class in recon_specs:
            try:
                rec = reconcile(itop_class, records, recon_specs[itop_class],
                                args.match_on, compare_fields)
                recon_results.append(rec)
                print(f"    -> reconciliation: {len(rec['missing_in_itop'])} missing, "
                      f"{len(rec['ghosts_in_itop'])} ghosts, "
                      f"{len(rec['mismatches'])} mismatches")
            except Exception as e:
                print(f"    !! Reconciliation failed for {itop_class}: {e}")

        if args.dump_raw:
            dump_raw_csv(os.path.join(args.out, f"{itop_class}_records.csv"), records)

    if not all_rows:
        sys.exit("No data profiled — check credentials/classes.")

    write_summary_csv(os.path.join(args.out, "summary.csv"), all_rows)
    if all_violations:
        write_violations_csv(os.path.join(args.out, "violations.csv"), all_violations)
    if recon_results:
        write_reconciliation_csv(os.path.join(args.out, "reconciliation.csv"),
                                 recon_results)
    write_html_report(os.path.join(args.out, "profile_report.html"),
                      all_rows, all_issues, class_totals,
                      violations=all_violations, recon_results=recon_results)

    n_flagged = sum(1 for r in all_rows if r["flag_count"])
    print(f"\n[OK] Profiled {len(all_rows)} attributes across {len(class_totals)} classes")
    print(f"     {n_flagged} attributes flagged, {len(all_issues)} cross-attribute issues")
    if all_violations:
        print(f"     {len(all_violations)} accuracy rule violations -> violations.csv")
    if recon_results:
        print(f"     {len(recon_results)} reconciliation report(s) -> reconciliation.csv")
    print(f"     Report: {os.path.join(args.out, 'profile_report.html')}")


if __name__ == "__main__":
    main()
