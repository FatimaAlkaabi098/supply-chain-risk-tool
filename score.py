"""
Supply Chain Risk Scoring Tool (Software-Only Version)
School of Cyber Defense 2026 - Team Shadow Djinn

Scores an AI server Bill of Materials for supply-chain risk before purchase.

Usage:
    python score.py
    python score.py --bom data/demo_bom.csv --out reports/report.html

Three risk dimensions, as required by the brief:
    1. Known vulnerabilities   - matched against a CVE dataset
    2. Origin and vendor policy - restricted vendors and country tiers
    3. Component factors        - end-of-life and single-source dependency

Plus:
    - concentration risk across the BOM as a whole
    - unverifiable components surfaced, never silently scored as safe

Every weight and threshold in this file is justified in DECISIONS.md.
"""

import argparse
import csv
import html
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Scoring configuration - justified in DECISIONS.md
# ---------------------------------------------------------------------------
W_VULNERABILITY = 0.40
W_POLICY        = 0.35
W_COMPONENT     = 0.25

# A management controller failure is worse than a fan failure.
CRITICALITY = {
    "bmc":      1.5,
    "firmware": 1.5,
    "cpu":      1.3,
    "gpu":      1.2,
    "nic":      1.2,
    "storage":  1.0,
    "memory":   1.0,
    "psu":      0.8,
    "cooling":  0.8,
    "other":    0.9,
}
DEFAULT_CRITICALITY = 1.0

# A component we cannot identify is not a component we have cleared.
# It carries a defined uncertainty penalty rather than a zero.
UNVERIFIED_PENALTY = 50.0

POLICY_SCORES = {"restricted": 100.0, "review": 60.0}
COUNTRY_TIER_SCORES = {"1": 10.0, "2": 40.0, "3": 70.0}

EOL_SCORES = {"yes": 60.0, "unknown": 30.0, "no": 0.0}
SINGLE_SOURCE_SCORE = 40.0

# Concentration risk: a BOM can be low risk part by part and still be
# fragile as a portfolio.
CONCENTRATION_THRESHOLD = 0.40   # one country supplying more than 40%
CONCENTRATION_MAX = 15.0
CRITICAL_CATEGORIES = {"bmc", "firmware", "cpu", "gpu"}

BANDS = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]

REQUIRED_BOM_COLUMNS = [
    "component_id", "component_name", "category", "vendor",
    "model", "version", "country_of_origin", "quantity", "end_of_life",
]
REQUIRED_CVE_COLUMNS = [
    "vendor", "product", "version_affected", "cve_id",
    "cvss_score", "score_source", "severity", "cwe",
    "description", "fix_available",
]
REQUIRED_POLICY_COLUMNS = ["rule_type", "key", "risk_tier", "action", "justification"]

UNKNOWN_VALUES = {"unknown", "", "n/a", "none", "-", "tbd"}

# The CWE tells you the fix. This is the mitigation ladder applied to findings.
CWE_MITIGATIONS = {
    "CWE-290": "Do not trust client-supplied headers for authentication; verify identity server-side. Apply the fixed firmware version.",
    "CWE-306": "Require authentication on every privileged function. Apply the fixed firmware version.",
    "CWE-330": "Use a cryptographically secure random source for session identifiers. Apply the fixed firmware version.",
    "CWE-119": "Apply the vendor firmware update and restrict the management interface to a dedicated out-of-band network.",
    "CWE-120": "Apply the vendor firmware update and restrict the management interface to a dedicated out-of-band network.",
}
DEFAULT_MITIGATION = ("Apply the vendor's fixed version. If no fix exists, isolate the component "
                      "on a segregated management network and evaluate an alternative supplier.")


# Default input paths resolve relative to THIS FILE, not to the shell's current
# directory, so the tool runs correctly however it is launched - from the
# project folder, from an IDE Run button, or from anywhere else. A path given
# explicitly on the command line is still resolved normally.
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BOM    = os.path.join(HERE, "data", "demo_bom.csv")
DEFAULT_CVES   = os.path.join(HERE, "data", "cve_dataset.csv")
DEFAULT_POLICY = os.path.join(HERE, "data", "policy.csv")
DEFAULT_OUT    = os.path.join(HERE, "reports", "report.html")


class DataError(Exception):
    """Raised when an input file cannot be used. Always explains why."""


# ---------------------------------------------------------------------------
# Loading - every loader must fail with an explanation, never a stack trace
# ---------------------------------------------------------------------------
def _read_csv(path, required, label):
    if not os.path.exists(path):
        raise DataError(f"{label} file not found: {path}")
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                raise DataError(f"{label} file is empty: {path}")
            headers = [(h or "").strip() for h in reader.fieldnames]
            missing = [c for c in required if c not in headers]
            if missing:
                raise DataError(
                    f"{label} file is missing required column(s): {', '.join(missing)}\n"
                    f"  found: {', '.join(headers)}")
            rows = []
            for raw in reader:
                row = {(k or "").strip(): (v or "").strip() for k, v in raw.items() if k}
                if not any(row.get(c) for c in required):
                    continue                      # blank or padding row
                rows.append(row)
    except UnicodeDecodeError:
        raise DataError(f"{label} file is not valid UTF-8 text: {path}")
    except csv.Error as exc:
        raise DataError(f"{label} file is not valid CSV: {path} ({exc})")
    if not rows:
        raise DataError(f"{label} file has headers but no data rows: {path}")
    return rows


def load_bom(path):
    rows = _read_csv(path, REQUIRED_BOM_COLUMNS, "BOM")
    seen, out, notes = set(), [], []
    for row in rows:
        cid = row["component_id"]
        if not cid:
            notes.append("skipped row with no component_id")
            continue
        if cid in seen:
            notes.append(f"skipped duplicate component_id {cid}")
            continue
        seen.add(cid)
        row["category"] = row["category"].lower()
        try:
            row["quantity"] = max(1, int(float(row["quantity"] or 1)))
        except ValueError:
            row["quantity"] = 1
            notes.append(f"{cid}: quantity is not a number, treated as 1")
        out.append(row)
    return out, notes


def load_cve_dataset(path):
    return _read_csv(path, REQUIRED_CVE_COLUMNS, "CVE dataset")


def load_policy(path):
    rows = _read_csv(path, REQUIRED_POLICY_COLUMNS, "Policy")
    policy = {"vendors": {}, "countries": {}}
    for r in rows:
        kind = r["rule_type"].lower()
        if kind == "vendor":
            policy["vendors"][r["key"].lower()] = r
        elif kind == "country":
            policy["countries"][r["key"].lower()] = r
    return policy


# ---------------------------------------------------------------------------
# Version handling
# ---------------------------------------------------------------------------
def _version_tuple(value):
    """('6.10.80.00') -> (6, 10, 80, 0). Returns None if not comparable."""
    if value is None:
        return None
    text = value.strip().lower()
    if text in UNKNOWN_VALUES:
        return None
    parts = re.split(r"[.\-_]", text)
    numbers = []
    for part in parts:
        if part.isdigit():
            numbers.append(int(part))
        else:
            digits = re.match(r"^(\d+)", part)
            if not digits:
                return None
            numbers.append(int(digits.group(1)))
    return tuple(numbers) or None


def compare_versions(a, b):
    """-1 if a < b, 0 if equal, 1 if a > b. None when not comparable."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    if ta is None or tb is None:
        return None
    width = max(len(ta), len(tb))
    ta += (0,) * (width - len(ta))
    tb += (0,) * (width - len(tb))
    return (ta > tb) - (ta < tb)


def in_affected_range(version, range_string):
    """Is `version` inside a range such as '>=12.0 <12.4' or '<3.39.30'?"""
    if not range_string or range_string.strip().lower() in UNKNOWN_VALUES | {"unspecified"}:
        return False
    for token in range_string.split():
        match = re.match(r"^(>=|<=|>|<)(.+)$", token)
        if not match:
            return False
        operator, bound = match.groups()
        result = compare_versions(version, bound)
        if result is None:
            return False
        if operator == ">=" and result < 0:
            return False
        if operator == ">" and result <= 0:
            return False
        if operator == "<=" and result > 0:
            return False
        if operator == "<" and result >= 0:
            return False
    return True


# ---------------------------------------------------------------------------
# Dimension 1 - known vulnerabilities
# ---------------------------------------------------------------------------
def is_identifiable(component):
    """Can we establish what this part actually is?"""
    return not (
        component["vendor"].lower() in UNKNOWN_VALUES
        or component["model"].lower() in UNKNOWN_VALUES
        or component["version"].lower() in UNKNOWN_VALUES
    )


def match_cves(component, cve_data):
    """Returns (score 0-100, list of matched CVE rows, status)."""
    if not is_identifiable(component):
        return UNVERIFIED_PENALTY, [], "UNVERIFIED"

    matches = []
    for cve in cve_data:
        if (component["vendor"].lower() == cve["vendor"].lower()
                and component["model"].lower() == cve["product"].lower()
                and in_affected_range(component["version"], cve["version_affected"])):
            matches.append(cve)

    if not matches:
        return 0.0, [], "VERIFIED"

    def cvss(row):
        try:
            return float(row["cvss_score"])
        except ValueError:
            return 0.0

    matches.sort(key=lambda r: (-cvss(r), r["cve_id"]))
    return cvss(matches[0]) * 10.0, matches, "VULNERABLE"


# ---------------------------------------------------------------------------
# Dimension 2 - origin and vendor policy
# ---------------------------------------------------------------------------
def apply_policy(component, policy):
    """Returns (score 0-100, list of reasons, blocking flag)."""
    reasons, score, blocking = [], 0.0, False

    rule = policy["vendors"].get(component["vendor"].lower())
    if rule:
        tier = rule["risk_tier"].lower()
        score = max(score, POLICY_SCORES.get(tier, 50.0))
        reasons.append(f"Vendor '{component['vendor']}' is {tier}: {rule['justification']}")
        if rule["action"].lower() == "block":
            blocking = True

    country = component["country_of_origin"].lower()
    crule = policy["countries"].get(country)
    if crule:
        tier_score = COUNTRY_TIER_SCORES.get(crule["risk_tier"], 40.0)
        if tier_score > 10.0:
            reasons.append(f"Origin {component['country_of_origin']} is tier "
                           f"{crule['risk_tier']}: {crule['justification']}")
        score = max(score, tier_score)
    else:
        score = max(score, COUNTRY_TIER_SCORES["3"])
        reasons.append(f"Origin '{component['country_of_origin']}' is not covered by the policy file")

    return score, reasons, blocking


# ---------------------------------------------------------------------------
# Dimension 3 - component factors
# ---------------------------------------------------------------------------
def find_single_source_categories(bom):
    vendors = defaultdict(set)
    for component in bom:
        vendors[component["category"]].add(component["vendor"])
    return {cat for cat, vs in vendors.items() if len(vs) == 1}


def component_factors(component, single_source_categories):
    reasons, score = [], 0.0
    eol = component["end_of_life"].lower()
    score += EOL_SCORES.get(eol, EOL_SCORES["unknown"])
    if eol == "yes":
        reasons.append("End of life - will receive no further security updates")
    elif eol not in ("no",):
        reasons.append("Lifecycle status not declared")

    if component["category"] in single_source_categories:
        score += SINGLE_SOURCE_SCORE
        reasons.append(f"Single-source dependency - '{component['category']}' is supplied "
                       f"only by {component['vendor']}")
    return min(100.0, score), reasons


# ---------------------------------------------------------------------------
# Combining
# ---------------------------------------------------------------------------
def band_for(score):
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"


def suggest_mitigation(component, cve_matches, policy_blocking, factor_reasons, bom):
    if cve_matches:
        cwe = cve_matches[0]["cwe"].strip()
        text = CWE_MITIGATIONS.get(cwe, DEFAULT_MITIGATION)
        if cve_matches[0]["fix_available"].lower().startswith("y"):
            text += " A fixed version is published by the vendor."
        return text
    if policy_blocking:
        alternatives = sorted({
            c["vendor"] for c in bom
            if c["category"] == component["category"] and c["vendor"] != component["vendor"]
        })
        if alternatives:
            return ("Vendor is blocked by policy. Substitute an approved supplier already in this "
                    "BOM for the same category: " + ", ".join(alternatives) + ".")
        return "Vendor is blocked by policy and no alternative supplier appears in this BOM. Re-tender this line item."
    if not is_identifiable(component):
        return ("Obtain the vendor, model and version from the supplier before purchase. "
                "Provenance that cannot be established cannot be assessed.")
    if factor_reasons:
        return ("Plan replacement before end of support, and qualify a second supplier "
                "to remove the single-source dependency.")
    return "No action required. Re-assess if the component version changes."


def score_component(component, cve_data, policy, bom, single_source_categories):
    vuln_score, cve_matches, status = match_cves(component, cve_data)
    policy_score, policy_reasons, blocking = apply_policy(component, policy)
    factor_score, factor_reasons = component_factors(component, single_source_categories)

    base = (W_VULNERABILITY * vuln_score
            + W_POLICY * policy_score
            + W_COMPONENT * factor_score)
    multiplier = CRITICALITY.get(component["category"], DEFAULT_CRITICALITY)
    final = min(100.0, base * multiplier)

    return {
        "component": component,
        "vuln_score": vuln_score,
        "policy_score": policy_score,
        "factor_score": factor_score,
        "base": base,
        "multiplier": multiplier,
        "score": final,
        "band": band_for(final),
        "status": status,
        "cves": cve_matches,
        "reasons": policy_reasons + factor_reasons,
        "blocking": blocking,
        "mitigation": suggest_mitigation(component, cve_matches, blocking, factor_reasons, bom),
    }


def concentration_risk(bom):
    """A BOM can be low risk component by component and fragile as a portfolio."""
    findings, penalty = [], 0.0
    total = len(bom)

    # Always report the origin spread, so the analysis is visible even when it
    # does not breach the threshold. Only breaches carry a penalty.
    countries = Counter(c["country_of_origin"] for c in bom)
    for country, count in countries.most_common(1):
        share = count / total
        if share > CONCENTRATION_THRESHOLD:
            points = min(CONCENTRATION_MAX, (share - CONCENTRATION_THRESHOLD) * 50.0)
            penalty += points
            findings.append(f"BREACH: {count} of {total} components ({share:.0%}) originate in "
                            f"{country} - above the {CONCENTRATION_THRESHOLD:.0%} threshold")
        else:
            findings.append(f"Largest single origin is {country} at {count} of {total} "
                            f"({share:.0%}) - within the {CONCENTRATION_THRESHOLD:.0%} threshold")

    undeclared = sum(1 for c in bom if c["country_of_origin"].lower() in UNKNOWN_VALUES)
    if undeclared:
        findings.append(f"{undeclared} of {total} components ({undeclared/total:.0%}) do not "
                        f"declare a country of origin, so true concentration may be higher")

    vendors = defaultdict(set)
    for component in bom:
        vendors[component["category"]].add(component["vendor"])
    for category in sorted(CRITICAL_CATEGORIES & set(vendors)):
        if len(vendors[category]) == 1:
            penalty += 5.0
            sole_vendor = next(iter(vendors[category]))
            findings.append(f"All '{category}' components come from a single vendor "
                            f"({sole_vendor}) - no second source")

    return min(CONCENTRATION_MAX, penalty), findings


def score_bom(scored, bom):
    total = len(scored)
    weighted_sum = sum(r["score"] * r["multiplier"] for r in scored)
    weight_total = sum(r["multiplier"] for r in scored) or 1.0
    mean = weighted_sum / weight_total

    penalty, concentration_findings = concentration_risk(bom)
    overall = min(100.0, mean + penalty)

    unverified = [r for r in scored if r["status"] == "UNVERIFIED"]
    coverage = (total - len(unverified)) / total if total else 0.0

    blocked = [r for r in scored if r["blocking"]]
    criticals = [r for r in scored if r["band"] == "CRITICAL"]

    if blocked:
        verdict = "REJECT"
        rationale = (f"{len(blocked)} component(s) come from a vendor blocked by procurement policy. "
                     "A restricted supplier is a compliance decision, not a risk trade-off.")
    elif criticals or coverage < 0.90:
        verdict = "APPROVE WITH CONDITIONS"
        parts = []
        if criticals:
            parts.append(f"{len(criticals)} component(s) score CRITICAL and must be remediated before deployment")
        if coverage < 0.90:
            parts.append(f"provenance could not be established for {len(unverified)} component(s)")
        rationale = "; ".join(parts).capitalize() + "."
    else:
        verdict = "APPROVE"
        rationale = "No blocking policy findings, no critical components, and provenance is established for at least 90% of the BOM."

    return {
        "total": total,
        "overall": overall,
        "mean": mean,
        "penalty": penalty,
        "concentration": concentration_findings,
        "coverage": coverage,
        "unverified": unverified,
        "blocked": blocked,
        "criticals": criticals,
        "verdict": verdict,
        "rationale": rationale,
        "band_counts": Counter(r["band"] for r in scored),
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
CSS = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1c2733}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 64px}
h1{margin:0 0 4px;font-size:26px}
h2{margin:36px 0 12px;font-size:18px;border-bottom:2px solid #d7dee5;padding-bottom:6px}
.sub{color:#5b6b7a;margin:0 0 24px}
.verdict{padding:18px 22px;border-radius:8px;color:#fff;margin:0 0 24px}
.REJECT{background:#8e1b1b}.APPROVEWITHCONDITIONS{background:#9a6212}.APPROVE{background:#1d6b3a}
.verdict b{font-size:20px;display:block;margin-bottom:6px}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:8px}
.card{background:#fff;border:1px solid #dde3e9;border-radius:8px;padding:14px 18px;min-width:150px;flex:1}
.card .n{font-size:24px;font-weight:700}
.card .l{color:#5b6b7a;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;background:#fff;font-size:14px}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid #e6ebef;vertical-align:top}
th{background:#eef2f5;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:#44535f}
.badge{display:inline-block;padding:2px 8px;border-radius:11px;font-size:11px;font-weight:700;color:#fff}
.b-CRITICAL{background:#8e1b1b}.b-HIGH{background:#c05621}.b-MEDIUM{background:#9a7d12}.b-LOW{background:#4a5a68}
.mono{font-family:Consolas,monospace;font-size:12px;color:#44535f}
.mit{color:#25506e;font-size:13px}
.note{background:#fff;border-left:4px solid #9a6212;padding:12px 16px;margin:12px 0;font-size:14px}
footer{margin-top:44px;color:#6b7986;font-size:12px;border-top:1px solid #d7dee5;padding-top:14px}
"""


def _e(text):
    return html.escape(str(text))


def write_report(scored, summary, out_path, sources):
    ranked = sorted(scored, key=lambda r: (-r["score"], -r["base"], r["component"]["component_id"]))
    findings = [r for r in ranked if r["score"] > 0]
    unverified = sorted(summary["unverified"], key=lambda r: r["component"]["component_id"])

    p = []
    p.append(f"<style>{CSS}</style><div class='wrap'>")
    p.append("<h1>Supply Chain Risk Assessment</h1>")
    p.append(f"<p class='sub'>Bill of materials: <span class='mono'>{_e(sources['bom'])}</span> "
             f"&middot; {summary['total']} components assessed</p>")

    cls = summary["verdict"].replace(" ", "")
    p.append(f"<div class='verdict {cls}'><b>{_e(summary['verdict'])}</b>{_e(summary['rationale'])}</div>")

    p.append("<div class='cards'>")
    for label, value in [
        ("Overall BOM risk", f"{summary['overall']:.1f}/100"),
        ("Coverage", f"{summary['coverage']:.0%}"),
        ("Critical", summary["band_counts"].get("CRITICAL", 0)),
        ("High", summary["band_counts"].get("HIGH", 0)),
        ("Unverifiable", len(summary["unverified"])),
    ]:
        p.append(f"<div class='card'><div class='n'>{_e(value)}</div><div class='l'>{_e(label)}</div></div>")
    p.append("</div>")

    if summary["concentration"]:
        p.append("<h2>Concentration risk</h2>")
        p.append(f"<p class='sub'>Portfolio-level exposure. Adds {summary['penalty']:.1f} points "
                 f"to the overall score of {summary['mean']:.1f}.</p>")
        for finding in summary["concentration"]:
            p.append(f"<div class='note'>{_e(finding)}</div>")

    p.append("<h2>Findings, highest risk first</h2>")
    p.append("<table><tr><th>Score</th><th>Component</th><th>Why</th>"
             "<th>Breakdown</th><th>Mitigation or alternative</th></tr>")
    for r in findings:
        c = r["component"]
        why = []
        for cve in r["cves"]:
            why.append(f"<b>{_e(cve['cve_id'])}</b> &middot; CVSS {_e(cve['cvss_score'])} "
                       f"{_e(cve['severity'])} ({_e(cve['score_source'])}) &middot; {_e(cve['cwe'])}<br>"
                       f"{_e(cve['description'])}")
        why.extend(_e(x) for x in r["reasons"])
        if r["status"] == "UNVERIFIED":
            why.insert(0, "<b>Cannot be identified</b> - vendor, model or version not declared")
        p.append(
            f"<tr><td><span class='badge b-{r['band']}'>{r['score']:.1f}</span><br>"
            f"<span class='mono'>{_e(r['band'])}</span></td>"
            f"<td><b>{_e(c['component_id'])}</b> {_e(c['component_name'])}<br>"
            f"<span class='mono'>{_e(c['vendor'])} {_e(c['model'])} {_e(c['version'])}<br>"
            f"{_e(c['category'])} &middot; {_e(c['country_of_origin'])} &middot; qty {_e(c['quantity'])}</span></td>"
            f"<td>{'<br>'.join(why) if why else '-'}</td>"
            f"<td class='mono'>vuln {r['vuln_score']:.0f}&times;{W_VULNERABILITY}<br>"
            f"policy {r['policy_score']:.0f}&times;{W_POLICY}<br>"
            f"factors {r['factor_score']:.0f}&times;{W_COMPONENT}<br>"
            f"= {r['base']:.1f} &times; {r['multiplier']} ({_e(c['category'])})</td>"
            f"<td class='mit'>{_e(r['mitigation'])}</td></tr>")
    p.append("</table>")

    p.append("<h2>Components that could not be verified</h2>")
    p.append("<p class='sub'>These are <b>not</b> scored as safe. An absence of known vulnerabilities "
             "for a component we cannot identify is an absence of evidence, not evidence of absence. "
             f"Each carries a defined uncertainty penalty of {UNVERIFIED_PENALTY:.0f}/100 "
             "on the vulnerability dimension.</p>")
    if unverified:
        p.append("<table><tr><th>ID</th><th>Component</th><th>Vendor</th><th>Version</th><th>Origin</th></tr>")
        for r in unverified:
            c = r["component"]
            p.append(f"<tr><td class='mono'>{_e(c['component_id'])}</td><td>{_e(c['component_name'])}</td>"
                     f"<td>{_e(c['vendor'])}</td><td class='mono'>{_e(c['version'])}</td>"
                     f"<td>{_e(c['country_of_origin'])}</td></tr>")
        p.append("</table>")
    else:
        p.append("<p>All components were identifiable.</p>")

    p.append("<h2>Method</h2><table>"
             "<tr><th>Dimension</th><th>Weight</th><th>Source</th></tr>"
             f"<tr><td>Known vulnerabilities</td><td>{W_VULNERABILITY}</td>"
             f"<td class='mono'>{_e(sources['cves'])} &middot; NVD CVSS 3.1 base scores</td></tr>"
             f"<tr><td>Origin and vendor policy</td><td>{W_POLICY}</td>"
             f"<td class='mono'>{_e(sources['policy'])} &middot; organisation-supplied</td></tr>"
             f"<tr><td>Component factors</td><td>{W_COMPONENT}</td>"
             "<td>End-of-life status and single-source dependency</td></tr></table>")
    p.append("<p class='sub' style='margin-top:12px'>Scores are a prioritisation index on a 0-100 scale, "
             "not a probability of compromise. Category criticality multipliers range from 0.8 to 1.5.</p>")

    p.append(f"<footer>Team Shadow Djinn &middot; School of Cyber Defense 2026 &middot; "
             f"generated {datetime.now():%Y-%m-%d %H:%M}</footer></div>")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(p))


# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Score an AI server bill of materials for supply-chain risk.")
    parser.add_argument("--bom", default=DEFAULT_BOM)
    parser.add_argument("--cves", default=DEFAULT_CVES)
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args()

    try:
        bom, notes = load_bom(args.bom)
        cve_data = load_cve_dataset(args.cves)
        policy = load_policy(args.policy)
    except DataError as exc:
        print(f"\nCannot run: {exc}\n", file=sys.stderr)
        return 1

    for message in notes:
        print(f"  warning: {message}")

    single_source = find_single_source_categories(bom)
    scored = [score_component(c, cve_data, policy, bom, single_source) for c in bom]
    summary = score_bom(scored, bom)
    write_report(scored, summary, args.out,
                 {"bom": args.bom, "cves": args.cves, "policy": args.policy})

    print(f"\n  Components assessed : {summary['total']}")
    print(f"  Overall BOM risk    : {summary['overall']:.1f}/100")
    print(f"  Coverage            : {summary['coverage']:.0%} "
          f"({len(summary['unverified'])} could not be verified)")
    print(f"  Verdict             : {summary['verdict']}")
    print(f"  {summary['rationale']}\n")
    for r in sorted(scored, key=lambda r: -r["score"])[:5]:
        cves = ", ".join(c["cve_id"] for c in r["cves"]) or "-"
        print(f"    {r['score']:5.1f}  {r['band']:<8} {r['component']['component_id']}  "
              f"{r['component']['vendor']} {r['component']['model']}  {cves}")
    print(f"\n  Report written to {args.out}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
