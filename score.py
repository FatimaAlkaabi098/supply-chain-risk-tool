"""
BOMShield - AI Server Supply-Chain Risk Assessment
School of Cyber Defense 2026 - Team Shadow Djinn

Scores an AI server Bill of Materials for supply-chain risk before purchase.

Usage:
    python score.py
    python score.py --bom data/demo_bom.csv

Outputs:
    reports/dashboard.html   interactive dashboard (open this one)
    reports/report.html      static findings report
    reports/data.json        the scored data, for reuse

FIVE RISK DIMENSIONS (adaptive risk scoring):
    1. Vulnerability  - published CVEs, weighted by CVSS severity and EPSS likelihood
    2. Vendor/Policy  - restricted and under-review suppliers
    3. Lifecycle      - end-of-life and support horizon
    4. Geopolitical   - country-of-origin tier and undeclared provenance
    5. Operational    - single-source dependency, validated alternatives, lead time

HYBRID SCORING: every score is reported three ways - a qualitative band
(LOW/MEDIUM/HIGH/CRITICAL), a 0-100 index, and a normalised 0.0-1.0 value.

Components whose identity cannot be established are NOT SCORED, never scored
as zero. They are reported separately and reduce data confidence.

Every weight and threshold is justified in DECISIONS.md.
"""

import argparse
import csv
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Scoring configuration - justified in DECISIONS.md
# ---------------------------------------------------------------------------
DIMENSIONS = ["vulnerability", "policy", "lifecycle", "geopolitical", "operational"]
DIMENSION_LABELS = {
    "vulnerability": "Vulnerability",
    "policy":        "Vendor / Policy",
    "lifecycle":     "Lifecycle",
    "geopolitical":  "Geopolitical",
    "operational":   "Operational",
}
WEIGHTS = {
    "vulnerability": 0.30,
    "policy":        0.20,
    "lifecycle":     0.15,
    "geopolitical":  0.20,
    "operational":   0.15,
}

# A management controller failure is worse than a fan failure.
CRITICALITY = {
    "bmc": 1.5, "firmware": 1.5, "cpu": 1.3, "gpu": 1.2, "nic": 1.2,
    "storage": 1.0, "memory": 1.0, "psu": 0.8, "cooling": 0.8, "other": 0.9,
}
DEFAULT_CRITICALITY = 1.0

# Vulnerability: severity x likelihood.
# CVSS states how bad it would be; EPSS states how likely exploitation is.
# Severity alone over-ranks vulnerabilities nobody is exploiting, so the EPSS
# percentile modulates the score by up to 30%. A CISA KEV listing means
# exploitation is not a prediction but an observed fact, so it overrides both.
EPSS_MODULATION = 0.30
KEV_FLOOR = 90.0

POLICY_SCORES = {"restricted": 100.0, "review": 60.0}
COUNTRY_TIER_SCORES = {"1": 10.0, "2": 40.0, "3": 70.0}
UNDECLARED_ORIGIN_SCORE = 70.0

EOL_SCORES = {"yes": 80.0, "unknown": 40.0, "no": 0.0}

NO_ALTERNATIVE_SCORE = 50.0
UNKNOWN_ALTERNATIVE_SCORE = 30.0
SINGLE_SOURCE_SCORE = 30.0
LEAD_TIME_LONG_WEEKS = 16
LEAD_TIME_VERY_LONG_WEEKS = 26
LEAD_TIME_LONG_SCORE = 20.0
LEAD_TIME_VERY_LONG_SCORE = 30.0

# A weighted mean dilutes a single severe finding: a component with a critical
# remotely-exploitable vulnerability would be averaged down by four clean
# dimensions. Vulnerability and Policy describe conditions that are true NOW -
# an exploitable flaw, or a supplier the organisation may not buy from - so
# either can set a floor under the component's score on its own. Lifecycle,
# Geopolitical and Operational describe exposure and resilience: real, but not
# by themselves disqualifying, so they contribute only through the mean.
DOMINANT_DIMENSIONS = ("vulnerability", "policy")
DOMINANCE = 0.85

# The same argument at BOM level. A bill of materials is not acceptable because
# most of it is fine - procurement rejects on the worst line item.
WORST_COMPONENT_FLOOR = 0.70

CONCENTRATION_THRESHOLD = 0.40
CONCENTRATION_MAX = 15.0
CRITICAL_CATEGORIES = {"bmc", "firmware", "cpu", "gpu"}

BANDS = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]
COVERAGE_TARGET = 0.90

REQUIRED_BOM_COLUMNS = [
    "component_id", "component_name", "category", "vendor", "model", "version",
    "country_of_origin", "quantity", "end_of_life",
    "lead_time_weeks", "validated_alternative",
]
REQUIRED_CVE_COLUMNS = [
    "vendor", "product", "version_affected", "cve_id", "cvss_score",
    "score_source", "severity", "cwe", "description", "fix_available",
    "kev", "epss", "epss_percentile",
]
REQUIRED_POLICY_COLUMNS = ["rule_type", "key", "risk_tier", "action", "justification"]

UNKNOWN_VALUES = {"unknown", "", "n/a", "none", "-", "tbd"}

CWE_MITIGATIONS = {
    "CWE-290": "Do not trust client-supplied headers for authentication; verify identity server-side. Apply the fixed firmware version.",
    "CWE-306": "Require authentication on every privileged function. Apply the fixed firmware version.",
    "CWE-330": "Use a cryptographically secure random source for session identifiers. Apply the fixed firmware version.",
    "CWE-119": "Apply the vendor firmware update and restrict the management interface to a dedicated out-of-band network.",
    "CWE-120": "Apply the vendor firmware update and restrict the management interface to a dedicated out-of-band network.",
    "CWE-125": "Apply the vendor firmware update. Restrict who can reach the management interface until it is applied.",
    "CWE-787": "Apply the vendor firmware update. Disable network boot where it is not required.",
    "CWE-284": "Enforce authorisation on every request rather than on entry. Apply the fixed firmware version.",
    "CWE-522": "Credential material must never be retrievable through a management interface. Apply the fixed version and rotate any exposed credentials.",
    "CWE-20":  "Validate input against an allowlist at the trust boundary. Apply the vendor firmware update.",
    "CWE-501": "Enforce the trust boundary in the bootloader lockdown policy. Apply the vendor update.",
    "CWE-1258": "Apply the vendor firmware update and confirm debug interfaces are disabled in production builds.",
}
DEFAULT_MITIGATION = ("Apply the vendor's fixed version. If no fix exists, isolate the component "
                      "on a segregated management network and evaluate an alternative supplier.")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BOM    = os.path.join(HERE, "data", "demo_bom.csv")
DEFAULT_CVES   = os.path.join(HERE, "data", "cve_dataset.csv")
DEFAULT_POLICY = os.path.join(HERE, "data", "policy.csv")
DEFAULT_OUTDIR = os.path.join(HERE, "reports")


def r1(value):
    """Round to one decimal, half away from zero.

    Python's built-in round() uses banker's rounding (14.25 -> 14.2) while
    JavaScript's Math.round rounds half up (14.25 -> 14.3). The dashboard
    re-scores in the browser, so the two must agree exactly or the model
    self-check fails. It did fail, on exactly this: component C027 scored
    14.25 and the two runtimes disagreed. Both now round half away from zero.
    """
    return math.floor(value * 10 + 0.5) / 10 if value >= 0 else -(math.floor(-value * 10 + 0.5) / 10)


class DataError(Exception):
    """Raised when an input file cannot be used. Always explains why."""


# ---------------------------------------------------------------------------
# Loading - every loader fails with an explanation, never a stack trace
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
                    continue
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
    if value is None:
        return None
    text = value.strip().lower()
    if text in UNKNOWN_VALUES:
        return None
    numbers = []
    for part in re.split(r"[.\-_]", text):
        if part.isdigit():
            numbers.append(int(part))
        else:
            digits = re.match(r"^(\d+)", part)
            if not digits:
                return None
            numbers.append(int(digits.group(1)))
    return tuple(numbers) or None


def compare_versions(a, b):
    ta, tb = _version_tuple(a), _version_tuple(b)
    if ta is None or tb is None:
        return None
    width = max(len(ta), len(tb))
    ta += (0,) * (width - len(ta))
    tb += (0,) * (width - len(tb))
    return (ta > tb) - (ta < tb)


def in_affected_range(version, range_string):
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


def first_fixed_version(range_string):
    """Lowest version NOT covered by an affected range, where determinable."""
    if not range_string:
        return None
    tokens = range_string.split()
    for token in tokens:
        m = re.match(r"^<(?!=)(.+)$", token)
        if m:
            return m.group(1)
    for token in tokens:
        m = re.match(r"^<=(.+)$", token)
        if m:
            parts = m.group(1).split(".")
            try:
                parts[-1] = str(int(parts[-1]) + 1)
            except ValueError:
                return None
            return ".".join(parts)
    return None


def _number(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
def is_identifiable(component):
    return not (component["vendor"].lower() in UNKNOWN_VALUES
                or component["model"].lower() in UNKNOWN_VALUES
                or component["version"].lower() in UNKNOWN_VALUES)


def band_for(score):
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"


# ---------------------------------------------------------------------------
# The five dimensions
# ---------------------------------------------------------------------------
def dim_vulnerability(component, cve_data):
    """Severity x likelihood. Returns (score, matched CVEs, reasons)."""
    matches = []
    for cve in cve_data:
        if (component["vendor"].lower() == cve["vendor"].lower()
                and component["model"].lower() == cve["product"].lower()
                and in_affected_range(component["version"], cve["version_affected"])):
            matches.append(cve)
    if not matches:
        return 0.0, [], []

    matches.sort(key=lambda r: (-(_number(r["cvss_score"], 0.0)), r["cve_id"]))
    worst = matches[0]
    cvss = _number(worst["cvss_score"], 0.0)
    base = cvss * 10.0

    percentile = _number(worst.get("epss_percentile"), None)
    if percentile is None:
        score = base
        reason = f"CVSS {cvss} with no EPSS data - severity used unmodulated"
    else:
        factor = (1.0 - EPSS_MODULATION) + EPSS_MODULATION * percentile
        score = base * factor
        reason = (f"CVSS {cvss} modulated by EPSS percentile {percentile:.2f} "
                  f"(exploitation likelihood)")

    reasons = [reason]
    if any(c.get("kev", "").lower().startswith("y") for c in matches):
        score = max(score, KEV_FLOOR)
        reasons.append("Listed in the CISA Known Exploited Vulnerabilities catalogue - "
                       "exploitation is observed, not predicted")
    return min(100.0, score), matches, reasons


def dim_policy(component, policy):
    """Restricted or under-review suppliers. Returns (score, reasons, blocking)."""
    rule = policy["vendors"].get(component["vendor"].lower())
    if not rule:
        return 0.0, [], False
    tier = rule["risk_tier"].lower()
    score = POLICY_SCORES.get(tier, 50.0)
    blocking = rule["action"].lower() == "block"
    return score, [f"Vendor '{component['vendor']}' is {tier}: {rule['justification']}"], blocking


def dim_lifecycle(component):
    eol = component["end_of_life"].lower()
    score = EOL_SCORES.get(eol, EOL_SCORES["unknown"])
    if eol == "yes":
        return score, ["End of life - will receive no further security updates"]
    if eol not in ("no",):
        return score, ["Lifecycle status not declared by the supplier"]
    return score, []


def dim_geopolitical(component, policy):
    country = component["country_of_origin"]
    if country.lower() in UNKNOWN_VALUES:
        return UNDECLARED_ORIGIN_SCORE, ["Country of origin not declared - provenance cannot be verified"]
    rule = policy["countries"].get(country.lower())
    if not rule:
        return COUNTRY_TIER_SCORES["3"], [f"Origin '{country}' is not covered by the policy file"]
    score = COUNTRY_TIER_SCORES.get(rule["risk_tier"], 40.0)
    reasons = [] if score <= 10.0 else [f"Origin {country} is tier {rule['risk_tier']}: {rule['justification']}"]
    return score, reasons


def dim_operational(component, single_source_categories):
    score, reasons = 0.0, []
    alternative = component["validated_alternative"].lower()
    if alternative == "no":
        score += NO_ALTERNATIVE_SCORE
        reasons.append("No validated alternative supplier has been qualified")
    elif alternative in UNKNOWN_VALUES:
        score += UNKNOWN_ALTERNATIVE_SCORE
        reasons.append("Whether an alternative supplier exists has not been established")

    if component["category"] in single_source_categories:
        score += SINGLE_SOURCE_SCORE
        reasons.append(f"Single-source dependency - '{component['category']}' is supplied "
                       f"only by {component['vendor']}")

    weeks = _number(component["lead_time_weeks"], None)
    if weeks is not None:
        if weeks >= LEAD_TIME_VERY_LONG_WEEKS:
            score += LEAD_TIME_VERY_LONG_SCORE
            reasons.append(f"Very long lead time - {int(weeks)} weeks")
        elif weeks >= LEAD_TIME_LONG_WEEKS:
            score += LEAD_TIME_LONG_SCORE
            reasons.append(f"Long lead time - {int(weeks)} weeks")
    return min(100.0, score), reasons


# ---------------------------------------------------------------------------
# Combining
# ---------------------------------------------------------------------------
def find_single_source_categories(bom):
    vendors = defaultdict(set)
    for component in bom:
        vendors[component["category"]].add(component["vendor"])
    return {cat for cat, vs in vendors.items() if len(vs) == 1}


def suggest_mitigation(component, cves, blocking, bom, dim_reasons):
    if cves:
        text = CWE_MITIGATIONS.get(cves[0]["cwe"].strip(), DEFAULT_MITIGATION)
        if cves[0]["fix_available"].lower().startswith("y"):
            fixed = first_fixed_version(cves[0]["version_affected"])
            if fixed:
                text += f" Upgrade to {fixed} or later."
        return text
    if blocking:
        alternatives = sorted({c["vendor"] for c in bom
                               if c["category"] == component["category"]
                               and c["vendor"] != component["vendor"]})
        if alternatives:
            return ("Vendor is blocked by policy. Substitute an approved supplier already in "
                    "this BOM for the same category: " + ", ".join(alternatives) + ".")
        return "Vendor is blocked by policy and no alternative appears in this BOM. Re-tender this line item."
    if not is_identifiable(component):
        return ("Obtain vendor, model and version from the supplier before purchase. "
                "Provenance that cannot be established cannot be assessed.")
    if dim_reasons["operational"]:
        return "Qualify and validate a second supplier to remove the single-source dependency."
    if dim_reasons["lifecycle"]:
        return "Plan replacement before end of support and confirm the successor part now."
    return "No action required. Re-assess if the component version changes."


def score_component(component, cve_data, policy, bom, single_source_categories):
    identifiable = is_identifiable(component)
    scores, reasons = {}, {}

    if identifiable:
        scores["vulnerability"], cves, reasons["vulnerability"] = dim_vulnerability(component, cve_data)
    else:
        scores["vulnerability"], cves, reasons["vulnerability"] = 0.0, [], []

    scores["policy"], reasons["policy"], blocking = dim_policy(component, policy)
    scores["lifecycle"], reasons["lifecycle"] = dim_lifecycle(component)
    scores["geopolitical"], reasons["geopolitical"] = dim_geopolitical(component, policy)
    scores["operational"], reasons["operational"] = dim_operational(component, single_source_categories)

    multiplier = CRITICALITY.get(component["category"], DEFAULT_CRITICALITY)
    base = sum(WEIGHTS[d] * scores[d] for d in DIMENSIONS)
    weighted = base * multiplier
    floor = max((scores[d] * DOMINANCE for d in DOMINANT_DIMENSIONS), default=0.0)
    final = min(100.0, max(weighted, floor))
    driver = "weighted profile" if weighted >= floor else (
        max(DOMINANT_DIMENSIONS, key=lambda d: scores[d]))

    result = {
        "component": component,
        "identifiable": identifiable,
        "status": "SCORED" if identifiable else "NOT SCORED",
        "dimensions": {d: r1(scores[d]) for d in DIMENSIONS},
        "dimension_reasons": {d: reasons[d] for d in DIMENSIONS},
        "base": r1(base),
        "weighted": r1(weighted),
        "floor": r1(floor),
        "driver": driver,
        "multiplier": multiplier,
        "cves": cves,
        "blocking": blocking,
        "mitigation": suggest_mitigation(component, cves, blocking, bom, reasons),
    }
    if identifiable:
        result.update({"score": r1(final),
                       "normalised": round(r1(final) / 100.0, 3),
                       "band": band_for(final)})
    else:
        # Not scored, never zero. An unidentifiable component has not been cleared.
        result.update({"score": None, "normalised": None, "band": "UNKNOWN"})
    return result


def concentration_analysis(bom):
    findings, penalty, total = [], 0.0, len(bom)
    countries = Counter(c["country_of_origin"] for c in bom)
    top_country, top_count = countries.most_common(1)[0]
    share = top_count / total
    if share > CONCENTRATION_THRESHOLD:
        penalty += min(CONCENTRATION_MAX, (share - CONCENTRATION_THRESHOLD) * 50.0)
        findings.append(f"BREACH: {top_count} of {total} components ({share:.0%}) originate in "
                        f"{top_country} - above the {CONCENTRATION_THRESHOLD:.0%} threshold")
    else:
        findings.append(f"Largest single origin is {top_country} at {top_count} of {total} "
                        f"({share:.0%}) - within the {CONCENTRATION_THRESHOLD:.0%} threshold")

    undeclared = sum(1 for c in bom if c["country_of_origin"].lower() in UNKNOWN_VALUES)
    if undeclared:
        findings.append(f"{undeclared} of {total} components ({undeclared/total:.0%}) do not declare "
                        f"an origin, so true concentration may be higher")

    vendors = defaultdict(set)
    for c in bom:
        vendors[c["category"]].add(c["vendor"])
    for category in sorted(CRITICAL_CATEGORIES & set(vendors)):
        if len(vendors[category]) == 1:
            penalty += 5.0
            findings.append(f"All '{category}' components come from a single vendor "
                            f"({next(iter(vendors[category]))}) - no second source")
    return min(CONCENTRATION_MAX, penalty), findings, countries


def score_bom(scored, bom):
    total = len(scored)
    unknown = [r for r in scored if not r["identifiable"]]
    rated = [r for r in scored if r["identifiable"]]

    weighted = sum(r["score"] * r["multiplier"] for r in rated)
    weights = sum(r["multiplier"] for r in rated) or 1.0
    mean = weighted / weights

    penalty, concentration, countries = concentration_analysis(bom)
    worst = max((r["score"] for r in rated), default=0.0)
    portfolio = mean + penalty
    overall = min(100.0, max(portfolio, worst * WORST_COMPONENT_FLOOR))
    coverage = len(rated) / total if total else 0.0

    blocked = [r for r in rated if r["blocking"]]
    criticals = [r for r in rated if r["band"] == "CRITICAL"]
    highs = [r for r in rated if r["band"] == "HIGH"]

    if blocked:
        verdict, banner = "REJECT", "PROCUREMENT REVIEW REQUIRED"
        rationale = (f"{len(blocked)} component(s) come from a vendor blocked by procurement policy. "
                     "A restricted supplier is a compliance decision, not a risk trade-off.")
    elif criticals or coverage < COVERAGE_TARGET:
        verdict, banner = "APPROVE WITH CONDITIONS", "ACCEPTABLE WITH MITIGATIONS"
        parts = []
        if criticals:
            parts.append(f"{len(criticals)} component(s) score CRITICAL and must be remediated before deployment")
        if coverage < COVERAGE_TARGET:
            parts.append(f"provenance could not be established for {len(unknown)} component(s)")
        rationale = "; ".join(parts).capitalize() + "."
    else:
        verdict, banner = "APPROVE", "ACCEPTABLE"
        rationale = ("No blocking policy findings, no critical components, and provenance "
                     f"established for at least {COVERAGE_TARGET:.0%} of the BOM.")

    dimension_means = {}
    for d in DIMENSIONS:
        values = [r["dimensions"][d] for r in rated]
        dimension_means[d] = r1(sum(values) / len(values)) if values else 0.0

    return {
        "total": total, "rated": len(rated), "unknown": unknown,
        "overall": r1(overall), "normalised": round(r1(overall) / 100.0, 3),
        "band": band_for(overall), "mean": r1(mean), "penalty": r1(penalty),
        "portfolio": r1(portfolio), "worst": r1(worst),
        "overall_driver": "worst component" if worst * WORST_COMPONENT_FLOOR > portfolio else "portfolio profile",
        "concentration": concentration, "countries": countries,
        "coverage": coverage, "blocked": blocked, "criticals": criticals, "highs": highs,
        "verdict": verdict, "banner": banner, "rationale": rationale,
        "band_counts": Counter(r["band"] for r in scored),
        "dimension_means": dimension_means,
    }


def score_all(bom, cve_data, policy):
    single_source = find_single_source_categories(bom)
    scored = [score_component(c, cve_data, policy, bom, single_source) for c in bom]
    return scored, score_bom(scored, bom)


# ---------------------------------------------------------------------------
# Remediation simulator
# ---------------------------------------------------------------------------
EFFORT_ORDER = {"low": 0, "medium": 1, "high": 2}


def verdict_distance(summary):
    """Lexicographic distance to APPROVE: blockers, then criticals, then coverage."""
    return (len(summary["blocked"]), len(summary["criticals"]),
            round(max(0.0, COVERAGE_TARGET - summary["coverage"]), 4))


def build_remediation_actions(scored, bom, policy):
    actions = []
    for result in scored:
        component = result["component"]
        cid = component["component_id"]

        targets = [first_fixed_version(c["version_affected"]) for c in result["cves"]
                   if c["fix_available"].lower().startswith("y")]
        targets = [t for t in targets if t]
        if targets:
            highest = targets[0]
            for candidate in targets[1:]:
                if (compare_versions(candidate, highest) or 0) > 0:
                    highest = candidate
            actions.append({
                "type": "PATCH", "component_id": cid, "effort": "low",
                "label": f"Update {component['vendor']} {component['model']} to {highest}",
                "detail": "Resolves " + ", ".join(c["cve_id"] for c in result["cves"]),
                "change": {"version": highest}})

        if result["blocking"]:
            alts = [c for c in bom if c["category"] == component["category"]
                    and c["vendor"] != component["vendor"]
                    and c["vendor"].lower() not in policy["vendors"]]
            if alts:
                pick = sorted(alts, key=lambda c: c["vendor"])[0]
                actions.append({
                    "type": "REPLACE", "component_id": cid, "effort": "high",
                    "label": f"Re-source {component['component_name']} from {pick['vendor']}",
                    "detail": f"{component['vendor']} is blocked by procurement policy",
                    "change": {"vendor": pick["vendor"], "model": pick["model"],
                               "version": pick["version"],
                               "country_of_origin": pick["country_of_origin"]}})

        if component["end_of_life"].lower() == "yes":
            actions.append({
                "type": "REFRESH", "component_id": cid, "effort": "high",
                "label": f"Replace end-of-life {component['component_name']} with a supported generation",
                "detail": "Receives no further security updates in its current form",
                "change": {"end_of_life": "no"}})

        if component["validated_alternative"].lower() in {"no"} | UNKNOWN_VALUES:
            actions.append({
                "type": "QUALIFY", "component_id": cid, "effort": "medium",
                "label": f"Qualify a second supplier for {component['component_name']}",
                "detail": "No validated alternative source",
                "change": {"validated_alternative": "yes"}})

        if not result["identifiable"]:
            change, missing = {}, []
            for field, placeholder in (("vendor", "(declared by supplier)"),
                                       ("model", component["component_name"]),
                                       ("version", "1.0"),
                                       ("country_of_origin", "(declared by supplier)")):
                if component[field].lower() in UNKNOWN_VALUES:
                    change[field] = placeholder
                    missing.append(field.replace("_", " "))
            if change:
                actions.append({
                    "type": "IDENTIFY", "component_id": cid, "effort": "low",
                    "label": f"Obtain {', '.join(missing)} for {component['component_name']} from the supplier",
                    "detail": "Provenance cannot currently be established",
                    "change": change})
    return actions


def apply_actions(bom, actions):
    changes = {}
    for action in actions:
        changes.setdefault(action["component_id"], {}).update(action["change"])
    return [dict(c, **changes.get(c["component_id"], {})) for c in bom]


def remediation_plan(bom, cve_data, policy, baseline_scored, baseline_summary):
    candidates = build_remediation_actions(baseline_scored, bom, policy)
    baseline = baseline_summary["overall"]
    for action in candidates:
        _, trial = score_all(apply_actions(bom, [action]), cve_data, policy)
        action["saving"] = r1(baseline - trial["overall"])

    remaining, applied, steps = list(candidates), [], []
    current = baseline_summary
    while remaining and current["verdict"] != "APPROVE":
        here, best = verdict_distance(current), None
        for action in remaining:
            _, trial = score_all(apply_actions(bom, applied + [action]), cve_data, policy)
            key = (verdict_distance(trial), trial["overall"], EFFORT_ORDER[action["effort"]])
            if best is None or key < best[0]:
                best = (key, action, trial)
        (distance, _, _), action, trial = best
        if distance >= here:
            break
        applied.append(action); remaining.remove(action); current = trial
        steps.append({"action": action, "score": current["overall"],
                      "verdict": current["verdict"], "coverage": round(current["coverage"], 3),
                      "worst": current["worst"]})

    return {"candidates": sorted(candidates, key=lambda a: (-a["saving"], a["component_id"])),
            "steps": steps, "baseline_score": baseline,
            "baseline_verdict": baseline_summary["verdict"],
            "final_score": current["overall"], "final_verdict": current["verdict"],
            "reached_approve": current["verdict"] == "APPROVE"}


# ---------------------------------------------------------------------------
# Serialisation - the dashboard consumes this
# ---------------------------------------------------------------------------
def to_payload(scored, summary, plan, sources, notes, bom, cve_data, policy):
    return {
        # The dashboard re-scores this in the browser so the what-if simulator
        # can recalculate live, and so a different BOM can be uploaded.
        "raw": {"bom": bom, "cves": cve_data, "policy": policy},
        "meta": {"sources": sources, "notes": notes,
                 "weights": WEIGHTS, "criticality": CRITICALITY,
                 "dimension_labels": DIMENSION_LABELS,
                 "coverage_target": COVERAGE_TARGET,
                 "bands": BANDS,
                 "cwe_mitigations": CWE_MITIGATIONS,
                 "default_mitigation": DEFAULT_MITIGATION},
        "summary": {
            "total": summary["total"], "rated": summary["rated"],
            "overall": summary["overall"], "normalised": summary["normalised"],
            "band": summary["band"], "mean": summary["mean"], "penalty": summary["penalty"],
            "portfolio": summary["portfolio"], "worst": summary["worst"],
            "overall_driver": summary["overall_driver"],
            "coverage": round(summary["coverage"], 4),
            "verdict": summary["verdict"], "banner": summary["banner"],
            "rationale": summary["rationale"],
            "counts": {k: summary["band_counts"].get(k, 0)
                       for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")},
            "dimension_means": summary["dimension_means"],
            "concentration": summary["concentration"],
            "countries": dict(summary["countries"]),
            "unknown_ids": [r["component"]["component_id"] for r in summary["unknown"]],
            "blocked_ids": [r["component"]["component_id"] for r in summary["blocked"]],
            "cve_count": sum(len(r["cves"]) for r in scored),
            "restricted_vendors": sorted({r["component"]["vendor"] for r in summary["blocked"]}),
        },
        "components": [{
            "id": r["component"]["component_id"], "name": r["component"]["component_name"],
            "category": r["component"]["category"], "vendor": r["component"]["vendor"],
            "model": r["component"]["model"], "version": r["component"]["version"],
            "country": r["component"]["country_of_origin"], "quantity": r["component"]["quantity"],
            "end_of_life": r["component"]["end_of_life"],
            "lead_time_weeks": r["component"]["lead_time_weeks"],
            "validated_alternative": r["component"]["validated_alternative"],
            "score": r["score"], "normalised": r["normalised"], "band": r["band"],
            "status": r["status"], "base": r["base"], "multiplier": r["multiplier"],
            "weighted": r["weighted"], "floor": r["floor"], "driver": r["driver"],
            "dimensions": r["dimensions"],
            "reasons": {d: r["dimension_reasons"][d] for d in DIMENSIONS},
            "blocking": r["blocking"], "mitigation": r["mitigation"],
            "cves": [{"id": c["cve_id"], "cvss": _number(c["cvss_score"], 0.0),
                      "severity": c["severity"], "source": c["score_source"],
                      "cwe": c["cwe"], "kev": c["kev"],
                      "epss": _number(c["epss"], None),
                      "epss_percentile": _number(c["epss_percentile"], None),
                      "description": c["description"],
                      "fix": c["fix_available"]} for c in r["cves"]],
        } for r in scored],
        "plan": {
            "baseline_score": plan["baseline_score"], "baseline_verdict": plan["baseline_verdict"],
            "final_score": plan["final_score"], "final_verdict": plan["final_verdict"],
            "reached_approve": plan["reached_approve"],
            "steps": [{"type": s["action"]["type"], "component_id": s["action"]["component_id"],
                       "label": s["action"]["label"], "detail": s["action"]["detail"],
                       "effort": s["action"]["effort"], "score": s["score"],
                       "verdict": s["verdict"], "coverage": s["coverage"],
                       "worst": s["worst"]} for s in plan["steps"]],
            "candidates": [{"type": a["type"], "component_id": a["component_id"],
                            "label": a["label"], "detail": a["detail"], "effort": a["effort"],
                            "saving": a["saving"], "change": a["change"]}
                           for a in plan["candidates"]],
        } if plan else None,
    }


# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="BOMShield - score an AI server bill of materials for supply-chain risk.")
    parser.add_argument("--bom", default=DEFAULT_BOM)
    parser.add_argument("--cves", default=DEFAULT_CVES)
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--outdir", default=DEFAULT_OUTDIR)
    parser.add_argument("--no-simulate", action="store_true", help="skip the remediation simulator")
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

    scored, summary = score_all(bom, cve_data, policy)
    plan = None if args.no_simulate else remediation_plan(bom, cve_data, policy, scored, summary)
    payload = to_payload(scored, summary, plan,
                         {"bom": args.bom, "cves": args.cves, "policy": args.policy}, notes,
                         bom, cve_data, policy)

    os.makedirs(args.outdir, exist_ok=True)
    json_path = os.path.join(args.outdir, "data.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    from dashboard import write_dashboard, write_static_report
    dash_path = os.path.join(args.outdir, "dashboard.html")
    report_path = os.path.join(args.outdir, "report.html")
    write_dashboard(payload, dash_path)
    write_static_report(payload, report_path)

    print(f"\n  BOMSHIELD - {os.path.basename(args.bom)}")
    print(f"  Overall BOM risk    : {summary['overall']}/100  ({summary['normalised']}) "
          f"{summary['band']}")
    print(f"  Components          : {summary['total']}  scored {summary['rated']}, "
          f"not scored {len(summary['unknown'])}")
    print(f"  Data confidence     : {summary['coverage']:.0%}")
    print(f"  Verdict             : {summary['verdict']}  -  {summary['banner']}")
    print(f"  {summary['rationale']}")
    print("\n  Dimension means:")
    for d in DIMENSIONS:
        print(f"    {DIMENSION_LABELS[d]:<16} {summary['dimension_means'][d]:>5}  (weight {WEIGHTS[d]})")
    print("\n  Highest risk:")
    for r in sorted((x for x in scored if x["score"] is not None),
                    key=lambda r: -r["score"])[:5]:
        cves = ", ".join(c["cve_id"] for c in r["cves"]) or "-"
        print(f"    {r['score']:5.1f}  {r['band']:<8} {r['component']['component_id']}  "
              f"{r['component']['vendor']} {r['component']['model']}  {cves}")

    if plan:
        print(f"\n  REMEDIATION PLAN")
        if plan["reached_approve"]:
            print(f"  {len(plan['steps'])} action(s): {plan['baseline_verdict']} "
                  f"({plan['baseline_score']}) -> APPROVE ({plan['final_score']})")
        else:
            print(f"  Best achievable {plan['final_verdict']} ({plan['final_score']}), "
                  f"from {plan['baseline_score']}")
        for i, step in enumerate(plan["steps"], 1):
            print(f"    {i}. [{step['action']['type']:<8}] {step['action']['label']}")
            print(f"       -> risk {step['score']}  confidence {step['coverage']:.0%}  {step['verdict']}")

    print(f"\n  Dashboard : {dash_path}")
    print(f"  Report    : {report_path}")
    print(f"  Data      : {json_path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
