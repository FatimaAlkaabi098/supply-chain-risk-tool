"""
standards.py - maps BOMShield's scoring onto recognised risk-assessment standards.

CSF 4003 Risk Management.

WHY THIS MODULE EXISTS
----------------------
BOMShield scores a bill of materials on a 0-100 index built from five weighted
dimensions. That index is useful for ranking, but it is not the language that
ISO/IEC 27005 or NIST SP 800-30 speak. Those standards express risk as a
*risk scenario* carrying a Likelihood and an Impact, combined into a risk level.

The two views are not in conflict. BOMShield already separates likelihood
evidence from impact evidence - it simply never labelled them that way:

    LIKELIHOOD evidence  EPSS percentile  (probability of exploitation)
                         CISA KEV listing (exploitation observed, not predicted)
                         end-of-life status, single-source status, origin tier

    IMPACT evidence      CVSS severity    (how bad exploitation would be)
                         category criticality multiplier - a baseboard
                         management controller has total control of a machine
                         and survives an OS reinstall; a fan does not

So this module does not invent a second risk model. It re-expresses the
evidence BOMShield already holds in the structure the standards require:

    Asset -> Threat -> Vulnerability -> Existing controls -> Likelihood
          -> Impact -> Risk level -> Treatment -> Residual risk

A NOTE ON CONTROLS
------------------
Treatments in this model reduce LIKELIHOOD, not IMPACT. Patching firmware makes
exploitation less likely; it does not make the management controller less
critical to the machine. Impact is a property of the asset, likelihood is a
property of the threat environment. Conflating the two is the most common error
in student risk registers, so the residual calculation here keeps them apart.
The one exception is REPLACE, which removes the asset from the assessment
entirely and therefore retires the scenario.
"""
import math

# ---------------------------------------------------------------------------
# Scales - NIST SP 800-30 Appendix G uses a five-level qualitative scale, and
# ISO/IEC 27005 Annex A permits any consistent ordinal scale. We use 1-5 for
# both factors so that Risk = Likelihood x Impact lands on 1-25.
# ---------------------------------------------------------------------------
LIKELIHOOD_LABELS = {1: "Very low", 2: "Low", 3: "Moderate", 4: "High", 5: "Very high"}
IMPACT_LABELS = {1: "Very low", 2: "Low", 3: "Moderate", 4: "High", 5: "Very high"}

# Risk level bands over the 1-25 product.
RISK_BANDS = [(20, "VERY HIGH"), (15, "HIGH"), (10, "MODERATE"), (5, "LOW"), (0, "VERY LOW")]

# Impact is a property of the asset. These mirror the CRITICALITY multipliers
# in score.py: 1.5 -> 5, 1.3 -> 4, 1.2 -> 4, 1.0 -> 3, 0.9 -> 3, 0.8 -> 2.
ASSET_IMPACT = {
    "bmc": 5, "firmware": 5, "cpu": 4, "gpu": 4, "nic": 4,
    "storage": 3, "memory": 3, "other": 3, "psu": 2, "cooling": 2,
}
DEFAULT_ASSET_IMPACT = 3

# ISO/IEC 27005 risk treatment options.
TREATMENT_MODIFY = "Modify"
TREATMENT_AVOID = "Avoid"
TREATMENT_RETAIN = "Retain"
TREATMENT_SHARE = "Share"


def risk_band(level):
    for threshold, label in RISK_BANDS:
        if level >= threshold:
            return label
    return "VERY LOW"


def _clamp(value, lo=1, hi=5):
    return max(lo, min(hi, int(value)))


def _round_half_up(value):
    """Python's round() is banker's rounding (4.5 -> 4) while JavaScript's
    Math.round is half-up (4.5 -> 5). The browser build of this model must
    agree with the engine, so both round half away from zero."""
    return math.floor(value + 0.5)


def _cve_field(cve, *names, default=0.0):
    """CVE rows reach us in two shapes: raw CSV columns (cvss_score, cve_id) and
    score.py's payload (cvss, id). Accept either rather than silently reading a
    missing key as zero."""
    for n in names:
        if n in cve and cve[n] not in (None, ""):
            try:
                return float(cve[n])
            except (TypeError, ValueError):
                return cve[n]
    return default


# ---------------------------------------------------------------------------
# Likelihood derivation - one rule per dimension, each traceable to real data
# ---------------------------------------------------------------------------
def likelihood_vulnerability(cves):
    """EPSS percentile is an exploitation probability, so it maps to likelihood
    directly. A KEV listing is not a prediction - it is an observation."""
    if not cves:
        return None, "No matching CVE"
    if any(str(c.get("kev", "")).lower().startswith("y") for c in cves):
        return 5, "Listed in CISA KEV - exploitation observed in the wild"
    pct = max(_cve_field(c, "epss_percentile") for c in cves)
    if pct >= 0.85:
        return 5, f"EPSS percentile {pct:.2f} - among the most likely to be exploited"
    if pct >= 0.60:
        return 4, f"EPSS percentile {pct:.2f}"
    if pct >= 0.30:
        return 3, f"EPSS percentile {pct:.2f}"
    if pct >= 0.10:
        return 2, f"EPSS percentile {pct:.2f}"
    return 1, f"EPSS percentile {pct:.2f} - exploitation unlikely at present"


def likelihood_policy(component, dims):
    """A restricted supplier is not a probability. The component is in the BOM
    now, so the compliance breach is certain unless the item is replaced."""
    score = dims.get("policy", 0.0)
    if score >= 100:
        return 5, "Certain - the component is in the BOM and the vendor is blocked"
    if score >= 60:
        return 4, "Supplier is under review; the condition is present now"
    return None, "No vendor rule applies"


def likelihood_lifecycle(component, dims):
    score = dims.get("lifecycle", 0.0)
    if score >= 80:
        return 4, "Declared end of life - no future security fixes will be issued"
    if score >= 40:
        return 3, "Support horizon not declared by the supplier"
    return None, "Within vendor support"


def likelihood_geopolitical(component, dims):
    score = dims.get("geopolitical", 0.0)
    if score >= 70:
        return 4, "Origin undeclared or in the highest policy tier"
    if score >= 40:
        return 3, "Origin in an intermediate policy tier"
    if score > 0:
        return 2, "Origin in the lowest policy tier"
    return None, "No origin concern"


def likelihood_operational(component, dims):
    score = dims.get("operational", 0.0)
    if score >= 70:
        return 4, "Single source, no qualified alternative, or a long lead time"
    if score >= 40:
        return 3, "Limited sourcing flexibility"
    if score > 0:
        return 2, "Minor sourcing constraint"
    return None, "Second source available"


# ---------------------------------------------------------------------------
# Impact derivation
# ---------------------------------------------------------------------------
def impact_for(component, scenario_kind, cves=None):
    """Impact combines what the asset is with what the threat would do to it."""
    asset = ASSET_IMPACT.get(str(component.get("category", "")).lower(), DEFAULT_ASSET_IMPACT)

    if scenario_kind == "vulnerability":
        cvss = max(_cve_field(c, "cvss_score", "cvss") for c in cves) if cves else 0.0
        sev = 5 if cvss >= 9.0 else 4 if cvss >= 7.0 else 3 if cvss >= 4.0 else 2
        # The asset sets the ceiling: a critical flaw in a fan is still a fan.
        return _clamp(_round_half_up((sev + asset) / 2 + (0.5 if asset >= 5 else 0))), \
            f"CVSS {cvss} on a '{component.get('category')}' asset (asset impact {asset}/5)"

    if scenario_kind == "policy":
        return 5, "Procurement is blocked outright - legal and compliance exposure"

    if scenario_kind == "lifecycle":
        return _clamp(asset), f"Unpatchable '{component.get('category')}' asset (asset impact {asset}/5)"

    if scenario_kind == "geopolitical":
        return _clamp(asset - 1), "Supply interruption or provenance that cannot be verified"

    if scenario_kind == "operational":
        return _clamp(asset - 1), "Delivery delay or inability to replace a failed part"

    return DEFAULT_ASSET_IMPACT, "Default asset impact"


# ---------------------------------------------------------------------------
# Scenario construction - the ISO 27005 / NIST SP 800-30 row
# ---------------------------------------------------------------------------
SCENARIOS = [
    ("vulnerability",
     "Threat actor exploits a published vulnerability in the component firmware",
     "Unpatched firmware with a known CVE",
     "Vendor patching process; network segmentation of management interfaces"),
    ("policy",
     "Component is procured from a supplier prohibited by procurement policy",
     "Supplier appears on the organisation's restricted list",
     "Procurement policy and approved-supplier list"),
    ("lifecycle",
     "A vulnerability is published after the vendor has ended support",
     "Component is beyond its supported life, so no fix will be issued",
     "Asset lifecycle register; scheduled technology refresh"),
    ("geopolitical",
     "Supply is interrupted, or provenance cannot be verified, due to origin",
     "Country of origin is undeclared or in a higher-risk policy tier",
     "Supplier due diligence; country-of-origin declaration requirement"),
    ("operational",
     "Supply is disrupted and the component cannot be replaced in time",
     "Single-source dependency, no qualified alternative, or long lead time",
     "Second-source qualification programme; buffer stock"),
]

LIKELIHOOD_FN = {
    "vulnerability": None,  # handled separately, needs the CVE list
    "policy": likelihood_policy,
    "lifecycle": likelihood_lifecycle,
    "geopolitical": likelihood_geopolitical,
    "operational": likelihood_operational,
}

# Which remediation action treats which scenario, and what it does to likelihood.
TREATMENT_FOR = {
    "vulnerability": ("PATCH", "Apply the vendor's fixed firmware version", 1,
                      TREATMENT_MODIFY),
    "policy": ("REPLACE", "Re-source from an approved supplier", 0, TREATMENT_AVOID),
    "lifecycle": ("REFRESH", "Replace with an in-support component", 1, TREATMENT_MODIFY),
    "geopolitical": ("IDENTIFY", "Obtain and verify a country-of-origin declaration", 2,
                     TREATMENT_MODIFY),
    "operational": ("QUALIFY", "Qualify a second source for this category", 2,
                    TREATMENT_MODIFY),
}


def build_register(scored_components):
    """Return one risk-register row per applicable scenario per component.

    `scored_components` is the `components` list from score.py's payload.
    """
    register = []
    for comp in scored_components:
        dims = comp.get("dimensions") or {}
        cves = comp.get("cves") or []
        identifiable = comp.get("score") is not None

        # The unknown case is itself a risk, and the standards require it to be
        # recorded rather than dropped. NIST SP 800-30 treats missing
        # information as an uncertainty to be stated, not a zero.
        if not identifiable:
            register.append(_row(
                comp, "unidentified",
                threat="The component cannot be identified, so it cannot be assessed",
                vulnerability="Vendor, model or version is missing from the BOM",
                controls="BOM data-quality requirement at purchase-order stage",
                likelihood=(5, "Certain - the information is absent now"),
                impact=(ASSET_IMPACT.get(str(comp.get("category", "")).lower(),
                                         DEFAULT_ASSET_IMPACT),
                        "Unknown exposure on a live asset"),
                action=("IDENTIFY", "Obtain vendor, model and version from the supplier",
                        1, TREATMENT_MODIFY)))
            continue

        for kind, threat, vuln, controls in SCENARIOS:
            if kind == "vulnerability":
                lik = likelihood_vulnerability(cves)
            else:
                lik = LIKELIHOOD_FN[kind](comp, dims)
            if lik[0] is None:
                continue  # scenario does not apply to this component
            imp = impact_for(comp, kind, cves)
            register.append(_row(comp, kind, threat, vuln, controls, lik, imp,
                                 TREATMENT_FOR[kind]))
    register.sort(key=lambda r: (-r["risk_level"], r["asset_id"]))
    return register


def _row(comp, kind, threat, vulnerability, controls, likelihood, impact, action):
    lik, lik_why = likelihood
    imp, imp_why = impact
    level = lik * imp
    act_type, act_text, residual_lik, treatment_option = action

    # Controls act on likelihood, not on impact - see the module docstring.
    residual_lik = _clamp(min(lik, residual_lik)) if residual_lik else 0
    residual_level = residual_lik * imp if residual_lik else 0

    return {
        "asset_id": comp.get("id"),
        "asset": comp.get("name"),
        "asset_category": comp.get("category"),
        "asset_owner": "Procurement / Infrastructure",
        "scenario": kind,
        "threat": threat,
        "vulnerability": vulnerability,
        "existing_controls": controls,
        "likelihood": lik,
        "likelihood_label": LIKELIHOOD_LABELS[lik],
        "likelihood_rationale": lik_why,
        "impact": imp,
        "impact_label": IMPACT_LABELS[imp],
        "impact_rationale": imp_why,
        "risk_level": level,
        "risk_band": risk_band(level),
        "treatment_option": treatment_option,
        "treatment": act_text,
        "action_type": act_type,
        "residual_likelihood": residual_lik,
        "residual_level": residual_level,
        "residual_band": risk_band(residual_level) if residual_lik else "RETIRED",
    }


# ---------------------------------------------------------------------------
# FAIR - a quantitative view. FAIR decomposes risk into Loss Event Frequency
# and Loss Magnitude; risk is their product, an annualised loss expectancy.
#
# The money figures below are ILLUSTRATIVE PLACEHOLDERS for the course. FAIR
# expects calibrated estimates from the organisation's own loss history, which
# a student project does not have. What is genuine here is the *structure* -
# frequency x magnitude - and the fact that both are driven by the same
# evidence as the qualitative view, so the two cannot silently disagree.
# ---------------------------------------------------------------------------
LEF_PER_YEAR = {1: 0.05, 2: 0.15, 3: 0.40, 4: 1.00, 5: 2.50}
LOSS_MAGNITUDE_AED = {1: 5_000, 2: 25_000, 3: 100_000, 4: 400_000, 5: 1_200_000}


def fair_view(register):
    """Annualised loss expectancy per row, plus a portfolio total."""
    rows = []
    for r in register:
        lef = LEF_PER_YEAR[r["likelihood"]]
        lm = LOSS_MAGNITUDE_AED[r["impact"]]
        ale = lef * lm
        r_lef = LEF_PER_YEAR.get(r["residual_likelihood"], 0.0)
        r_ale = r_lef * lm
        rows.append({**r, "lef": lef, "loss_magnitude": lm, "ale": ale,
                     "residual_ale": r_ale, "ale_reduction": ale - r_ale})
    total = sum(x["ale"] for x in rows)
    residual_total = sum(x["residual_ale"] for x in rows)
    return {
        "rows": rows,
        "total_ale": total,
        "residual_ale": residual_total,
        "reduction": total - residual_total,
        "assumptions": {
            "lef_per_year": LEF_PER_YEAR,
            "loss_magnitude_aed": LOSS_MAGNITUDE_AED,
            "note": ("Illustrative calibration for coursework. FAIR requires loss "
                     "estimates drawn from the organisation's own history; these "
                     "placeholders make the method visible, not the money credible."),
        },
    }


# ---------------------------------------------------------------------------
# The 5x5 matrix
# ---------------------------------------------------------------------------
def matrix_counts(register, residual=False):
    """counts[impact][likelihood] for the heat map. Index 0 == level 1."""
    grid = [[0] * 5 for _ in range(5)]
    for r in register:
        lik = r["residual_likelihood"] if residual else r["likelihood"]
        if not lik:
            continue
        grid[r["impact"] - 1][lik - 1] += 1
    return grid


def summarise(register):
    bands = {}
    for r in register:
        bands[r["risk_band"]] = bands.get(r["risk_band"], 0) + 1
    residual_bands = {}
    for r in register:
        residual_bands[r["residual_band"]] = residual_bands.get(r["residual_band"], 0) + 1
    treated = [r for r in register if r["residual_level"] < r["risk_level"]]
    return {
        "total_risks": len(register),
        "bands": bands,
        "residual_bands": residual_bands,
        "highest": register[0] if register else None,
        "mean_level": round(sum(r["risk_level"] for r in register) / len(register), 1)
        if register else 0,
        "mean_residual": round(sum(r["residual_level"] for r in register) / len(register), 1)
        if register else 0,
        "treatable": len(treated),
    }


# ---------------------------------------------------------------------------
# Framework mapping - what each BOMShield concept is called in each standard
# ---------------------------------------------------------------------------
FRAMEWORK_MAP = [
    ("Bill of materials component", "Asset (Clause 8.2.2)", "Step 2 - Identify threat sources and assets",
     "Critical asset profile", "Asset at risk"),
    ("Five risk dimensions", "Risk identification (8.2)", "Step 2 - Threat / vulnerability identification",
     "Areas of concern", "Threat event"),
    ("EPSS percentile / CISA KEV", "Likelihood assessment (8.2.5)", "Task 2-4 - Likelihood of occurrence",
     "Threat probability", "Loss Event Frequency"),
    ("CVSS severity x criticality", "Consequence assessment (8.2.4)", "Task 2-5 - Magnitude of impact",
     "Impact on the organisation", "Loss Magnitude"),
    ("Risk = Likelihood x Impact", "Risk estimation (8.2.6)", "Task 2-6 - Determination of risk",
     "Risk measure", "Risk = LEF x LM"),
    ("Approval verdict thresholds", "Risk evaluation (8.3) against criteria",
     "Step 3 - Communicate results", "Mitigation priority", "Risk appetite comparison"),
    ("Remediation simulator", "Risk treatment (Clause 9)", "Step 4 - Maintain / respond",
     "Protection strategy", "Cost-benefit of controls"),
    ("Post-treatment projection", "Residual risk (9.2) and acceptance",
     "Reassessment after controls", "Residual risk", "Residual ALE"),
    ("NOT SCORED components", "Incomplete information must be recorded",
     "Uncertainty must be stated, not assumed away", "Gap in asset knowledge",
     "Excluded from estimate, declared"),
]

# ---------------------------------------------------------------------------
# Standalone runner:  python standards.py
#
# Reads the payload score.py already wrote and emits the risk register in the
# two forms a risk-management course actually needs - a spreadsheet to work in
# and a printable page to hand in.
# ---------------------------------------------------------------------------
REGISTER_COLUMNS = [
    ("asset_id", "Asset ID"), ("asset", "Asset"), ("asset_category", "Category"),
    ("asset_owner", "Owner"), ("threat", "Threat"), ("vulnerability", "Vulnerability"),
    ("existing_controls", "Existing controls"),
    ("likelihood", "Likelihood (1-5)"), ("likelihood_label", "Likelihood"),
    ("likelihood_rationale", "Likelihood rationale"),
    ("impact", "Impact (1-5)"), ("impact_label", "Impact"),
    ("impact_rationale", "Impact rationale"),
    ("risk_level", "Risk level (LxI)"), ("risk_band", "Risk band"),
    ("treatment_option", "Treatment option"), ("treatment", "Treatment"),
    ("residual_likelihood", "Residual likelihood"),
    ("residual_level", "Residual level"), ("residual_band", "Residual band"),
]

BAND_COLOUR = {"VERY HIGH": "#ff6f7e", "HIGH": "#f08a4b", "MODERATE": "#f4bd62",
               "LOW": "#4ed2a0", "VERY LOW": "#59b7ff", "RETIRED": "#8ea6c6"}


def write_csv(register, path):
    import csv
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([label for _, label in REGISTER_COLUMNS])
        for row in register:
            w.writerow([row[key] for key, _ in REGISTER_COLUMNS])
    return path


def write_html(register, summary, fair, path):
    esc = lambda t: (str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    rows = "".join(
        "<tr>"
        f"<td><b>{esc(r['asset'])}</b><br><small>{esc(r['asset_id'])} &middot; {esc(r['asset_category'])}</small></td>"
        f"<td>{esc(r['threat'])}</td><td>{esc(r['vulnerability'])}</td>"
        f"<td class='muted'>{esc(r['existing_controls'])}</td>"
        f"<td title=\"{esc(r['likelihood_rationale'])}\">{r['likelihood']}</td>"
        f"<td title=\"{esc(r['impact_rationale'])}\">{r['impact']}</td>"
        f"<td><span class='lvl' style='background:{BAND_COLOUR[r['risk_band']]}'>{r['risk_level']}</span> {esc(r['risk_band'])}</td>"
        f"<td><b>{esc(r['treatment_option'])}</b><br><small>{esc(r['treatment'])}</small></td>"
        f"<td><span class='lvl' style='background:{BAND_COLOUR[r['residual_band']]}'>{r['residual_level'] or '&mdash;'}</span> {esc(r['residual_band'])}</td>"
        "</tr>" for r in register)

    grid = matrix_counts(register)
    cells = ""
    for i in range(4, -1, -1):
        cells += f"<div class='ax'>{i+1}</div>"
        for l in range(5):
            n = grid[i][l]
            band = risk_band((i + 1) * (l + 1))
            cells += (f"<div class='mc' style='background:{BAND_COLOUR[band]}'>{n}</div>"
                      if n else "<div class='mc empty'>&middot;</div>")
    cells += "<div class='ax'></div>" + "".join(f"<div class='ax'>{l}</div>" for l in range(1, 6))

    html = f"""<!doctype html><meta charset="utf-8">
<title>Risk Register - BOMShield - CSF 4003</title>
<style>
 body{{font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;margin:26px;color:#16202c;background:#fff}}
 h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:15px;margin:26px 0 10px}}
 .sub{{color:#5f7082;margin:0 0 18px}}
 .kpis{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}}
 .kpi{{border:1px solid #d6dfe8;border-radius:9px;padding:9px 13px;min-width:130px}}
 .kpi small{{display:block;color:#5f7082;font-size:11px;text-transform:uppercase;letter-spacing:.6px}}
 .kpi b{{font-size:19px}}
 table{{border-collapse:collapse;width:100%;font-size:12px}}
 th{{text-align:left;background:#eef3f8;padding:7px 8px;border:1px solid #d6dfe8;font-size:11px;
    text-transform:uppercase;letter-spacing:.5px;color:#5f7082}}
 td{{padding:7px 8px;border:1px solid #e3eaf1;vertical-align:top}}
 td small{{color:#5f7082}} .muted{{color:#5f7082}}
 .lvl{{display:inline-block;min-width:24px;text-align:center;border-radius:4px;padding:1px 5px;
   font-weight:800;color:#08121f}}
 .mx{{display:grid;grid-template-columns:auto repeat(5,64px);gap:3px;margin:10px 0}}
 .mc{{height:42px;display:flex;align-items:center;justify-content:center;border-radius:6px;
   font-weight:800;color:#08121f}}
 .mc.empty{{background:#eef3f8;color:#93a7bb}}
 .ax{{display:flex;align-items:center;justify-content:center;color:#5f7082;font-size:11px;font-weight:700}}
 .note{{border-left:3px solid #f4bd62;background:#fdf6e7;padding:10px 13px;border-radius:7px;
   color:#5a4a28;font-size:12.5px;margin-top:14px}}
 @media print{{body{{margin:10mm}} table{{font-size:9.5px}} th{{font-size:8.5px}}}}
</style>
<h1>Supply-chain risk register</h1>
<p class="sub">BOMShield &middot; CSF 4003 Risk Management &middot; structured to ISO/IEC 27005 and NIST SP 800-30</p>
<div class="kpis">
 <div class="kpi"><small>Risk scenarios</small><b>{summary['total_risks']}</b></div>
 <div class="kpi"><small>Very high + high</small><b>{summary['bands'].get('VERY HIGH',0)+summary['bands'].get('HIGH',0)}</b></div>
 <div class="kpi"><small>Mean risk level</small><b>{summary['mean_level']}</b> / 25</div>
 <div class="kpi"><small>Mean residual</small><b>{summary['mean_residual']}</b> / 25</div>
 <div class="kpi"><small>Inherent ALE</small><b>AED {fair['total_ale']:,.0f}</b></div>
 <div class="kpi"><small>Residual ALE</small><b>AED {fair['residual_ale']:,.0f}</b></div>
</div>
<h2>5 &times; 5 risk matrix &mdash; rows are Impact, columns are Likelihood</h2>
<div class="mx">{cells}</div>
<h2>Risk register</h2>
<table><thead><tr>
 <th>Asset</th><th>Threat</th><th>Vulnerability</th><th>Existing controls</th>
 <th>L</th><th>I</th><th>Risk</th><th>Treatment</th><th>Residual</th>
</tr></thead><tbody>{rows}</tbody></table>
<div class="note"><b>Method.</b> Likelihood is derived from exploitation evidence (EPSS percentile, CISA KEV listing,
end-of-life status, sourcing constraints). Impact is derived from CVSS severity and the criticality of the asset
category. Risk = Likelihood &times; Impact on 1&ndash;5 scales. Treatments reduce likelihood, not impact &mdash; patching
firmware does not make a management controller less critical to the machine. The FAIR money figures are an
illustrative calibration for coursework, not a valuation.</div>
"""
    open(path, "w", encoding="utf-8", newline="").write(html)
    return path


def main():
    import json
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    payload = os.path.join(here, "reports", "data.json")
    if not os.path.exists(payload):
        print("reports/data.json not found - run 'python score.py' first.")
        return 1

    data = json.load(open(payload, encoding="utf-8"))
    register = build_register(data["components"])
    summary = summarise(register)
    fair = fair_view(register)

    out = os.path.join(here, "reports")
    csv_path = write_csv(register, os.path.join(out, "risk_register.csv"))
    html_path = write_html(register, summary, fair, os.path.join(out, "risk_register.html"))

    rule = "=" * 66
    print(rule)
    print("  SUPPLY-CHAIN RISK REGISTER - ISO/IEC 27005 / NIST SP 800-30")
    print(rule)
    print(f"  Risk scenarios     {summary['total_risks']} across {len(data['components'])} assets")
    print(f"  Inherent bands     {summary['bands']}")
    print(f"  Residual bands     {summary['residual_bands']}")
    print(f"  Mean risk level    {summary['mean_level']} / 25  ->  residual {summary['mean_residual']} / 25")
    print(f"  Inherent ALE       AED {fair['total_ale']:,.0f}")
    print(f"  Residual ALE       AED {fair['residual_ale']:,.0f}  (FAIR, illustrative calibration)")
    print()
    print("  HIGHEST RISKS")
    print(f"    {'ASSET':<32} {'SCENARIO':<14} {'L':>2} {'I':>2} {'RISK':>5}  {'BAND':<10}")
    for r in register[:6]:
        print(f"    {str(r['asset'])[:31]:<32} {r['scenario']:<14} {r['likelihood']:>2} "
              f"{r['impact']:>2} {r['risk_level']:>5}  {r['risk_band']:<10}")
    print()
    print(f"  Spreadsheet  {csv_path}")
    print(f"  Printable    {html_path}")
    print(rule)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
