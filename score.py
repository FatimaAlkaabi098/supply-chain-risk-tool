"""
Supply Chain Risk Scoring Tool (Software-Only Version)
School of Cyber Defense 2026 - Team Shadow Djinn

Usage:
    python score.py --bom data/demo_bom.csv --out reports/report.html

Reads a Bill of Materials for AI server components, scores each component
across three risk dimensions, produces a per-component and an overall BOM
score, and writes a findings report.

BUILD ORDER - build these one at a time and test after each one.
Do not start the next function until the previous one prints correct output.

    1. load_bom()            read the CSV, validate the columns
    2. match_cves()          DIMENSION 1 - known vulnerabilities
    3. apply_policy()        DIMENSION 2 - origin and restricted vendor
    4. component_factors()   DIMENSION 3 - end-of-life, single-source
    5. score_component()     combine the three into one score
    6. score_bom()           overall score + concentration risk
    7. write_report()        the HTML findings report

GRADED REQUIREMENTS - do not remove any of these:
    - unmatched components must be surfaced as UNKNOWN, never scored as safe
    - every finding needs a mitigation or an alternative component
    - must survive a second run and unexpected input without crashing
"""

import argparse
import csv
import os

# ---------------------------------------------------------------------------
# Weights - justify every one of these in DECISIONS.md
# ---------------------------------------------------------------------------
W_VULNERABILITY = 0.40
W_POLICY        = 0.35
W_COMPONENT     = 0.25

# Criticality multiplier by component category.
# A BMC vulnerability is far worse than a fan vulnerability.
CRITICALITY = {
    "bmc":      1.5,
    "firmware": 1.5,
    "cpu":      1.3,
    "gpu":      1.2,
    "nic":      1.2,
    "storage":  1.0,
    "memory":   1.0,
    "psu":      0.8,
}

REQUIRED_BOM_COLUMNS = [
    "component_id", "component_name", "category", "vendor",
    "model", "version", "country_of_origin", "quantity",
]


def load_bom(path):
    """Read the BOM CSV and return a list of dicts.

    Must handle, without crashing:
      - the file not existing
      - an empty file
      - missing required columns  (say WHICH ones are missing)
      - blank rows
      - unexpected extra columns  (ignore them)
    """
    # TODO
    raise NotImplementedError


def load_cve_dataset(path):
    """Read the CVE dataset CSV into a lookup structure."""
    # TODO
    raise NotImplementedError


def load_policy(path):
    """Read policy.csv - restricted vendors and country risk tiers.

    Policy driven, not opinion driven. The tool ships an example policy;
    a procurement office supplies its own.
    """
    # TODO
    raise NotImplementedError


def match_cves(component, cve_data):
    """DIMENSION 1 - known vulnerabilities.

    Match on vendor + product + version.
    Return the highest CVSS found, the list of matching CVE ids, and a
    match flag.

    IMPORTANT: no match means UNKNOWN, not zero. A component we cannot
    verify is not a component we have cleared.
    """
    # TODO
    raise NotImplementedError


def apply_policy(component, policy):
    """DIMENSION 2 - origin and vendor policy.

    A restricted vendor is a hard block, not a score.
    Otherwise return the country risk tier from the policy file.
    """
    # TODO
    raise NotImplementedError


def component_factors(component, bom):
    """DIMENSION 3 - component level factors.

    - end of life / end of support status
    - single source dependency: is this the only vendor in the whole BOM
      supplying this category?
    """
    # TODO
    raise NotImplementedError


def score_component(component, cve_data, policy, bom):
    """Combine the three dimensions into one 0-100 score.

    Apply the CRITICALITY multiplier for the component category.
    Return the score AND the breakdown - the jury asks for a clear breakdown,
    so keep every dimension's contribution visible.
    """
    # TODO
    raise NotImplementedError


def score_bom(scored_components):
    """Overall BOM score, plus CONCENTRATION RISK.

    Concentration risk is the innovation feature: a BOM can be low risk
    component by component and still be high risk as a portfolio, if too
    many critical parts share one vendor or one country of origin.

    Also return coverage: how many components were matched vs UNKNOWN.
    """
    # TODO
    raise NotImplementedError


def write_report(scored_components, bom_result, out_path):
    """Write the HTML findings report.

    Must contain:
      - overall BOM score and verdict (APPROVE / APPROVE WITH CONDITIONS / REJECT)
      - coverage figure: "matched X of Y components"
      - highest risk components first, with the score breakdown
      - a mitigation or an alternative component for every finding
      - the UNKNOWN components listed separately and clearly
    """
    # TODO
    raise NotImplementedError


def main():
    parser = argparse.ArgumentParser(description="Supply chain risk scoring for AI server BOMs")
    parser.add_argument("--bom", default="data/demo_bom.csv")
    parser.add_argument("--cves", default="data/cve_dataset.csv")
    parser.add_argument("--policy", default="data/policy.csv")
    parser.add_argument("--out", default="reports/report.html")
    args = parser.parse_args()

    # TODO: wire the functions together here, in the build order above.
    print("Not built yet - start with load_bom()")


if __name__ == "__main__":
    main()
