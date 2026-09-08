# Supply Chain Risk Scoring Tool (Software-Only Version)

School of Cyber Defense 2026 — Team Shadow Djinn

Scores an AI server **Bill of Materials for supply-chain risk before purchase**.

> Vulnerability scanners tell you what is wrong with the servers you already own.
> This tells you what is wrong with the ones you are about to buy.

**Who it is for:** a government or data-centre procurement office.
**What it replaces:** manual vendor due-diligence spreadsheets.

---

## Requirements

- Python 3.9 or newer
- **No external libraries. No internet connection. No API keys.**

## Run it

```
git clone <REPO URL>
cd supply-chain-risk-tool
python score.py
```

Then open `reports/report.html`.

The tool resolves its default data files relative to `score.py` itself, so it
runs correctly from any working directory - the project folder, an IDE Run
button, or anywhere else.

To use your own files:

```
python score.py --bom data/demo_bom.csv --cves data/cve_dataset.csv --policy data/policy.csv --out reports/report.html
```

## What you should see

```
  Components assessed : 34
  Overall BOM risk    : 29.7/100
  Coverage            : 82% (6 could not be verified)
  Verdict             : REJECT
  1 component(s) come from a vendor blocked by procurement policy.

     80.6  CRITICAL C008  Intel Active Management Technology Firmware  CVE-2018-3628
     79.8  CRITICAL C006  Dell iDRAC9                                  CVE-2024-25943
     74.6  HIGH     C007  NVIDIA DGX-1 BMC                             CVE-2023-25505
     53.2  HIGH     C005  AMI MegaRAC SPx12                            CVE-2023-34329
     51.0  HIGH     C012  Meridian Component Works MCW-25G-2P          -
```

## Inputs

| File | Holds |
|---|---|
| `data/demo_bom.csv` | The bill of materials — 34 components of an AI training rack |
| `data/cve_dataset.csv` | Known vulnerabilities, verified against the NVD API |
| `data/policy.csv` | Restricted vendors and country risk tiers — **organisation supplied** |

The policy file is **configuration, not code**. A procurement office supplies its
own restricted-supplier list and tiering; the tool enforces it rather than
deciding it.

## How it scores

Three dimensions, as required by the brief:

| Dimension | Weight | What it measures |
|---|---|---|
| Known vulnerabilities | 0.40 | Published CVEs matching this vendor, product and version |
| Origin and vendor policy | 0.35 | Restricted suppliers and country risk tier |
| Component factors | 0.25 | End-of-life status and single-source dependency |

The weighted result is multiplied by a **category criticality** factor (0.8–1.5).
A baseboard management controller has total control of a machine and survives an
operating system reinstall, so it is weighted 1.5×; a fan is weighted 0.8×.

Two things beyond per-component scoring:

- **Concentration risk** — the BOM is also assessed as a portfolio. Components
  that are individually acceptable can still be a single point of failure if too
  many critical parts share one supplier or one country.
- **The unknown case** — components whose vendor, model or version cannot be
  established are reported as **UNVERIFIABLE** and carry a defined uncertainty
  penalty. They are never silently scored as safe.

### Remediation simulator

The report does not stop at what is wrong. It computes **the smallest set of
changes that makes the purchase acceptable**, and shows the score and verdict
after each step:

```
  6 action(s) take this BOM from REJECT (29.7) to APPROVE (22.8)
    1. [REPLACE ] Re-source Dual-port 25GbE NIC from Broadcom      -> 28.5  APPROVE WITH CONDITIONS
    2. [PATCH   ] Update Dell iDRAC9 to 7.00.00.182                -> 26.1  APPROVE WITH CONDITIONS
    3. [PATCH   ] Update Intel AMT Firmware to 11.22.71            -> 24.1  APPROVE WITH CONDITIONS
    4. [IDENTIFY] Obtain version, origin for Rear I/O backplane    -> 23.6  APPROVE WITH CONDITIONS
    5. [IDENTIFY] Obtain version for GPU power cable harness       -> 23.2  APPROVE WITH CONDITIONS
    6. [IDENTIFY] Obtain version, origin for Rack mounting rails   -> 22.8  APPROVE
```

Actions are ranked by **distance to the approval conditions**, not by points
saved - so every step clears a real blocker. Disable with `--no-simulate`.

The verdict is rule-based, not a threshold on a single number:

| Verdict | When |
|---|---|
| **REJECT** | Any component from a vendor blocked by policy |
| **APPROVE WITH CONDITIONS** | Any CRITICAL component, or coverage below 90% |
| **APPROVE** | Neither of the above |

## Robustness

Tested and passing:

- Runs twice in a row with identical findings
- Missing file, empty file, or headers with no rows → explains the problem
- Missing required columns → names exactly which are missing
- Junk values, duplicate IDs, blank rows, non-numeric quantities → warns and continues
- Unicode and quoted fields handled
- Full run including the simulator completes in under one second

## Limitations

Stated plainly, because overclaiming costs more than admitting scope.

- The CVE dataset is **curated and scoped to server hardware and firmware**, not
  the complete NVD feed. The matching logic is dataset-agnostic and would work
  unchanged against the full feed.
- Components are matched on **vendor + model + version**. Production tools match
  on CPE strings; that was out of scope for the timeframe.
- Scores are a **prioritisation index on a 0–100 scale, not a probability of
  compromise.**
- Country tiers in `policy.csv` are **illustrative placeholders**. Real tiering is
  an organisational policy decision.

Design decisions and their justifications are in [DECISIONS.md](DECISIONS.md).

## Team

Fatmah Alkaabi (captain) · Alia Alkhazraji · Shahad Alhmoudi · Shamayel Aldhanhani
