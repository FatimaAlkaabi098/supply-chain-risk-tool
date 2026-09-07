# Supply Chain Risk Scoring Tool (Software-Only Version)

School of Cyber Defense 2026 — Team Shadow Djinn

> The jury runs this from the README. If it does not run from a clean clone,
> the prototype criterion (25%) is lost. Test it by cloning into a NEW folder.

## TODO before submission — delete this block when done

- [ ] Every command below actually works from a fresh clone
- [ ] Runs twice in a row with identical output, no crash
- [ ] Handles an empty file, a missing column, and junk values gracefully
- [ ] Demo BOM produces 2 vulnerable firmware components + 1 restricted vendor
- [ ] Unmatched components are listed, not silently scored safe

---

## What this is

A scoring tool for AI server procurement. It ingests a Bill of Materials,
scores each component for supply-chain risk, and produces a findings report
with a mitigation or alternative for each risk.

**Who it is for:** a government or data-centre procurement office.
**What it replaces:** manual vendor due-diligence spreadsheets.

## Requirements

- Python 3.9 or newer
- No external libraries, no internet connection, no API keys

## Install

```
git clone <REPO URL>
cd supply-chain-risk-tool
```

## Run

```
python score.py --bom data/demo_bom.csv --out reports/report.html
```

Then open `reports/report.html`.

## Inputs

| File | What it holds |
|---|---|
| `data/demo_bom.csv` | The server bill of materials |
| `data/cve_dataset.csv` | Known vulnerabilities, curated from NVD |
| `data/policy.csv` | Restricted vendors and country risk tiers |

The policy file is **configurable** — the tool ships an example policy and a
procurement office supplies its own.

## Output

An HTML report containing the overall BOM score and verdict, a coverage
figure, the highest-risk components with their score breakdown, a mitigation
or alternative for each, and any components that could not be matched.

## Risk dimensions

1. **Known vulnerabilities** — matched from the CVE dataset
2. **Origin and vendor policy** — restricted vendors and country tiers
3. **Component factors** — end-of-life status, single-source dependency

Plus **concentration risk** across the BOM as a whole.

## Limitations

<!-- Be honest here. Judges reward it and punish overclaiming. -->
- The CVE dataset is curated and scoped to server hardware and firmware, not
  the complete NVD feed. The matching logic is dataset-agnostic.
- Scores are a **prioritisation index**, not a probability of compromise.

## Team

Fatmah Alkaabi (captain) · Alia Alkhazraji · Shahad Alhmoudi · Shamayel Aldhanhani
