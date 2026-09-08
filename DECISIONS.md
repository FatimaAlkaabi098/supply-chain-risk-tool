# Design decisions and justifications

> Add a line here **every time** you choose a weight, a threshold or a rule.
> This is where the Technical Depth mark (25%) comes from — the rubric says
> "is the approach justified". A number with a reason beats a number that is
> merely correct. You cannot reconstruct this on the 10th, so write it as
> you go.

## Dimension weights

| Dimension | Weight | Why this weight |
|---|---|---|
| Known vulnerabilities | 0.40 | The only dimension with a directly exploitable path today. |
| Origin and vendor policy | 0.35 | In government procurement a restricted vendor is a hard compliance blocker, not a preference. |
| Component factors | 0.25 | Signals future exposure (end-of-life, single-source) rather than present exploitability. |

<!-- If you change a weight, change the reason too. -->

## Criticality multipliers

| Category | Multiplier | Why |
|---|---|---|
| BMC / firmware | 1.5 | Runs beneath the OS, survives reinstall, and is rarely monitored. |
| CPU | 1.3 | |
| GPU / NIC | 1.2 | |
| Storage / memory | 1.0 | Baseline. |
| PSU | 0.8 | Limited access to data or execution. |

## Unknown handling

A component that cannot be matched is reported as **UNKNOWN**, never scored
as zero risk. Rationale: absence of a known vulnerability is not evidence of
safety, and silently scoring unverified parts as clean is precisely the
failure mode the brief warns about.

## Scores are ordinal, not probabilistic

The output is a **prioritisation index** for ranking components. It is not a
probability of compromise and must never be described as one.

## CVSS source selection

The **NVD (NIST) base score** is used for every entry, so scores are comparable
across the dataset. Where NVD has not scored a CVE, the CNA score is used and
flagged in the `score_source` column.

This matters more than it sounds. Vendor and NVD assessments differ materially,
in both directions:

| CVE | NVD | Vendor (CNA) | Why they differ |
|---|---|---|---|
| CVE-2023-34329 | 8.0 HIGH | 9.1 CRITICAL (AMI) | Attack vector: NVD assessed adjacent-network, AMI assessed network |
| CVE-2024-25943 | **9.8 CRITICAL** | 7.6 HIGH (Dell) | NVD assessed no privileges and no user interaction required |

Mixing sources within one dataset would make the scores non-comparable and the
ranking meaningless.

## The unknown case - CVE-2024-8105 (PKfail)

PKfail is a genuine firmware supply-chain vulnerability: a hard-coded UEFI
Platform Key means anyone holding the private key can sign firmware that
affected systems will trust. It is precisely the risk this brief describes,
entering through a component long before an attacker touches the network.

**NVD holds no CVSS base score, no CWE, and no affected-product configuration
for it.** An automated matcher therefore cannot match it to a component by
vendor and version.

This is not a gap in our tool - it is the case the brief asks us to handle. A
scanner that silently scores unmatched components as safe would report an
affected server as clean. Ours surfaces it as UNVERIFIED and reports coverage.

## Version range simplification

NVD expresses affected versions as CPE range objects. These are flattened to a
readable string (e.g. `>=12.0 <12.4`). Where a product has several
generation-specific ranges they are combined into one field (e.g. Dell iDRAC9).
A deliberate simplification for readability; comparison remains version-based.

## Component matching approach

Components are matched to CVEs on **vendor + model** (exact, case-insensitive)
followed by a **version range check**. Production tools match on CPE strings.
CPE matching was out of scope for the timeframe; the simplification is recorded
here rather than hidden, and the matching logic is otherwise identical in shape.

## Two different kinds of "no result"

These must not be conflated, and the distinction is the heart of the unknown-case
requirement:

| Case | Meaning | How it is scored |
|---|---|---|
| Component identified, no CVE found | Genuinely no *known* vulnerability | Low vulnerability score, marked VERIFIED |
| Vendor or version cannot be established | We do not know what this part is | **UNVERIFIABLE** - surfaced, never scored as safe |

The demo BOM contains 6 components of the second kind (unbranded backplanes,
cable harnesses, rail kits), giving **82% coverage**. A scanner that silently
treats those as clean would report this rack as safer than it is.

## Country tiering is illustrative and organisation-supplied

`policy.csv` ships with placeholder tiers keyed to a supplier-audit status, not
to any geopolitical assessment. The tool is **policy-driven**: a procurement
office supplies its own restricted-vendor list and country tiering. This is both
better engineering and keeps the team out of claims it cannot defend.

**ACTION: confirm the real tiering basis with Dr. Zheeshan before submission.**

The restricted vendor in the demo BOM ("Meridian Component Works") is fictional,
so no real supplier is characterised.

## BOM schema

`end_of_life` (yes/no/unknown) was added to the BOM so that dimension 3 has a
lifecycle signal. Single-source dependency is derived from the BOM itself by
counting distinct vendors per category - it needs no extra input data.

## Default paths are script-relative

Default input paths resolve against the location of `score.py`, not the shell's
current working directory. Found during testing: an IDE Run button launches the
interpreter from the IDE's own install folder, so relative default paths failed.
The jury runs this from a README on an unknown machine, so the tool must not
assume a working directory. Paths passed explicitly on the command line still
resolve normally.

## Finding: NVD enrichment lags for recent CVEs

While building the dataset we pulled 13 CVEs directly from the NVD API. Only
**5 carry an NVD (NIST) primary CVSS score**. The other 8 have only a score
supplied by the reporting organisation (the CNA).

The split is almost entirely by age. Older, well-established CVEs are enriched;
recent ones (2025-2026) frequently are not yet.

This is not a flaw in our tool - it is a property of the reference data, and it
has a direct consequence for anyone building on NVD: **you cannot assume a
consistent scoring source.** Our `score_source` column records which was used
for every entry so the difference is visible rather than hidden.

It also reinforces the unknown-case argument. If the authoritative vulnerability
database itself has coverage gaps, a procurement tool that treats "nothing found"
as "nothing there" is unsafe by design.

## Interpreting vendor version strings

CVE-2023-25191 is fixed in "SPx_12-update-7.00". NVD's CPE entry lists the
vulnerable configuration generically as version 12. We read the vendor's fix
notation as 12.7 and recorded the range as `>=12.0 <12.7`. This is an
interpretation of the vendor's own notation, recorded here rather than applied
silently.

## Remediation simulator

Scoring a BOM tells procurement what is wrong. It does not tell them what to do,
or what it would buy them. The simulator answers the question a buyer actually
asks: **what is the smallest set of changes that makes this purchase acceptable?**

Four action types are derived automatically from the findings:

| Action | Derived from | Modelled as |
|---|---|---|
| PATCH | A matched CVE with a published fix | Version raised to the first fixed version, computed from the affected range |
| REPLACE | A vendor blocked by policy | Re-sourced from an approved supplier already present in the BOM for that category |
| REFRESH | End-of-life status | Replaced with a supported generation |
| IDENTIFY | Unverifiable provenance | The missing fields only are supplied |

### Why the plan is ranked by distance, not by points

The verdict is decided by three rules - a blocking vendor, any CRITICAL
component, and coverage below 90%. Ranking actions by points saved produced a
10-step plan full of changes that lowered the number without moving the
decision. Ranking by **distance to the approval conditions** produces a 6-step
plan where every step clears one condition. Points are only a tie-breaker.

On the demo BOM: 1 REPLACE clears the blocking vendor, 2 PATCH clear the two
CRITICAL components, and 3 IDENTIFY raise coverage from 82% to 91%.

### Honesty about what is modelled

PATCH and REPLACE are modelled exactly - the resulting component is rescored
through the same pipeline. **IDENTIFY models the best case**: that the supplier
provides provenance and the part proves to have no known vulnerability. If
provenance instead reveals a vulnerable part, the score will not improve by the
amount shown. This is stated in the report itself rather than left implicit.

### Bug found and fixed during testing

The first version of IDENTIFY overwrote the vendor field unconditionally. On a
component that was both from a blocked vendor and missing a version, obtaining
the version silently cleared the policy block and flipped REJECT to APPROVE.
IDENTIFY now fills in **only the fields that are actually missing**. Knowing a
part's version does not make its supplier acceptable.

## Open questions

- [ ] Confirm with organisers: is AI assistance permitted for the build, and must it be disclosed?
- [ ] Weight sensitivity — does the demo BOM ranking change if weights shift by ±0.05?

## Decision log

<!-- date | who | decision | why -->

| Date | Who | Decision | Why |
|---|---|---|---|
| 2026-09-07 | Team | CSV ingestion rather than CycloneDX/SPDX | Explicitly permitted by the brief; parsing effort earns no extra marks. |
| 2026-09-07 | Team | NVD score used over CNA score throughout | Comparability across the dataset. |
| 2026-09-07 | Team | Match on vendor + model, not CPE | CPE matching out of scope for a 4-day build. |
| 2026-09-07 | Team | Added `end_of_life` column to the BOM | Dimension 3 needs a lifecycle signal a procurement BOM would realistically carry. |
