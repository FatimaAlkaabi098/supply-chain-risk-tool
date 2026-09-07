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

## Open questions

- [ ] Confirm with organisers: is AI assistance permitted for the build, and must it be disclosed?
- [ ] Weight sensitivity — does the demo BOM ranking change if weights shift by ±0.05?

## Decision log

<!-- date | who | decision | why -->

| Date | Who | Decision | Why |
|---|---|---|---|
| 2026-09-07 | Team | CSV ingestion rather than CycloneDX/SPDX | Explicitly permitted by the brief; parsing effort earns no extra marks. |
