# Walking the FAT/SAT checklist on a real handover

> **Tier 4 / Lesson 3 — 60 minutes.**

## Why FAT/SAT is the audit point of greatest leverage

A weak FAT/SAT means insecure configurations get baked into a 20-year asset lifecycle. Catching it at handover costs days. Catching it after operations cost months and a shutdown window.

Most plants have *no* FAT/SAT security checklist — only functional acceptance. That gap is consistently the highest-impact early finding in any IACS audit.

## The two artefacts you'll use

1. **The checklist** — [`templates/iec-62443-fat-sat-checklist.md`](#templates/view:iec-62443-fat-sat-checklist)
2. **The worked sample report** — [`samples/iec-62443-fat-sample.md`](#templates/view:iec-62443-fat-sample) — read this to see what an auditor expects the *output* to look like

Use the checklist as the procedure. Compare the auditee's actual handover artefacts against it.

## What to look for, by section

| Checklist section | What "satisfied" looks like | What "not satisfied" looks like |
|---|---|---|
| **System information** | All asset IDs, SL-T per zone, vendor/model documented | Blank fields, "TBD", or "n/a" without justification |
| **Hardening / build** | CIS / vendor hardening guide applied; default accounts disabled; unused services removed | "We applied vendor defaults" |
| **Network** | Zones implemented per design; firewall rules sampled; OT-aware DPI confirmed | "Vendor configured the network — talk to them" |
| **Remote access** | Jump server / IDMZ pattern; JIT for vendors; recording active | Direct VPN to PLCs; shared accounts |
| **Backup** | Backup taken before commissioning; restoration tested in testbed | "We'll back it up after go-live" |
| **Patch state at delivery** | Latest vendor security advisories applied or compensating controls documented | Out-of-date firmware with no mitigation note |
| **Logging** | Audit log generation enabled; logs forwarded to SIEM; retention configured | "We'll wire logging later" |
| **Documentation handover** | Network diagram, asset register, account inventory, IR contacts — all current | "Will be updated post go-live" |

## What to accept

- A documented gap with a stated remediation deadline AND a compensating control. ("Unable to disable Service X — vendor restriction. Compensating control: blocked at network boundary, documented in firewall rules ID 4421. Permanent remediation: vendor patch ETA Q3.")

## What to reject

- An undocumented gap.
- A gap with "we'll fix it later".
- A gap with a remediation deadline but no compensating control.
- A vendor saying "you'll have to take it up with us" — that means the auditee handed over without testing.

## Find the citation

Every accepted-with-conditions item must be entered into the **Vulnerability Ledger** (per [Pillar C — Continuous Vulnerability Management](#basic-start/pillar-continuous-vulnerability-management)). The ledger entry cites:

- The IEC 62443 SR violated.
- The compensating control documented.
- The owner.
- The remediation deadline.

If the ledger doesn't exist, that's a higher-order finding than the individual gap.

## Map to repo

- The checklist: [`templates/iec-62443-fat-sat-checklist`](#templates/view:iec-62443-fat-sat-checklist)
- The sample: [`samples/iec-62443-fat-sample`](#templates/view:iec-62443-fat-sample)
- IEC 62443: SR-7.7 (audit log); IEC 62443-4-1 (vendor secure dev lifecycle)
- NACSA: s18 (security measures), s23 (audit)

## What's next

[Lesson 4 — Writing a finding that maps to SR + NACSA](#learn/lesson:t4-auditor:04-finding-to-mapping).
