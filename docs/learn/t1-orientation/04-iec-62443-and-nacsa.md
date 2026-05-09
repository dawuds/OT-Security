# IEC 62443 and NACSA Act 854 in 15 minutes

> **Tier 1 / Lesson 4 — 15 minutes.**

## IEC 62443 in one diagram (in your head)

IEC 62443 is a **family** of standards for IACS (Industrial Automation and Control Systems) security. The parts you actually use:

| Part | What it covers |
|---|---|
| **IEC 62443-2-1** | Security programme requirements (organisation level) |
| **IEC 62443-3-2** | Risk assessment + zone-and-conduit design |
| **IEC 62443-3-3** | System security requirements (the famous **51 SRs / 7 FRs**) |
| **IEC 62443-4-1** | Secure development lifecycle for product suppliers |
| **IEC 62443-4-2** | Component-level security requirements (PLCs, HMIs, network gear) |

For day-to-day work, **62443-3-3** and **62443-3-2** are the two you need.

### The 7 Foundational Requirements (FRs)

| FR | Name | One-liner |
|---|---|---|
| FR1 | Identification & Authentication Control | Who is this user/device? |
| FR2 | Use Control | What are they allowed to do? |
| FR3 | System Integrity | Did the configuration / firmware / message stay intact? |
| FR4 | Data Confidentiality | Is the data protected at rest and in transit? |
| FR5 | Restricted Data Flow | Is the network properly segmented? |
| FR6 | Timely Response to Events | Can we detect and respond? |
| FR7 | Resource Availability | Is the system there when we need it? |

Each FR breaks into System Requirements (SRs). Each SR has descriptions for **Security Levels 1–4**. Browse them in [Framework → System Requirements](#framework/iec-sr).

### Security Levels (SLs)

| SL | Threat profile | Where it applies |
|---|---|---|
| SL 1 | Casual / opportunistic | Non-critical OT |
| SL 2 | Motivated, generic IT skills | NCII baseline for most OT sectors |
| SL 3 | OT-expert attacker | High-criticality NCII assets |
| SL 4 | Nation-state, SIS-targeting | Safety Instrumented Systems — *all sectors* |

You **target** an SL per zone (SL-T), and you **achieve** an SL through implemented controls (SL-A). The gap between SL-T and SL-A is your work programme.

See [Security Levels](#framework/iec-sl) for the full definitions.

## NACSA Act 854 in 10 minutes (Malaysia-specific)

The **Cyber Security Act 2024 (Act 854)** governs **National Critical Information Infrastructure (NCII)** operators in Malaysia. The OT-relevant sections:

| Section | What it requires | Map to IEC 62443 |
|---|---|---|
| **s17** | NCII designation (you must know if you are NCII) | Asset inventory (SR-7.8) defines scope |
| **s18** | Implement security measures | IEC 62443 SL-2 minimum; SL-3 for high-criticality |
| **s19** | Awareness, training, security programme | FR2 + organisational programme (62443-2-1) |
| **s20** | Incident management capabilities | FR6 + the IR programme |
| **s21** | Risk assessment | IEC 62443-3-2 zone-based methodology is the standard route |
| **s22** | Code of practice (sectoral COPs) | Sector mapping in [`cross-references/sector-to-nacsa-cop.json`](#reference/sector-cop) |
| **s23** | Security audit by NACSA-licensed auditor | IEC 62443-3-3 SL assessment + the audit package described in [Templates](#templates) |
| **s26** | Incident notification (6h initial / 72h supplementary / 30-day report) | The IR plan in [Pillar 4](#basic-start/pillar-incident-response-planning) bakes this in |

The full mapping (every SR ↔ every relevant NACSA section) is in [`cross-references/iec62443-to-nacsa.json`](#reference/nacsa).

### NCII sectors in Malaysia

There are 11 NCII sectors under Act 854. Six are OT-heavy and covered in this repo: Energy, Water, Oil & Gas, Transport, Manufacturing, Building Automation. Each has a sector lead (e.g., Energy Commission, SPAN for water, PETRONAS for oil & gas). Sector-specific obligations live in [Sectors](#framework/sectors).

## How the two frameworks fit together

- IEC 62443 is the **engineering standard** — what you actually build.
- NACSA Act 854 is the **legal mandate** — what you must do, by when, and to whom you must report.

For NCII operators in Malaysia, the practical path is: **adopt IEC 62443 as the engineering basis, document everything against the NACSA section it satisfies.** That's the structure this repo enforces in every cross-reference file.

## What's next

Move on to the [checkpoint](#learn/lesson:t1-orientation:05-checkpoint). Eight questions. If you can answer them without looking, T1 is complete.
