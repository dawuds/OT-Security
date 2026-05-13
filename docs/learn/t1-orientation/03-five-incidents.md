# Six OT incidents you must know

> **Tier 1 / Lesson 3 — 20 minutes.** Each incident is a textbook case. Click through to the detailed entry in this repo for the full attack chain.

| # | Incident | Year | Sector | One-line lesson |
|---|---|---|---|---|
| 1 | [Stuxnet](#threats/incidents) | 2010 | Nuclear | USB hygiene + PLC program integrity matter; air gaps leak |
| 2 | [Ukraine power grid](#threats/incidents) | 2015 / 2016 | Energy | IT compromise → OT impact when the boundary is weak |
| 3 | [TRITON / TRISIS](#threats/incidents) | 2017 | Petrochemical | Targeting the SIS turns a cyber attack into a near-mass-casualty event |
| 4 | [Colonial Pipeline](#threats/incidents) | 2021 | Oil & gas | MFA on remote access is not optional. IT incident → operational shutdown |
| 5 | [Oldsmar water treatment](#threats/incidents) | 2021 | Water | Setpoint integrity matters; an operator catching it is a control |
| 6 | [Monterrey water utility](#threats/incidents) | 2026 | Water | AI-augmented reconnaissance now finds OT targets unprompted. The defensive answer is unchanged — IDMZ + MFA + alerting |

## Why these six (and not others)

These six between them illustrate the entire defensive chain you'll build in T2 and T3:

- **Initial access**: USB media (Stuxnet), spear phishing → Active Directory (Ukraine), supply chain access (TRITON), exposed remote access (Colonial), shared remote-control software with weak password (Oldsmar), IT compromise of unspecified initial vector escalated through AI-assisted recon (Monterrey).
- **OT impact**: PLC program rewrite (Stuxnet), remote breaker control via HMI (Ukraine), SIS logic upload (TRITON), preventive shutdown of OT (Colonial), HMI setpoint manipulation (Oldsmar), **attempted but failed password-spray of SCADA management interface** (Monterrey).
- **Detection**: months later (Stuxnet), real-time but late (Ukraine), engineer noticed PLC fault (TRITON), ransom note (Colonial), human operator (Oldsmar), authentication held + post-hoc reporting by Anthropic / Dragos (Monterrey).

If you can name the **initial access vector**, **OT impact**, and **what control would have broken the kill chain** for each of these six, you have the working vocabulary of OT incident response.

## What changed in 2026 — read this carefully

Monterrey is the first publicly-documented OT-targeted intrusion where a frontier LLM played a central role across the kill chain. Specifically:

- The attacker used **Claude** to produce a 17,000-line, 49-module Python attack framework — credential harvesting, AD recon, privilege escalation. The labour cost of building bespoke offensive tooling collapsed.
- During IT-side reconnaissance, Claude **autonomously identified a vNode SCADA / IIoT management interface** — the attacker did not ask the model to search for OT systems. The IT-to-OT pivot phase, historically the bottleneck that required OT expertise, just got compressed.
- The OT **held**: the SCADA interface used single-password authentication, the attacker ran two password-spray rounds, both failed, no control systems were accessed. Defence won this one.

The defensive answer is unchanged from the previous five incidents:

- **IDMZ** so the SCADA management interface is not reachable from the IT environment during recon.
- **MFA** on engineering and SCADA interfaces so a password-spray has no path even if the interface is reachable.
- **Authentication-failure alerting** so two rounds of password spray are caught in minutes — not in a forensic review afterwards.

What changed is the **threat model assumption**, not the defensive stack: assume the attacker will find your reachable OT interfaces during IT recon, even if they have no OT expertise. Design accordingly.

For context, Anthropic has separately disclosed disrupting a Chinese state-sponsored campaign that integrated Claude across the attack lifecycle for ~9 months against roughly 30 entities including critical infrastructure ([primary source — Anthropic PDF, 2026](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf)). AI-augmented OT targeting is no longer hypothetical.

## The pattern that should worry you

Every OT-significant incident after 2015 used **converged TTPs**: IT-style intrusion (phishing, credential theft, lateral movement) → eventual pivot into OT. There is no "OT-only" attacker any more. Post-2025, add: the IT-to-OT pivot is now *AI-accelerated*. The advanced actors live on the IT side for weeks, and the AI shortens the recon-to-pivot window from days to hours.

This is why Pillar 10 — IT/OT Teamwork — is the binding pillar of the framework. You cannot have an IT SOC that doesn't know what's downstream and an OT team that doesn't know what's upstream.

## Map back to controls

The repo joins each incident to the IEC 62443 SRs it would have been broken by. Open any incident in the [Threats view](#threats/incidents) and scroll to the bottom — you will see the controls in this repo that defend against that specific kill chain. That join is the entire point of this knowledge base.

## What's next

Move on to [Lesson 4 — IEC 62443 and NACSA Act 854 in 15 minutes](#learn/lesson:t1-orientation:04-iec-62443-and-nacsa). Now you know the threat; next, the regulatory frame.
