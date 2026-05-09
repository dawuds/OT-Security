# Five OT incidents you must know

> **Tier 1 / Lesson 3 — 15 minutes.** Each incident is a textbook case. Click through to the detailed entry in this repo for the full attack chain.

| # | Incident | Year | Sector | One-line lesson |
|---|---|---|---|---|
| 1 | [Stuxnet](#threats/incidents) | 2010 | Nuclear | USB hygiene + PLC program integrity matter; air gaps leak |
| 2 | [Ukraine power grid](#threats/incidents) | 2015 / 2016 | Energy | IT compromise → OT impact when the boundary is weak |
| 3 | [TRITON / TRISIS](#threats/incidents) | 2017 | Petrochemical | Targeting the SIS turns a cyber attack into a near-mass-casualty event |
| 4 | [Colonial Pipeline](#threats/incidents) | 2021 | Oil & gas | MFA on remote access is not optional. IT incident → operational shutdown |
| 5 | [Oldsmar water treatment](#threats/incidents) | 2021 | Water | Setpoint integrity matters; an operator catching it is a control |

## Why these five (and not others)

These five between them illustrate the entire defensive chain you'll build in T2 and T3:

- **Initial access**: USB media (Stuxnet), spear phishing → Active Directory (Ukraine), supply chain access (TRITON), exposed remote access (Colonial), shared remote control software with weak password (Oldsmar).
- **OT impact**: PLC program rewrite (Stuxnet), remote breaker control via HMI (Ukraine), SIS logic upload (TRITON), preventive shutdown of OT (Colonial), HMI setpoint manipulation (Oldsmar).
- **Detection**: months later (Stuxnet), real-time but late (Ukraine), engineer noticed PLC fault (TRITON), ransom note (Colonial), human operator (Oldsmar).

If you can name the **initial access vector**, **OT impact**, and **what control would have broken the kill chain** for each of these five, you have the working vocabulary of OT incident response.

## The pattern that should worry you

Every incident after 2015 used **converged TTPs**: IT-style intrusion (phishing, credential theft, lateral movement) → eventual pivot into OT. There is no "OT-only" attacker any more. The advanced ones live on the IT side for weeks before touching anything industrial. This is why Pillar 10 — IT/OT Teamwork — is the binding pillar of the framework. You cannot have an IT SOC that doesn't know what's downstream and an OT team that doesn't know what's upstream.

## Map back to controls

The repo joins each incident to the IEC 62443 SRs it would have been broken by. Open any incident in the [Threats view](#threats/incidents) and scroll to the bottom — you will see the controls in this repo that defend against that specific kill chain. That join is the entire point of this knowledge base.

## What's next

Move on to [Lesson 4 — IEC 62443 and NACSA Act 854 in 15 minutes](#learn/lesson:t1-orientation:04-iec-62443-and-nacsa). Now you know the threat; next, the regulatory frame.
