# SABESB TP4 — OT Security Audit Report (DRAFT)

> Audit firm: ACME Audit Sdn Bhd · Lead auditor: A. Junior · Date: 2026-04-15 · Status: DRAFT

> **Sample data only.** This is a *deliberately flawed* draft audit report — used in T4 to teach the difference between a finding and a complaint, and between a correct citation and a miscited one.

## Audit summary

We performed a five-day audit of SABESB Treatment Plant 4. We reviewed network architecture, remote access, asset inventory, and the incident response plan. We identified the following findings.

---

## Finding 1 — Severity: HIGH

**Observation:** The plant uses Modbus on TCP port 502 with no encryption.

**Criteria:** IEC 62443 SR-4.1 (Confidentiality of information at rest).

**Cause:** Legacy protocol design.

**Effect:** Sensitive process data could be intercepted on the network.

**Recommendation:** Encrypt all Modbus traffic.

---

## Finding 2 — Severity: MEDIUM

**Observation:** The Engineering Workstation (10.20.30.20) has two network interfaces — one connected to the corporate VLAN (10.40.50.0/24) and one connected to the OT VLAN (10.20.30.0/24).

**Criteria:** IEC 62443 SR-5.1 (Network segmentation); NACSA Act 854 s18 (security measures); internal Network Architecture Standard cl. 4.3.

**Cause:** The workstation was configured by the plant during commissioning (2023) to give engineers access to corporate email without leaving the plant floor; configuration was never reviewed.

**Effect:** Direct routable path between corporate and OT networks bypasses the IDMZ. A corporate-side compromise (phishing, ransomware) has a direct path to the OT environment without traversing any security boundary. Identical pattern to Ukraine 2015 (corporate AD → OT pivot).

**Recommendation:** Remove the corporate-side NIC. Require engineering staff to access OT only via an IDMZ-hosted jump server. Move the workstation behind the OT-side firewall.

**Rating justification:** MEDIUM — direct path exists but no evidence of exploitation.

---

## Finding 3 — Severity: LOW

**Observation:** The plant uses corporate WiFi (WPA2-PSK) for tablets on the plant floor.

**Criteria:** IEC 62443 SR-1.6 (Wireless authentication and integrity).

**Cause:** Convenience; cost.

**Effect:** Wireless credentials shared among plant staff; if compromised, anyone in WiFi range could potentially join the corporate network.

**Recommendation:** Move to WPA3-Enterprise with per-device authentication.

---

## Finding 4 — Severity: LOW

**Observation:** The Remote Access Policy (SABESB-TP4-POL-007) does not require session recording for vendor remote sessions.

**Criteria:** Internal Remote Access Policy v1.0 cl. 4.4.

**Cause:** Privacy concerns cited.

**Effect:** No forensic record of what vendors do during remote sessions.

**Recommendation:** Enable session recording.

---

## Finding 5 — Severity: HIGH

**Observation:** The plant does not have a documented Cyber Incident Response Plan.

**Criteria:** Best practice; ISO 27001.

**Cause:** Resource constraints.

**Effect:** Unable to respond effectively to a cyber incident.

**Recommendation:** Develop a Cyber Incident Response Plan.

---

## Closing

We thank the SABESB team for their cooperation. Findings will be tracked through the standard remediation process.

*— Draft prepared by A. Junior, ACME Audit Sdn Bhd*

---

> **Reader exercise:** Read this report carefully. Two findings are *correct*. Two are *miscited* (right observation, wrong criteria or wrong rating). One major finding is *missing entirely*. Identify which is which before reading the answer key.
