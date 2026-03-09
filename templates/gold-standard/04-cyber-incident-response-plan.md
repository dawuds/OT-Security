# Cyber Incident Response Plan (CIRP)

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be reviewed and customized by a qualified cybersecurity professional before formal adoption.
> **Classification:** Internal Use Only (Confidential)

## Document Control
| Field | Details |
| :--- | :--- |
| **Document Owner** | Incident Response Commander / CISO |
| **Approver** | Board of Directors / CEO |
| **Version** | 1.0 |
| **Last Reviewed** | [Date] |
| **Next Review Due** | [Date + 1 Year] |

## 1. Regulatory & Standard Alignment
This plan is designed to satisfy the requirements of:
*   **NIST SP 800-61 Rev 2:** Computer Security Incident Handling Guide
*   **BNM RMiT (Nov 2025):** Section 11 (Cyber Resilience)
*   **Malaysia Act 854:** Section 26 (NCII Incident Notification)
*   **PDPA (Act A1727):** Section 12B (Data Breach Notification)

## 2. Purpose and Scope
The purpose of this CIRP is to provide a structured, systemic approach for responding to and managing cybersecurity incidents. The goal is to minimize damage, reduce recovery time and costs, and ensure compliance with all statutory notification timelines.

## 3. Incident Classification & Notification Thresholds

| Severity Level | Definition | Statutory Notification SLA |
| :--- | :--- | :--- |
| **Critical (Sev-1)** | Complete outage of NCII or Core Banking system. Active ransomware. | NACSA (6 hours) / BNM (2 hours) |
| **High (Sev-2)** | Massive data breach. Major degradation of services. | JPDP (72 hours) |
| **Medium (Sev-3)** | Localized malware infection (contained). Single system outage. | Internal Logging Only |
| **Low (Sev-4)** | Phishing attempt caught by filters. Port scan. | No escalation |

## 4. Roles & Responsibilities (CSIRT)
*   **Incident Commander (CISO):** Overall authority for incident declaration and response strategy.
*   **Technical Lead (SOC Manager):** Directs the technical containment and eradication efforts.
*   **Legal/Compliance Lead:** Manages regulatory notifications (NACSA, BNM, JPDP).
*   **Communications Lead (PR):** Manages internal and external messaging.

## 5. Incident Response Phases (NIST Methodology)
1.  **Preparation:** Continuous training, tool deployment, and playbook updates.
2.  **Detection & Analysis:** Identifying the incident, triaging severity, and preserving initial forensic evidence.
3.  **Containment, Eradication, & Recovery:**
    *   *Short-term Containment:* Isolating affected network segments.
    *   *System Backup:* Creating forensic images before eradication.
    *   *Eradication:* Removing malware, closing vulnerabilities.
    *   *Recovery:* Restoring from known-good backups.
4.  **Post-Incident Activity:** Completing the Post-Incident Report (PIR) and implementing lessons learned.

## 6. Communication Protocols
*   **Out-of-Band (OOB) Comms:** If corporate email/Slack is compromised, the CSIRT will switch to [Signal/WhatsApp/Secure Channel].
*   **Law Enforcement:** The Incident Commander will authorize engagement with PDRM Cyber Crime Division if a criminal act is confirmed.

## 7. Plan Testing
This CIRP must be tested at least annually via a Tabletop Exercise (TTX) involving senior management, and via a technical Red Team exercise as required by RMiT/Act 854.
