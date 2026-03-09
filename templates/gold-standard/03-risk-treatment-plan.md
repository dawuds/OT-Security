# Risk Treatment Plan (RTP)

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be reviewed and customized by a qualified cybersecurity professional before formal adoption.
> **Classification:** Internal Use Only (Confidential)

## Document Control
| Field | Details |
| :--- | :--- |
| **Document Owner** | Chief Information Security Officer (CISO) |
| **Approver** | Board Risk Committee |
| **Version** | 1.0 |
| **Last Reviewed** | [Date] |
| **Next Review Due** | [Date + 6 Months] |

## 1. Regulatory & Standard Alignment
This plan is designed to satisfy the requirements of:
*   **ISO/IEC 27005:2022:** Information Security Risk Management
*   **BNM RMiT (Nov 2025):** Section 9 (Technology Risk Management Framework)
*   **Malaysia Act 854:** P.U.(A) 219/2024 (Risk Assessment and Audit Regulations)

## 2. Purpose and Scope
The Risk Treatment Plan (RTP) documents the decisions, actions, and timelines required to manage unacceptable information security and technology risks down to an acceptable level, in accordance with the Board-approved Risk Appetite.

## 3. Executive Summary
*   **Total Risks Assessed:** [Number]
*   **Critical/High Risks Requiring Treatment:** [Number]
*   **Risks Accepted (Exception):** [Number]

## 4. Risk Treatment Schedule

| Risk ID | Risk Description | Inherent Risk (5x5) | Treatment Strategy | Planned Actions (Controls) | Owner | Target Date | Residual Risk (5x5) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RSK-001** | Legacy core system lacking MFA support | Critical (20) | Mitigate | Implement PAM jump-server with MFA enforcement before accessing legacy system. | IT Ops | Q3 2026 | Medium (8) | In Progress |
| **RSK-002** | DDoS attack against public banking portal | High (15) | Transfer / Mitigate | Procure Cloud WAF and DDoS scrubbing service from tier-1 provider. | Network Sec | Q2 2026 | Low (4) | Planned |
| **RSK-003** | Use of end-of-life Windows 10 for ATM backend | Critical (25) | Avoid | Upgrade all ATM OS to supported Windows 11 LTSC version. | ATM Sec | Q4 2026 | Low (3) | Budget Approved |

## 5. Risk Acceptance (Exceptions)
Risks that cannot be mitigated within the standard timeline and remain above the tolerance threshold must be formally accepted.

| Risk ID | Risk Description | Justification for Acceptance | Compensating Controls | Accepted By | Expiry Date |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RSK-004** | Mainframe OS unsupported | Migration project requires 18 months. | Total network isolation; manual monitoring. | CEO / Board | Q4 2027 |

## 6. Monitoring and Review
The CISO will present progress against this RTP to the Board Risk Committee on a quarterly basis. Any delays in "Critical" risk treatments require immediate escalation.
