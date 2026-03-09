# Business Continuity Plan (BCP)

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be reviewed and customized by a qualified Business Continuity professional before formal adoption.
> **Classification:** Internal Use Only (Confidential)

## Document Control
| Field | Details |
| :--- | :--- |
| **Document Owner** | Business Continuity Manager |
| **Approver** | Board of Directors / CEO |
| **Version** | 1.0 |
| **Last Reviewed** | [Date] |
| **Next Review Due** | [Date + 1 Year] |

## 1. Regulatory & Standard Alignment
This plan is designed to satisfy the requirements of:
*   **ISO 22301:2019:** Security and resilience — Business continuity management systems
*   **BNM RMiT (Nov 2025):** Section 10.35 (Service Interruption Response)
*   **Malaysia Act 854:** NCII Resilience requirements

## 2. Purpose and Scope
The purpose of this BCP is to ensure that [Organization Name] can continue to operate essential business functions during and after a disruptive event, such as a cyberattack, natural disaster, or physical facility loss.
**Scope:** Covers all critical business functions, IT services, and personnel located at [Headquarters/Locations].

## 3. Recovery Objectives (BIA Results)
Based on the latest Business Impact Analysis (BIA), the following critical services must be restored within these parameters:

| Critical Business Function | Maximum Tolerable Period of Disruption (MTPD) | Recovery Time Objective (RTO) | Recovery Point Objective (RPO) |
| :--- | :--- | :--- | :--- |
| **Core Banking System** | 4 Hours | 2 Hours | 15 Minutes |
| **NCII SCADA Operations** | 1 Hour | 30 Minutes | 0 Minutes (Real-time) |
| **Customer Support Portal** | 24 Hours | 12 Hours | 4 Hours |

## 4. Disaster Declaration & Invocation
A disaster may be declared by the **Crisis Management Team (CMT) Leader** if an event is expected to exceed the RTO of any critical business function.
*   **Invocation Trigger:** Physical site loss, massive IT failure (e.g., Ransomware), or severe staffing shortage.
*   **Assembly Point:** [Primary Virtual Bridge / Alternate Physical Site]

## 5. Recovery Strategies
*   **Data Centre Loss:** Failover to Disaster Recovery (DR) site located in [Secondary Location] via automated routing within [X] hours.
*   **Cyber Incident (Ransomware):** Sever network connections, initiate "Clean Room" restore from immutable backups.
*   **Workplace Unavailability:** 100% remote work activation via secure VPN for non-essential staff; critical staff to alternate site.

## 6. Testing and Maintenance
The BCP will be tested at least annually via full-scale DR failover simulation. Test results, including achieved RTO/RPO vs. target RTO/RPO, must be reported to the Board.
