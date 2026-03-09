# Statement of Applicability (SoA) - ISO/IEC 27001:2022

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be reviewed and customized by a qualified cybersecurity professional before formal adoption.
> **Classification:** Internal Use Only (Confidential)

## Document Control
| Field | Details |
| :--- | :--- |
| **Document Owner** | Chief Information Security Officer (CISO) |
| **Approver** | Board of Directors / CEO |
| **Version** | 1.0 |
| **Last Reviewed** | [Date] |
| **Next Review Due** | [Date + 1 Year] |

## 1. Purpose and Scope
This Statement of Applicability (SoA) fulfills the requirement of **ISO/IEC 27001:2022 Clause 6.1.3(d)**. It defines which of the 93 Annex A controls are applicable to [Organization Name]'s Information Security Management System (ISMS), the justification for their inclusion or exclusion, and their current implementation status.
**Scope:** [Define the boundaries of the ISMS, e.g., "All IT operations supporting the core banking platform in the Kuala Lumpur data centre."]

## 2. Regulatory & Standard Alignment
This SoA maps the ISO 27001 Annex A controls to the following local regulatory requirements:
*   **BNM RMiT (Nov 2025):** Appendix 1 (Minimum IT Security Requirements)
*   **Malaysia Act 854:** NCII Sectoral Codes of Practice
*   **PDPA (Act 709):** Security Principle (s9)

## 3. Annex A Controls Assessment

| Control ID | Control Name | Applicable? | Justification | Implementation Status | Related Policy / Procedure |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A.5.1** | Policies for information security | Yes | Required to establish ISMS baseline. | Fully Implemented | Master ISP |
| **A.5.15** | Access control | Yes | RMiT 10.51 and PDPA s9 requirement. | Fully Implemented | IAM Policy |
| **A.5.23** | Information security for use of cloud services | Yes | Organization utilizes SaaS and IaaS providers. | Partially Implemented (Awaiting SRM updates) | Cloud Security Policy |
| **A.8.1** | User endpoint devices | Yes | All employees are issued company laptops. | Fully Implemented | Endpoint Security Standard |
| **A.8.12** | Data leakage prevention | Yes | Required by BNM RMiT for critical data. | Fully Implemented | DLP Policy |
| **A.8.24** | Use of cryptography | Yes | PDPA and RMiT requirement for data at rest/transit. | Fully Implemented | Cryptographic Standard |
| **A.8.31** | Separation of development, testing and production environments | Yes | RMiT 10.7 requirement. | Fully Implemented | SDLC Standard |
| **A.8.34** | Protection of information systems during audit testing | No | We do not allow audit tools to be run against production systems. | Excluded | N/A |

## 4. Exception Management
Any changes to the applicability of controls listed in this document must be approved through the formal Risk Acceptance process and updated in the next revision of this SoA.

## 5. Approval
The controls selected in this SoA have been reviewed and approved as appropriate to mitigate the risks identified in the Information Security Risk Assessment.
