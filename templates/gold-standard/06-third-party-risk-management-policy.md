# Third-Party Risk Management (TPRM) Policy

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be reviewed and customized by a qualified cybersecurity professional before formal adoption.
> **Classification:** Internal Use Only (Confidential)

## Document Control
| Field | Details |
| :--- | :--- |
| **Document Owner** | Vendor Risk Manager / CISO |
| **Approver** | Board of Directors / CEO |
| **Version** | 1.0 |
| **Last Reviewed** | [Date] |
| **Next Review Due** | [Date + 1 Year] |

## 1. Regulatory & Standard Alignment
This policy is designed to satisfy the requirements of:
*   **NIST SP 800-161 Rev 1:** Cybersecurity Supply Chain Risk Management (C-SCRM)
*   **BNM RMiT (Nov 2025):** Section 10.46 (Third Party Service Provider System Changes) and Appendix 7 (Cloud)
*   **PDPA (Act 709):** Section 5 (Data Processor Obligations)

## 2. Purpose and Scope
The TPRM Policy establishes the framework for identifying, assessing, mitigating, and monitoring cybersecurity risks introduced by third-party vendors, suppliers, and service providers.
**Scope:** Applies to all external parties providing software, hardware, cloud services, or consulting that requires access to [Organization Name]'s systems or data.

## 3. Vendor Classification
Vendors must be classified based on the criticality of the service and data accessed:
*   **Tier 1 (Critical):** Cloud hosting (AWS/Azure), Core Banking software, MSSP.
*   **Tier 2 (High):** Payroll processors, CRM systems containing personal data.
*   **Tier 3 (Medium/Low):** Marketing analytics, non-integrated office supplies.

## 4. Assessment Requirements
*   **Tier 1 & 2:** Must undergo a formal C-SCRM questionnaire, provide a SOC 2 Type II or ISO 27001 certificate, and be subject to an annual penetration test review before onboarding.
*   **Tier 3:** Must sign the Standard Contractual Clauses (SCC) and Non-Disclosure Agreement (NDA).

## 5. Contractual Obligations
All third-party contracts involving personal data must include:
*   Mandatory 24-hour breach notification clause.
*   "Right to Audit" clause allowing [Organization Name] to inspect the vendor's security controls.
*   Data residency requirement (data must not leave Malaysia without explicit CISO approval).

## 6. Continuous Monitoring
Tier 1 vendors must be monitored continuously using supply chain risk intelligence tools, and must undergo a formal re-assessment annually.
