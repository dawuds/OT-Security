# Identity & Access Management (IAM) Policy

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be reviewed and customized by a qualified cybersecurity professional before formal adoption.
> **Classification:** Internal Use Only (Confidential)

## Document Control
| Field | Details |
| :--- | :--- |
| **Document Owner** | Head of Identity & Access Management |
| **Approver** | Chief Information Security Officer (CISO) |
| **Version** | 1.0 |
| **Last Reviewed** | [Date] |
| **Next Review Due** | [Date + 1 Year] |

## 1. Regulatory & Standard Alignment
This policy is designed to satisfy the requirements of:
*   **CIS Controls v8:** Control 5 (Account Management) and Control 6 (Access Control Management)
*   **BNM RMiT (Nov 2025):** Section 10.51 (Access Control Policy), 10.55 (MFA)
*   **ISO/IEC 27001:2022:** A.5.15 (Access Control), A.5.16 (Identity Management)

## 2. Purpose and Scope
The purpose of this IAM Policy is to establish the rules for creating, managing, reviewing, and revoking user and system identities and their access privileges. 
**Scope:** Applies to all user accounts (employees, contractors, vendors), privileged accounts, and non-human identities (service accounts, API keys) across all [Organization Name] systems.

## 3. Account Provisioning & Lifecycle
1.  **Identity Verification:** All users must have their identity verified by Human Resources (for employees) or Procurement (for vendors) before an account is provisioned.
2.  **Unique Identifiers:** Every user must be assigned a unique, non-shared User ID. Shared/generic accounts are strictly prohibited unless formally approved as an exception for a technical necessity.
3.  **Deprovisioning (Termination):** 
    *   Voluntary Resignation: Access must be revoked by 5:00 PM on the final day.
    *   Involuntary Termination: Access must be revoked *prior* to the termination meeting.

## 4. Access Authorization (Least Privilege & RBAC)
*   **Default Deny:** All access is denied by default.
*   **Role-Based Access Control (RBAC):** Access rights must be granted based on the user's defined job role, not individual preference.
*   **Least Privilege:** Users will only be granted the minimum level of access required to perform their duties.

## 5. Authentication & Passwords
*   **Multi-Factor Authentication (MFA):** MFA is mandatory for:
    *   All remote access (VPN, Cloud Services).
    *   All privileged access (Administrators, Root).
    *   All access to systems containing C3 (Confidential) or C4 (Restricted) data.
*   **Password Complexity:** Minimum 12 characters, requiring a mix of alphanumeric and special characters, checked against known compromised password lists.

## 6. Privileged Access Management (PAM)
Privileged accounts (e.g., Domain Admins, root, sysadmin) pose the highest risk and require stringent controls:
1.  Privileged accounts must be distinct from the user's daily standard account (e.g., `admin-jdoe` vs. `jdoe`).
2.  Privileged access must be brokered through a centralized PAM vault that records sessions and rotates credentials after use.

## 7. Access Reviews (Recertification)
To prevent "privilege creep", access rights must be formally reviewed and certified by the respective Business Owners:
*   **Standard Access:** Reviewed annually.
*   **Privileged / High-Risk Access:** Reviewed quarterly.
*   **Third-Party Access:** Reviewed semi-annually.
Any access not actively approved during the review cycle will be automatically revoked.

## 8. Enforcement & Non-Compliance
Circumventing IAM controls, sharing passwords, or failing to complete access reviews on time constitutes a policy violation subject to disciplinary action.
