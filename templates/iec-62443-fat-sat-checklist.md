# IEC 62443 Factory/Site Acceptance Test (FAT/SAT) Security Checklist

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be customized by an OT Security Engineer to match the specific IACS architecture and security levels (SL-T).
> **Audit Evidence Reference:** SR-7.7 | IEC 62443-4-1

## 1. System Information
*   **Project Name:**
*   **Asset ID(s):**
*   **Target Security Level (SL-T):** [ ] SL-1 [ ] SL-2 [ ] SL-3 [ ] SL-4

## 2. Security Verification (FAT/SAT)

| Requirement | Test Description | Result | Comments |
| :--- | :--- | :--- | :--- |
| **Identification** | Verify default credentials have been changed on all PLCs/HMIs. | [ ] Pass [ ] Fail | |
| **Segmentation** | Confirm asset is placed in the correct network zone as per topology. | [ ] Pass [ ] Fail | |
| **Least Service** | Verify all unused ports and services (HTTP, Telnet, etc.) are disabled. | [ ] Pass [ ] Fail | |
| **Logging** | Confirm system logs are being forwarded to the centralized syslog server. | [ ] Pass [ ] Fail | |
| **Malware Prot.** | Verify application whitelisting is active and in 'Enforce' mode. | [ ] Pass [ ] Fail | |

## 3. Physical Security
*   **Tamper Evidence:** Have physical security seals been applied to cabinet/device? [ ] Yes [ ] No
*   **Port Lockdown:** Are all unused physical USB/Ethernet ports physically blocked? [ ] Yes [ ] No

## 4. Sign-off
**Commissioning Engineer:**
**OT Security Validator:**
**Date:**
