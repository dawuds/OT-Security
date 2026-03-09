# Worked Example: IEC 62443 FAT Security Test (Substation PLC)

> **AI Disclaimer:** This is a **SAMPLE** completed test record for educational purposes. It follows IEC 62443-4-1 requirements.
> **Audit Evidence Reference:** SR-7.7 | System Commissioning

## 1. Test Details
*   **Project:** Substation Automation Phase 2
*   **Asset ID:** PLC-ZONE-B-01 (Siemens S7-1500)
*   **Target SL:** SL-2

## 2. Test Execution

| Requirement | Test Method | Result | Evidence |
| :--- | :--- | :--- | :--- |
| **SR 1.1** | Change default 'admin' password to unique complexity-compliant string. | PASS | Hash verified |
| **SR 5.1** | Verify PLC is isolated from the corporate VLAN via the IDMZ firewall. | PASS | Rule 102 active |
| **SR 7.7** | Disable unused ports: HTTP (80), Telnet (23), SNMP (161). | PASS | Nmap scan result |
| **SR 2.1** | Configure RBAC: 'Operator' role limited to Read-Only values. | PASS | Log verify |

## 3. Findings
*   **Observation:** Firmware version was one version behind baseline.
*   **Action:** Updated firmware to v2.9.4 during test window.

---
**Tested By:** Mike Tan (Commissioning Lead)
**Verified By:** Sarah Wong (OT Security)
**Date:** 2026-03-08
