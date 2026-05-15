# SABESB TP4 — Answer Key

> Read this **after** working through `01`–`04`. Otherwise it's a study guide, not a calibration anchor.

---

## 01 — Asset list issues

Three deliberate issues in the 12-row asset list:

### Issue 1 — Engineering workstation `10.20.30.20` has dual NIC

This is the canonical OT segmentation finding. The workstation has both `10.40.50.0/24` (corporate) and `10.20.30.0/24` (OT) interfaces and accepts RDP from corporate hosts. There is no IDMZ between them — the workstation IS the routing path.

- **Failing:** SR-5.1 (Network segmentation); SR-5.2 (Zone boundary protection).
- **Severity:** **HIGH** (or **CRITICAL** depending on rating methodology).
- **Map to:** [NS-R2 (Industrial DMZ)](#framework/domain:network-segmentation), [Ukraine 2015 incident](#threats/incidents).

### Issue 2 — SIS controller `10.20.30.30` on the same VLAN as BPCS

The Siemens device is documented as a Safety Instrumented System controller but sits in the same `10.20.30.0/24` VLAN as the Reactor PLC and Pump PLC (BPCS). The cardinal rule from T1 lesson 2 is violated: SIS and BPCS must be physically and logically isolated.

- **Failing:** SR-3.6 (Deterministic output); IEC 61511 (SIS lifecycle management).
- **Severity:** **HIGH** (safety-significant).
- **Map to:** [Safety System Security domain](#framework/domain:safety-system-security), [TRITON 2017 incident](#threats/incidents).

### Issue 3 — Anomalous Modbus from outside the plant subnet (`10.99.99.5`)

A device with `unknown` MAC OUI is observed sending an inbound Modbus packet from outside the plant subnet to OT. This is either (a) a scanning probe from a compromised IT host, (b) an unauthorised device on the network, or (c) a recon attempt indicative of a Monterrey-style AI-augmented enumeration. The "flagged for review" note tells you the discovery happened — the *response* did not.

- **Failing:** SR-6.1 (Audit log generation), SR-6.2 (Centralised logging) — alerting failed; the row exists in the inventory but no one acted on it.
- **Severity:** **MEDIUM** (potential indicator of compromise).
- **Map to:** [Monitoring and Logging domain](#framework/domain:monitoring-logging), [Monterrey 2026 incident](#threats/incidents).

A junior auditor finds 1. A senior auditor finds 2 and cites Ukraine. An OT-fluent auditor finds all three and ties #3 to Monterrey.

---

## 02 — Network diagram IDMZ violations

Three deliberate IDMZ violations:

### Violation 1 — No IDMZ exists

There is *no* IDMZ in the diagram. The single Cisco firewall does corporate boundary; OT sits behind nothing more than VLAN separation. The phrase "we use the corporate firewall as the boundary" is the entire failure.

- **Failing:** SR-5.1; **NACSA Act 854 s18**; IEC 62443-3-2 zone definition entirely.
- **Severity:** **CRITICAL** — this is the architectural finding.

### Violation 2 — Engineering workstation dual NIC (same as Asset Issue 1)

Confirmed in the diagram by the dual connection to corporate VLAN and OT VLAN.

### Violation 3 — Vendor laptop with HTTPS egress AND RDP into OT

`10.30.40.5` reaches both the internet (HTTPS) and the OT engineering workstation (RDP). No IDMZ jump pattern. No protocol break. The vendor's compromised laptop is a direct route to OT regardless of whether the vendor is malicious.

- **Failing:** SR-1.13 (Access via untrusted networks); IDMZ pattern broken.
- **Severity:** **HIGH**.
- **Map to:** [Remote Access domain](#framework/domain:remote-access), [Colonial Pipeline 2021 incident](#threats/incidents).

Plus one bonus finding for the keen eye: **WiFi**. Corporate WPA2-PSK shared SSID covering the plant floor is a wireless conduit with no zone enforcement and no per-device auth. SR-1.6 violation. **HIGH** for any safety-significant plant.

---

## 03 — Remote-access policy failures

Six things wrong with this policy. A T2 learner who drafted a policy from the IAM gold-standard template should have found at least four; a T4 auditor should find all six.

### 1. No mention of an IDMZ jump server (Section 3.3 fails the protocol break)

"Once authenticated to the corporate network, users may access OT systems through the engineering workstation using the standard RDP client" — this is the protocol break violated explicitly. The user's session terminates on a Level 2/3 OT host, not on an IDMZ jump server. *NS-R2 violation.*

### 2. MFA only on VPN, not on engineering interface (Section 3.2)

Once on the corporate VPN, no further MFA is required to RDP into OT. Single password-spray opportunity all the way to the engineering workstation. *Monterrey class.*

### 3. Vendor accounts are "standard user" (Section 4.2)

No JIT (just-in-time) provisioning; no per-vendor scope; no time-bounded sessions. A vendor that needs 2 hours of access in March still has access in November. *RA-R3 / Pillar 6 (Secure Remote Access) violation.*

### 4. Vendor session recording explicitly disabled (Section 4.4)

"Privacy considerations" is not a defensible justification for refusing to record vendor sessions on safety-significant infrastructure. The vendor signed an NDA — they consented to the relationship. Session recording is a control, not surveillance. *Direct conflict with audit evidence requirements.*

### 5. TeamViewer + AnyDesk both listed as approved tools (Section 6.1)

These are the *exact* tools the policy should ban. Outbound dial-out from OT eliminates every layered defence between the OT host and the internet. **Oldsmar 2021** went down through TeamViewer. AnyDesk being labelled "legacy use" without an explicit retirement date means it is *current use*.

### 6. Annual review cadence (header)

Approved 2026-01-01, reviewed 2027-01-01. For a safety-significant plant with active OT threat activity, annual review is too slow. Compare to the firewall rule 90-day review cycle in [Pillar S](#learn/lesson:t3-programme:03b-pillar-s-network-architecture).

The policy "looks compliant" because it has the right *structure* (purpose, scope, sections). It fails because it codifies the wrong defaults.

---

## 04 — Audit report grading

Five findings in the fake report. Here's how a senior auditor would grade them:

### Finding 1 — Modbus encryption — **WRONG (miscited)**

**The observation is technically true** — Modbus has no encryption. But the *finding is meaningless in context*:

- Modbus encryption is not a realistic control. The protocol has been unencrypted since 1979; the defence is the *network* (segmentation, DPI), not the protocol. See [OT protocols primer](#learn/lesson:t1-orientation:04b-ot-protocols).
- SR-4.1 is about confidentiality of data at rest — not the right criterion for protocol-in-transit. The right citation would be SR-4.2 (Confidentiality of information in transit), and even that is a low priority because the threat in OT is integrity, not confidentiality.
- Severity HIGH is wildly inflated. There is no realistic exploitation path that depends on Modbus payloads being unencrypted *that isn't already worse via the SR-5.1 violation in Finding 2*.

**Fix:** Withdraw or downgrade to LOW informational. Rewrite the criterion. Note that segmentation (Finding 2) is the substantive control, not protocol encryption.

### Finding 2 — Dual-NIC engineering workstation — **CORRECT**

This is the audit's strongest finding. Observation is factual; criteria are properly cited (SR-5.1, NACSA s18, internal standard); cause names a specific commissioning date; effect explicitly references Ukraine 2015 by name; recommendation is implementable.

**Only weakness:** The *severity is too low*. MEDIUM understates a direct routable IT-to-OT path. A senior auditor would rate this **HIGH** or **CRITICAL** depending on methodology — "no evidence of exploitation" is not a mitigating factor when the path itself is the finding.

### Finding 3 — WiFi — **CORRECT (but undersold)**

Observation correct, criteria correct, severity reasonable for a non-safety plant. For SABESB (water utility — safety-significant for public health), severity should be **MEDIUM** or **HIGH**, not LOW.

### Finding 4 — No vendor session recording — **MISCITED**

The observation is correct, but citing only the *internal policy clause* is too narrow. The right citation includes IEC 62443 SR-2.8 (Auditable events), SR-2.9 (Audit storage capacity), and the broader [Remote Access domain](#framework/domain:remote-access). The internal policy clause is the *symptom*; the standard is the *criterion*.

**Severity LOW is also wrong.** No forensic record of vendor activity on safety-significant infrastructure should be at minimum MEDIUM. After the next incident, this finding will retroactively be HIGH.

### Finding 5 — No IRP — **WRONG (criteria) AND MISSING (sub-finding)**

Observation may be correct; the criteria are wrong:

- "Best practice; ISO 27001" is not a citation an auditor signs their name to. The right citation: **NACSA Act 854 s20 (incident management capability)**, plus IEC 62443 SR-6.1 / SR-6.2 / SR-3.1.
- For a Malaysian NCII operator, no IRP is also a likely **NACSA s23 audit failure** in its own right.

**Missing sub-finding:** even if there is no IRP, the audit should *explicitly* cite that there is consequently no NACSA s26 notification readiness — that is the regulatory time-bomb. The fake report's omission of s26 is itself a finding.

### THE MISSING FINDING

**The fake report does not mention the SIS controller on the same VLAN as the BPCS.** This is the asset-list Issue 2 — a safety-significant finding that an OT-fluent auditor would rate as HIGH or CRITICAL on day one. The fake report's silence on it suggests A. Junior either did not do an asset walk-through or did not recognise the implication.

This is the single most important learning from the audit-grading exercise: **the absence of a finding is itself a finding**.

---

## Calibration summary

| Tier | What you should produce vs the bundle |
|---|---|
| T2 | Your asset list should *find* Issues 1, 2, 3. Your IDMZ gap analysis should *find* Violations 1, 2, 3 + WiFi. Your remote-access policy should *avoid* every flaw in `03`. |
| T3 | Your Pillar A plan should produce a register that catches Issue 3. Your Pillar S plan should design the IDMZ that closes Violations 1, 2, 3. Your Pillar I plan should respond to the Issue 3 alert in minutes, not in a forensic review. |
| T4 | Your audit report should grade the fake report findings as above (CORRECT / MISCITED / WRONG / MISSING) and add the SIS-on-BPCS finding the fake report missed. |

If you produce all of the above, T2/T3/T4 are passed. If your work merely *resembles* the bundle (matches its flaws), you missed the point.
