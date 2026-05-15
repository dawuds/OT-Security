# Find the IDMZ gap

> **Tier 2 / Lesson 4 — 45 minutes.** Walk an existing network diagram. List every IT-to-OT path that bypasses the IDMZ.

## The audit question

> *"Show me the IDMZ. Now show me every path between Level 4+ and Level 0–3 that does not transit through it."*

If the answer to the first half is "we don't have one" or "it's just a VLAN", that is the entire finding. Stop the assessment, file the gap, and move to remediation planning.

If the IDMZ exists, the second half is where most environments fail. Common gaps:

| Pattern | Why it's a gap | What "right" looks like |
|---|---|---|
| Engineering workstation with dual NIC (corp + OT) | The workstation IS a routing path | Workstation in OT, accessed via IDMZ jump server |
| Vendor remote-access VPN terminating directly on a PLC subnet | The protocol break is missing | VPN to IDMZ jump host; new session from there to PLC |
| Historian replicating to corporate via TCP from Level 3 | Bidirectional path | Historian replication via data diode through IDMZ |
| Patch server reachable from corporate AD | If corp AD compromise → patch server compromise → OT poisoning | Patch server is IDMZ-only; manual approval to push |
| AnyDesk / TeamViewer / RDP exposed on plant devices | Outbound dial-out bypasses everything | Block outbound from OT; jump server only |
| WiFi access point bridging corp SSID and OT VLAN | Wireless is a Layer 1 conduit | OT WiFi on dedicated controller, separate VLAN |
| Shared Active Directory (corp AD = OT AD) | Single credential gives access to both | Separate OT directory or one-way trust |

Each row in this table is a real finding from a real audit.

## How to walk the diagram

For each Level 4+ device, ask: "If I am this device and I open a TCP connection to a Level 1 PLC IP, what stops me?"

- If the answer is "the firewall" — name the firewall and the rule.
- If the answer is "nothing" — that is your finding.
- If the answer is "the IDMZ" — verify the protocol break is real (separate session from IDMZ jump down to OT, not just a port forward).

## Map findings to controls

For each gap, cite:

- **Requirement** — typically [NS-R2 (IDMZ implementation)](#framework/domain:network-segmentation) or [NS-R3 (DPI filtering)](#framework/domain:network-segmentation)
- **Control** — [Industrial DMZ Implementation](#control/idmz-implementation) or related
- **SR** — typically SR-5.1 or SR-5.2 (see [Framework → SRs](#framework/iec-sr))
- **NACSA section** — usually s18 (Security Measures) or s20 (Incident management capability)

A finding without a citation is an opinion. A finding with a citation is a deliverable.

## Calibration

Use the broken-plant network diagram as practice: [`docs/learn/samples/02-network-diagram.md`](../samples/02-network-diagram.md). Find every IDMZ violation. Compare to the [answer key](../samples/05-answer-key.md). Three core violations plus a WiFi bonus — your eye should land on them in under five minutes for the lesson to stick.

## What's next

[Lesson 5 — Draft a remote-access policy from the template](#learn/lesson:t2-practitioner:05-remote-access-policy). You've found the gap; now produce the policy that closes it.
