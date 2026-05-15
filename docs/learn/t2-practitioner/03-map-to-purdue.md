# Map your assets to the Purdue model

> **Tier 2 / Lesson 3 — 45 minutes.** From asset list → defensible Purdue diagram.

## What you start with

The output of [Lesson 1](#learn/lesson:t2-practitioner:01-passive-discovery-lab) — a list of devices with IP, vendor inferred from MAC OUI, and protocol seen.

## The mapping rules

For each device, decide its level using these heuristics, in order:

1. **Device class** trumps everything else:
   - Sensor / actuator / motor → **Level 0**
   - PLC, RTU, IED, SIS controller → **Level 1**
   - HMI, alarm panel, local display → **Level 2**
   - SCADA server, historian, engineering workstation, OPC server → **Level 3**
   - Patch server, AV relay, jump server, IDMZ historian replica → **Level 3.5 (IDMZ)**
   - Site business app, ERP front-end, time-tracking → **Level 4**
   - Corporate IT, VPN concentrators, internet gateway → **Level 5**

2. **Protocol** is a strong signal when device class is unknown:
   - Modbus / DNP3 / EtherNet-IP / S7Comm / PROFINET → Level 1 or 2
   - OPC-UA, OSIsoft PI polling → Level 3
   - HTTP/RDP from named admin tools → Level 3 (engineering workstation)

3. **Communication partners** confirm the inference. A device only ever talking to a known PLC at Level 1 is itself almost certainly Level 2 (HMI) or Level 3 (engineering workstation). A device talking to both Level 4 and Level 1 is your **smoking gun** — that is a segmentation violation.

## What "good" looks like

A defensible Purdue diagram has, for every device:

- A clear level assignment.
- A documented justification (one line: "PLC running ladder logic; talks Modbus to HMI on Level 2").
- An assigned **target Security Level (SL-T)** based on consequence (defaults: SL-2 for general OT, SL-3 for high-criticality, SL-4 for SIS).

The repo gives you the Purdue model definitions in [`architecture/purdue-model.json`](#reference/purdue) and the SL-by-zone targeting examples in [`sectors/*`](#framework/sectors).

## What "bad" looks like

- "We'll figure out levels later." No — the level *is* the security boundary.
- Devices listed without a justification. If you can't justify, you'll be overruled the first time someone wants to bypass the boundary.
- Engineering workstations with **dual NICs** (one to OT, one to corporate). This is the #1 architectural finding in OT audits. The IDMZ jump server pattern eliminates it.

## The deliverable

Produce a Purdue diagram (any tool — even pen and paper). Annotate every device with **(Level, SL-T)**. Identify and circle every device that:

1. Has dual connectivity (talks across more than one Purdue level by Layer 3 routing, not via IDMZ).
2. Talks an OT protocol but is in a non-OT level.
3. Has no clear classification.

Each circle is a finding for [Lesson 4](#learn/lesson:t2-practitioner:04-find-the-idmz-gap).

## Calibration

If you don't have a real environment to map, use the **broken-plant bundle**: [`docs/learn/samples/01-asset-list.csv`](../samples/01-asset-list.csv) is a 12-row asset list with three deliberate Purdue / segmentation issues. Produce your diagram from that, then check your work against [`docs/learn/samples/05-answer-key.md`](../samples/05-answer-key.md). If your circles match the answer key's three issues plus the SIS-on-BPCS finding, you have the diagnostic eye.

## What's next

[Lesson 4 — Find the IDMZ gap](#learn/lesson:t2-practitioner:04-find-the-idmz-gap).
