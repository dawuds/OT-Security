# Lab — Passive asset discovery from PCAP

> **Tier 2 / Lesson 1 — 60 minutes.** Hands-on. You will produce an asset list without ever touching the OT network.

## Why this tier exists — what a week buys you

> One week of T2 buys you the right to be the *first responder* in an OT environment. After T1 you can talk about OT; after T2 you can *do* OT, safely. You will leave with five physical artefacts a plant manager will accept: a passive asset inventory, a Purdue diagram, an IDMZ gap analysis, a customised remote-access policy draft, and a captured PCAP that proves you can hold the tooling. These are exactly the deliverables a junior OT security engineer is asked to produce in their first 90 days. By the end of T2, you can produce them in a week.

## Why this is the first lab

You cannot protect what you cannot see. In OT, "see" means "infer from passive observation". This lab is a small, self-contained version of what Dragos / Claroty / Nozomi do continuously in production environments.

## What you'll need

- Python 3.10+
- A PCAP capture containing OT protocol traffic. If you don't have one, the [Modbus honeypot lab](#learn/lesson:t2-practitioner:02-modbus-honeypot-lab) generates one.
- The repo's [`tools/pcap-analyzer.py`](../../../tools/pcap-analyzer.py) and [`tools/requirements-pcap.txt`](../../../tools/requirements-pcap.txt).

## Setup

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r tools/requirements-pcap.txt
```

## Run it

```
python3 tools/pcap-analyzer.py path/to/capture.pcap
```

You should see one row per source IP, with detected protocol, vendor inferred from MAC OUI, and a guess at the device type.

## Read what came back

For each device, you should be able to fill in this table:

| IP | MAC OUI vendor | Protocol seen | Likely Purdue level | Likely device type |
|---|---|---|---|---|
| | | | | |

The Purdue level isn't in the packets — it's an inference:

- Modbus TCP / DNP3 / EtherNet/IP / S7Comm seen → **Level 1 or 2**
- HTTP / RDP to engineering workstations → **Level 3**
- Historian polling traffic (OPC-UA, OSIsoft PI) → **Level 3 ↔ 3.5**

## What "good" looks like

Compare what you produced to the requirements in [Asset Inventory and Management](#framework/domain:asset-inventory). The first requirement (AI-R1) demands "passive discovery + ongoing maintenance". You've now done the discovery half — manually, on a sample. In production this is continuous.

## What "bad" looks like

If your team has been running Nessus or `nmap -sV` against the OT network, that's a finding for an audit, not a security control. Map this to:

- [SR-7.8 (Asset inventory)](#framework/iec-sr) — passive only
- [Asset Inventory domain](#framework/domain:asset-inventory) — AI-R1, AI-R2

## What's next

Move on to [Lesson 2 — Modbus honeypot](#learn/lesson:t2-practitioner:02-modbus-honeypot-lab). Now that you've seen what real traffic looks like, simulate what an attacker probing your network would see.
