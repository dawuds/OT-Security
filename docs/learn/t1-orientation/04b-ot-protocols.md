# OT protocols on the wire (the 15-minute primer)

> **Tier 1 / Lesson 4b — 15 minutes.** The bridge between "Purdue Level 1 talks Modbus" (which you now know) and the T2 PCAP lab (which assumes you know what Modbus *looks* like). If you skip this, T2 lesson 1 will feel like reading a foreign language.

## Four protocols cover ~80% of what you will see

| Protocol | Default port | Purdue level | Where you'll meet it |
|---|---|---|---|
| **Modbus TCP** | 502/tcp | 1 ↔ 2 | Manufacturing, water, building automation, generic PLCs |
| **DNP3** | 20000/tcp (or serial) | 1 ↔ 2/3 | Electric utilities, especially North America |
| **EtherNet/IP (CIP)** | 44818/tcp + 2222/udp | 1 ↔ 2 | Rockwell / Allen-Bradley plants — heavy in US manufacturing |
| **S7Comm / S7Comm-Plus** | 102/tcp (ISO-TSAP) | 1 ↔ 2 | Siemens plants — heavy in Europe and process industries |

You will see other protocols (PROFINET, IEC 61850, BACnet, OPC-UA, Modbus-RTU over serial), but if you can read a Modbus and an S7 capture, you can read the rest.

## The thing every OT protocol has in common

**No authentication. No encryption. No integrity check.**

These protocols were designed in the 1970s–1990s for a world where:

- The PLC sat on a serial cable in a locked cabinet.
- "The network" was the room.
- Security was a padlock.

When someone bridged the serial bus to TCP/IP in the 1990s — usually with a Moxa-style serial-to-Ethernet converter — the protocol came along unchanged. **A modern Modbus-TCP packet has no more security than a 1979 Modbus-RTU frame on RS-485.**

This is the whole reason the IDMZ exists. The protocol is not going to defend itself. The network has to.

## Read vs write — the only function-code distinction that matters today

Modbus has ~20 function codes. For the security conversation, you need two categories:

| Category | Modbus function codes | Operational meaning |
|---|---|---|
| **Read** | 01, 02, 03, 04 (read coils / discrete inputs / holding registers / input registers) | Observation. The PLC's state is sampled. No process effect. |
| **Write** | 05, 06, 15, 16 (write single coil / single register / multiple coils / multiple registers) | Mutation. The PLC's state is *changed*. Process effect. |

A Modbus *read* against a chlorination dosing PLC is a probe. A Modbus *write function code 16 (FC16)* against the same PLC is a public-health emergency in 50 milliseconds.

Standard stateful firewalls (allow tcp/502) cannot tell read from write. **An OT-aware firewall doing deep packet inspection (DPI) can.** This is why the requirement [NS-R3 (OT protocol-aware filtering)](#framework/domain:network-segmentation) demands DPI at every inter-zone conduit, and why the Monterrey 2026 attacker probed the SCADA management interface via single-password authentication rather than via Modbus directly — the OT protocol *itself* would have been blocked by a competent firewall.

The same distinction exists in every OT protocol:

- **DNP3**: function code 0x01 (READ) vs 0x02 (WRITE), and the dangerous one — function code 0x05 (DIRECT_OPERATE).
- **EtherNet/IP (CIP)**: service code 0x4E (Get_Attribute_Single) vs 0x05 (Reset) or 0x4D (Set_Attribute_Single).
- **S7Comm**: function 0x04 (Read Var) vs 0x05 (Write Var); ROSCTR 0x07 with sub-function 0x29 (PLC Stop) is the kill switch.

## A 60-byte Modbus example you should be able to read

A Modbus TCP request to read 10 holding registers from PLC unit 1:

```
00 01      transaction id (0x0001 — picked by client; ignored by us for security)
00 00      protocol id (0x0000 — always Modbus)
00 06      length of remaining bytes (6)
01         unit id (PLC slave 1)
03         function code 03 — READ HOLDING REGISTERS  ← THIS IS THE INTERESTING BYTE
00 00      starting register (0)
00 0A      register count (10)
```

The same request, but writing 10 registers (FC16), differs by **two bytes plus the data**:

```
... headers ...
01         unit id
10         function code 16 (0x10) — WRITE MULTIPLE REGISTERS  ← DIFFERENT
00 00      starting register (0)
00 0A      register count (10)
14         byte count (20 = 10 registers × 2 bytes)
[20 bytes of new register values]
```

**A defender's firewall rule that distinguishes these two requests is your entire OT segmentation strategy.** A defender's rule that allows port 502 and stops there is no defence at all.

## How to actually look at this traffic

If you have access to a switch span / mirror port to a sensor:

- **Wireshark** (free) — built-in dissectors for Modbus, DNP3, EtherNet/IP, S7. Filter `modbus.func_code == 16` to find writes.
- **`tcpdump -w capture.pcap port 502`** — capture only.
- **`tools/pcap-analyzer.py`** in this repo (used in [T2 Lesson 1](#learn/lesson:t2-practitioner:01-passive-discovery-lab)) — extracts protocol + asset metadata.

You will *not* run any of this on production OT without explicit authorisation from the plant owner. Sniffing is passive and safe; the operational risk is the engineering control you don't yet understand.

## Three things to remember when you forget the rest

1. **Every OT protocol you will meet was designed for a locked room, not a TCP/IP network.** Authentication is not "weak" — it is *absent*.
2. **Read ≠ Write.** Every OT protocol has the distinction; every defensive boundary should enforce it. Standard firewalls don't; OT-aware firewalls do.
3. **Port-only firewall rules are the canonical OT finding.** "Permit tcp/502 to PLC subnet" is not a control — it's a hole.

## Map back to controls

- [Network Segmentation domain — NS-R3 (OT protocol-aware filtering)](#framework/domain:network-segmentation) — the requirement that demands DPI at conduit boundaries.
- [Network Segmentation domain — NS-R2 (Industrial DMZ)](#framework/domain:network-segmentation) — the architecture that makes DPI possible.
- [Monitoring and Logging domain](#framework/domain:monitoring-logging) — passive visibility into what's actually crossing your zones.

## Primary references

These are public specifications — read the section, not a blog post:

- **Modbus Application Protocol Specification V1.1b3**, Modbus Organization, 2012 — section 6 (Function Codes).
- **IEEE 1815-2012 (DNP3)** — section 4 (Application Layer Function Codes).
- **ODVA Volume 1 (CIP Common)** — chapter 5 (Connection Manager + Service Codes).
- **Siemens S7 Communication** — no public spec; reverse-engineered. Wireshark dissector source is the practical reference.

## What's next

Move on to the [checkpoint](#learn/lesson:t1-orientation:05-checkpoint). The protocol primer is the last reading — the checkpoint will test whether you can apply what you've learned.
