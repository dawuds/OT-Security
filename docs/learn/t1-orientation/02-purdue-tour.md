# The Purdue Model in 10 minutes

> **Tier 1 / Lesson 2 — 10 minutes.**

## What it is

The **Purdue Enterprise Reference Architecture** (Purdue Model) is the canonical layering of an industrial environment. It came out of Purdue University in the 1990s as a manufacturing reference; it survived because it gave the security industry a shared language for "where stuff lives".

There are six levels (0–5) and one half-level (3.5). Top is corporate IT. Bottom is the physical process.

| Level | Name | Examples | Talks to |
|---|---|---|---|
| 5 | Enterprise | Office IT, internet, email | 4 |
| 4 | Site business | ERP, plant scheduling, time tracking | 5, IDMZ |
| **3.5** | **IDMZ** | Patch server, AV update relay, jump server, historian replica | 4 ↔ 3 (proxied only) |
| 3 | Operations | SCADA servers, historians, engineering workstations | IDMZ, 2 |
| 2 | Supervisory | HMIs, alarm servers | 3, 1 |
| 1 | Control | PLCs, RTUs, IEDs | 2, 0 |
| 0 | Process | Sensors, actuators, motors | 1 |

Level 0 is the physical world. Level 5 is your inbox. Everything in between is the chain of control between them.

## The IDMZ is the headline

Level 3.5 — the **Industrial DMZ** — is the single most important architectural control in OT. The rule:

> **No traffic should route directly from corporate IT (Level 4+) to the operational network (Level 0–3) without transiting through IDMZ-hosted services.**

Two firewalls. The IDMZ sits between them. Patch servers, antivirus relays, historian replicas, and jump servers live in the IDMZ. A user wanting to RDP to an HMI does not RDP to the HMI — they RDP to the jump server in the IDMZ, and a separate session opens from the jump server to the HMI. That two-hop pattern is the **protocol break**.

If your environment doesn't have an IDMZ, that is your number-one security finding, full stop. Every incident from Ukraine 2015 onward exploited the absence of one.

See the [domain detail for Network Segmentation](#framework/domain:network-segmentation) for the requirements that codify this, and [Industrial DMZ Implementation](#control/idmz-implementation) for the specific control.

## Levels 0 and 1 are sacred

- **Level 0** sensors and actuators have no security at all. A pressure transmitter doesn't authenticate. The defence is *physical access control* and *integrity of the signal path*.
- **Level 1** PLCs/RTUs run programs you can overwrite. They typically have no authentication on the engineering protocol. The defence is *who can reach the engineering port* and *integrity verification of the program*.

Stuxnet exploited Level 1: it overwrote PLC ladder logic to spin centrifuges past their failure speed while reporting normal RPM upwards to Level 2. TRITON exploited the safety system at Level 1 specifically — it tried to disable the safety instrumented system, which would have allowed an unsafe state to propagate.

## Where Safety Instrumented Systems live

A **Safety Instrumented System (SIS)** is a separate set of Level 0/1 devices whose only job is to put the process into a safe state when something goes wrong. It is governed by IEC 61511, not 62443. **The cardinal rule: SIS must be physically and logically isolated from the Basic Process Control System (BPCS).** TRITON tried to violate this. If SIS and BPCS share a network, your safety net has a knife in it.

See [Safety System Security domain](#framework/domain:safety-system-security).

## Wireless & IIoT are extensions of the zone

WiFi, WirelessHART, ISA100, private 5G — these don't get a free pass. They are zones; they need conduits; they need authentication. A rogue access point in the plant breakroom is a Level 4 device that thinks it's outside but is reachable from inside. Every "smart sensor" project should be reviewed against the Purdue model before deployment.

## What's next

Move on to [Lesson 3 — Five incidents you must know](#learn/lesson:t1-orientation:03-five-incidents). Now that you know the geography, those incidents become a tour of where things have gone wrong.
