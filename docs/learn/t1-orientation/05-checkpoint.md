# Checkpoint — orientation self-test

> **Tier 1 / Lesson 5 — 15 minutes.** Five short scenarios. Application, not recall. Each has a definite answer; an answer key is at the bottom — **don't read it until you've written your answers down**. If you get fewer than 4 right, re-read the relevant lesson before starting T2.

## The scenarios

### Scenario 1 — Triage call at 02:14

You are paged. The IT SOC reports ransomware spreading on the corporate network. Your industrial historian (Level 3) has just dropped off the corporate AD. There is no confirmed evidence of OT compromise yet. The plant manager is on the phone asking whether to shut down the production line.

> **What is your *first* question to the plant manager? What is your *first* action? Why this order?**

### Scenario 2 — The asset list

A junior engineer hands you this list from a "passive scan" of an unfamiliar OT environment:

| IP | MAC OUI | Protocol seen | Other |
|---|---|---|---|
| 10.20.30.10 | Siemens | S7Comm on tcp/102 | only talks to 10.20.30.20 |
| 10.20.30.20 | Wonderware | RDP from 10.40.50.x; OPC-UA to 10.20.30.10 | dual NIC visible |
| 10.20.30.30 | Schneider | Modbus on tcp/502 | talks to 10.20.30.20 only |
| 10.40.50.5 | Dell | RDP to 10.20.30.20; HTTPS to internet | corporate laptop user |

> **Identify the two devices that indicate a segmentation violation. Which Purdue level is each device on? What is the proximate finding, and which IEC 62443 SR(s) is it failing?**

### Scenario 3 — Single failed control

You inherit a water plant. There is no IDMZ. Vendor remote access goes via direct VPN to the Level 2 HMI. There is no MFA. The vendor account is shared between three contract engineers. Backup integrity has not been tested in 18 months.

> **Of the failures listed, name the *two* that — if fixed first — would have stopped the Oldsmar 2021 incident from happening at this plant. Defend the choice over the other failures.**

### Scenario 4 — A Modbus packet

You see this in a Wireshark capture leaving an engineering workstation, destined for a chlorination dosing PLC:

```
function code: 16 (Write Multiple Registers)
starting register: 100
register count: 1
new value: 0x2B (43 decimal)
```

The chlorination dosing setpoint is the value at register 100. Normal operating range is 1–10 ppm. The PLC accepts the write.

> **What did the attacker just achieve? Name *two* compensating controls that would have prevented the physical consequence even though the network write succeeded.**

### Scenario 5 — The IT colleague's "fix"

An IT colleague proposes: "Let's just put the OT environment behind the corporate AD with MFA. We'll join the engineering workstations to the domain. Standard hardening, same as the rest of the estate."

> **In one sentence each, give *three* reasons this is wrong for OT. Cite the specific principle, control, or incident behind each reason.**

---

## Self-grading rubric

- **5/5** — You're ready for T2. Move on.
- **4/5** — Re-read the lesson the failed scenario points at; come back tomorrow.
- **≤ 3/5** — Re-read the whole tier. T2 builds on this; it will not work otherwise.

---

## Answer key

> **Stop scrolling unless you've written your answers down.**

### Scenario 1

**First question to the plant manager:** "Is the process still safe?" — *not* "what's compromised?" or "is the historian reachable?". Triage in OT puts physical safety ahead of data confidentiality and even system availability. ([Lesson 1](#learn/lesson:t1-orientation:01-why-ot-is-different))

**First action:** Initiate the IT/OT severance procedure if it exists; if not, isolate the OT network at the IDMZ boundary while keeping the process running on local control. The plant manager (not IT) holds severance authority in a defensible OT IR plan.

**Why this order:** The historian dropping off corporate AD is a symptom of either (a) ransomware reaching the IDMZ, or (b) a defensive auto-disconnect. Either way, OT continuity > IT visibility while you stabilise.

### Scenario 2

**The two devices:** `10.20.30.20` (Wonderware HMI / engineering workstation, **Level 2/3**) — has a dual NIC and accepts RDP from `10.40.50.5` (corporate laptop, **Level 4+**). This means the corporate Level 4 device has a routable RDP path to a Level 2/3 OT host *without transiting an IDMZ jump server*.

**Proximate finding:** Direct IT-to-OT routing path bypasses the IDMZ.

**Failing SRs:** **SR-5.1** (Network segmentation) at minimum; **SR-5.2** (Zone boundary protection) too. Map to [requirement NS-R2](#framework/domain:network-segmentation). NACSA s18 (Security Measures) is the regulatory hook for an NCII operator.

The dual NIC on `10.20.30.20` is the *physical embodiment* of the segmentation violation — the canonical OT audit finding. ([Lesson 2](#learn/lesson:t1-orientation:02-purdue-tour))

### Scenario 3

**The two fixes that would have stopped Oldsmar:**

1. **Eliminate direct internet-exposed remote access** (TeamViewer at Oldsmar). Force vendor access through an IDMZ jump server. *Without this, the attacker has a path; with it, they don't.*
2. **MFA on remote access**, with hardware tokens if mobiles are banned on the plant floor. *Without this, a shared password is the entire authentication; with it, the single password isn't enough.*

**Why these two over the others:**

- *Backup integrity* — important, but Oldsmar wasn't a ransomware event; backups would not have prevented it.
- *Shared vendor account* — contributing factor, but the prior two changes alone would have prevented access regardless of who owned the account.

The IDMZ + MFA pair eliminates the *path*. Everything else mitigates *consequence after the path is taken*. ([Lesson 3 — Oldsmar](#learn/lesson:t1-orientation:03-five-incidents))

### Scenario 4

**What the attacker achieved:** Set the chlorination dosing setpoint to 43 ppm — 4–43× the normal operating range. If the PLC's output drives a pump or valve that responds linearly to the setpoint, this delivers caustic / over-chlorinated water to consumers. Identical class to Oldsmar 2021.

**Two compensating controls that would have prevented the physical consequence:**

1. **Hardware interlock** on the dosing pump — a physical setpoint limiter that mechanically caps the dosing rate at, say, 12 ppm regardless of PLC command. The PLC can be told to dose 43 ppm; the physical hardware refuses.
2. **Software input validation in SCADA / PLC firmware** — reject any setpoint write outside the validated operating range (1–10 ppm). The Write Multiple Registers (FC16) would land but the value would be clamped or rejected at the PLC's I/O loop.

A defender that relies only on the *network* to catch this fails. A defender that combines [NS-R3 (DPI on Modbus FC16 writes)](#framework/domain:network-segmentation) with hardware-and-software input validation has defence in depth. ([Lesson 4b — OT protocols](#learn/lesson:t1-orientation:04b-ot-protocols), Lesson 3 — Oldsmar)

### Scenario 5

**Three reasons the IT colleague's "fix" is wrong:**

1. **Shared AD = single attack surface.** If the corporate AD is compromised (Ukraine 2015, Colonial Pipeline 2021), the OT environment is compromised by transitive trust. The IDMZ exists precisely to prevent this. (SR-5.1, [Ukraine + Colonial in Lesson 3](#learn/lesson:t1-orientation:03-five-incidents))
2. **Standard IT hardening can break OT.** Disabling unused services, forcing reboots for patches, enabling host-based scanning — each one of these has crashed real PLCs. OT hardening must be vendor-validated; "standard hardening" is the wrong default. (Lesson 1 — *patching ≠ IT*)
3. **Engineering workstations on corporate AD have a dual identity problem.** They become reachable from anywhere AD reaches — including OT — and they become Level 4+ assets in the Purdue model, not Level 3. The architectural status of the workstation changes the moment you join it. (Lesson 2 — Purdue levels and the IDMZ)

The right answer is *adjacent* identity (separate OT directory, or one-way trust), inside the IDMZ jump pattern, with OT-specific hardening profiles.

---

## What's next

When you can answer four of five without looking, start [T2 — Practitioner](#learn/tier:t2-practitioner). The first lesson is a hands-on PCAP lab — and the OT-protocols primer in [Lesson 4b](#learn/lesson:t1-orientation:04b-ot-protocols) is the bridge.
