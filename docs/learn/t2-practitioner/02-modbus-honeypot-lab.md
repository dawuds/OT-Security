# Lab — Stand up a Modbus honeypot

> **Tier 2 / Lesson 2 — 60 minutes.** Hands-on. You will see what an attacker scanning port 502 sees, and capture traffic you can analyse in Lesson 1.

## Why a honeypot

Three reasons:

1. **You learn what real Modbus probes look like.** This is the same protocol Stuxnet and Oldsmar manipulated.
2. **It generates traffic.** Run it on a network segment with a packet capture going, and you have a PCAP for [Lesson 1](#learn/lesson:t2-practitioner:01-passive-discovery-lab).
3. **In production, honeypots in the IDMZ are a tripwire.** Anyone hitting them is by definition unauthorised. They are mentioned in the [Monitoring & Logging domain](#framework/domain:monitoring-logging).

## What you'll need

- Python 3.10+
- The repo's [`tools/modbus-honeypot.py`](../../../tools/modbus-honeypot.py) and [`tools/requirements-honeypot.txt`](../../../tools/requirements-honeypot.txt).
- A safe network — **never** put a honeypot on the corporate or production network. Use a lab VLAN or your laptop loopback only.
- `tcpdump` or Wireshark for capture.

## Setup

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r tools/requirements-honeypot.txt
```

## Run it

In one terminal, start the capture:

```
sudo tcpdump -i lo -w /tmp/modbus-honeypot.pcap port 502
```

In another, start the honeypot:

```
python3 tools/modbus-honeypot.py
```

In a third, throw some queries at it (example with the `pymodbus` CLI):

```
python3 -c "from pymodbus.client import ModbusTcpClient as C; c=C('127.0.0.1',502); c.connect(); print(c.read_holding_registers(0,10).registers); c.close()"
```

Stop the capture (`Ctrl-C`). You now have a PCAP showing the attack surface.

## Now run Lesson 1 against this PCAP

```
python3 tools/pcap-analyzer.py /tmp/modbus-honeypot.pcap
```

You should see your honeypot identified as a Modbus device on `127.0.0.1`. That confirms your tooling chain works end-to-end.

## What to take from this

- **Modbus has no authentication.** Any TCP connect to port 502 can read or write registers. The defence is **the network**, not the protocol.
- **DPI matters.** A Modbus *read* is benign; a Modbus *write function code 16* on a chlorination dosing PLC is a public health emergency. Standard firewalls don't distinguish — OT-aware firewalls do. See [requirement NS-R3](#framework/domain:network-segmentation).
- **Logging matters.** Every connection to port 502 from outside an explicit allow-list should generate an alert.

## What's next

[Lesson 3 — Map your assets to the Purdue model](#learn/lesson:t2-practitioner:03-map-to-purdue). You now have a tool chain and a sample PCAP — turn that into a defensible diagram.
