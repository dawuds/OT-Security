# SABESB Treatment Plant 4 — Network Diagram

> Provided by the client during the audit kickoff. Sample data only.

```
                              [INTERNET]
                                  |
                            (Cisco FW 10.10.10.5)
                                  |
              +-------------------+-------------------+
              |                                       |
        [Corporate VLAN 10.40.50.0/24]          [Vendor laptop]
              |                                  10.30.40.5
              |  RDP → 10.20.30.20                    |
              |                                       |  HTTPS → internet
              |                                       |  RDP → 10.20.30.20
              |                                       |
              +---------------+-----------------------+
                              |
                              |  (no IDMZ — direct routing
                              |   from corp + vendor to OT)
                              |
                  [OT VLAN 10.20.30.0/24]
                              |
              +---------------+--------------+----------------+
              |               |              |                |
       10.20.30.10     10.20.30.11    10.20.30.20      10.20.30.30
      Reactor PLC      Pump PLC       Eng workstation   SIS controller
      (Schneider)      (Schneider)    (Wonderware,      (Siemens)
       Modbus 502       Modbus 502     dual NIC)         S7Comm 102
                                       OPC-UA            (same VLAN
                                       to PLCs            as BPCS!)


   Wireless (corporate WiFi SSID)
   covers plant floor and control room
   shared SSID, WPA2-PSK
```

## What the operator briefly explained

- "We use the corporate firewall as the boundary."
- "The engineering workstation is on both networks because the engineers need access to corporate email."
- "The SIS controller is on the OT network — same as the other PLCs. It works fine."
- "We have a vendor laptop for remote support; it goes through HTTPS so it's safe."
- "WiFi is the corporate WiFi; we re-use it for tablets on the plant floor."

## What you can see at a glance

You should be able to find at least three deliberate IDMZ violations in this diagram before reading the answer key. Each is a real-world pattern auditors find on real plants.
