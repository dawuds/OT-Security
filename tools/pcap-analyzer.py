#!/usr/bin/env python3
"""
OT Passive Asset Fingerprinter & PCAP Analyzer
Reads an offline .pcap/.pcapng file (GUI file selector) and extracts:
  - Unique device inventory (MAC, IP, OUI vendor)
  - Industrial protocol detection (Modbus, DNP3, ENIP/CIP, S7Comm, BACnet)
  - Communication flow matrix (Who Talks to Whom)
  - Public IP detection and alerting

Outputs:
  ot_asset_inventory.csv
  ot_communication_map.csv

Requirements: pyshark>=0.6, tshark installed on host OS.
Run: python3 pcap-analyzer.py

EDUCATIONAL / LAB USE ONLY. Offline analysis only — no live sniffing.
"""

import csv
import ipaddress
import os
import sys
import tkinter as tk
from tkinter import filedialog
from collections import defaultdict

try:
    import pyshark
except ImportError:
    print('[!] pyshark not installed. Run: pip install pyshark')
    sys.exit(1)

# ─── ANSI colours ───────────────────────────────────────────────────────────
RESET   = '\033[0m'
RED     = '\033[91m'
YELLOW  = '\033[93m'
CYAN    = '\033[96m'
GREEN   = '\033[92m'
BOLD    = '\033[1m'

def red(s):    return f'{BOLD}{RED}{s}{RESET}'
def yellow(s): return f'{BOLD}{YELLOW}{s}{RESET}'
def cyan(s):   return f'{BOLD}{CYAN}{s}{RESET}'
def green(s):  return f'{BOLD}{GREEN}{s}{RESET}'

# ─── OUI vendor prefix table (first 24 bits of MAC) ─────────────────────────
# Partial table focusing on common OT vendors.
# For production use, download the full IEEE OUI database.
OUI_TABLE = {
    '00:00:BC': 'Rockwell Automation / Allen-Bradley',
    '00:00:1D': 'Cabletron Systems',
    '00:01:AF': 'Siemens Industrial',
    '00:0E:8C': 'Siemens',
    '08:00:06': 'Siemens AG',
    '00:80:F4': 'Telemecanique / Schneider Electric',
    '00:07:B4': 'Schneider Electric',
    '00:1A:8C': 'Schneider Electric',
    '00:50:C2': 'Schneider Electric (IANA)',
    '00:60:35': 'Rockwell Automation',
    '00:00:A7': 'Rockwell Automation',
    '00:00:BC': 'Rockwell / Allen-Bradley',
    '2C:27:D7': 'Rockwell Automation',
    '00:80:2F': 'Tadiran',
    '00:0B:5D': 'Emerson Electric',
    '00:12:4B': 'Texas Instruments',
    '00:A0:F0': 'GE Fanuc Automation',
    '00:00:4E': 'Icad Inc / GE',
    '00:E0:5C': 'ABB',
    '00:07:3C': 'ABB Automation',
    '00:10:60': 'Honeywell',
    '00:C0:4E': 'Honeywell',
    '00:00:4F': 'Logicraft',
    '00:A0:E7': 'Foxboro / Schneider',
    '00:02:A2': 'Advantech',
    '00:D0:C9': 'Kontron',
    'FC:C2:3D': 'Dell',
    'AC:BC:32': 'Apple',
    '00:50:56': 'VMware',
    '08:00:27': 'Oracle VirtualBox',
    '52:54:00': 'QEMU/KVM',
}

def resolve_oui(mac: str) -> str:
    if not mac or mac in ('', 'N/A'):
        return 'Unknown'
    prefix = mac.upper()[:8]
    return OUI_TABLE.get(prefix, 'Unknown Vendor')


# ─── Industrial protocol port definitions ───────────────────────────────────
INDUSTRIAL_PORTS = {
    502:   'Modbus TCP',
    20000: 'DNP3',
    44818: 'ENIP/CIP (EtherNet/IP)',
    2222:  'ENIP/CIP (UDP Discovery)',
    102:   'S7Comm (Siemens)',
    4840:  'OPC-UA',
    47808: 'BACnet/IP',
    9600:  'Omron FINS',
    18245: 'GE SRTP',
    1089:   'FF HSE (Foundation Fieldbus)',
    34964: 'PROFINET (DCP)',
    61158: 'PROFINET (RT)',
}

def detect_protocol(src_port: int, dst_port: int) -> str:
    for p in (dst_port, src_port):
        if p in INDUSTRIAL_PORTS:
            return INDUSTRIAL_PORTS[p]
    return 'Other'


# ─── Public IP detection ─────────────────────────────────────────────────────
def is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private and not addr.is_loopback and not addr.is_multicast
    except ValueError:
        return True  # treat unparseable as safe (e.g., broadcast)


def alert_public_ip(src_ip: str, dst_ip: str, dst_port: int):
    pub = dst_ip if not is_private_ip(dst_ip) else src_ip
    internal = src_ip if pub == dst_ip else dst_ip
    print(red(f'\n[!] WARNING: Public IP Interaction Detected!'))
    print(red(f'    Internal: {internal} ↔ Public: {pub} on Port {dst_port}'))
    print(red(f'    OT devices should NEVER communicate with public Internet.\n'))


# ─── GUI file selector ───────────────────────────────────────────────────────
def select_pcap_file() -> str:
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    path = filedialog.askopenfilename(
        title='Select PCAP/PCAPNG File for OT Analysis',
        filetypes=[('PCAP files', '*.pcap *.pcapng'), ('All files', '*.*')]
    )
    root.destroy()
    return path


# ─── Main analysis ───────────────────────────────────────────────────────────
def analyse(pcap_path: str):
    print(green(f'\n{"="*65}'))
    print(green(f'  OT Passive Asset Fingerprinter'))
    print(green(f'{"="*65}'))
    print(f'  File: {pcap_path}')
    print(f'  Mode: Offline analysis (no live sniffing)\n')

    # Tracking structures
    devices = {}        # mac → {'mac','ip','ipv6','vendor','protocols': set}
    flows   = defaultdict(lambda: {'protocol': 'Other', 'count': 0, 'public': False})
    # flows key: (src_mac, src_ip, dst_mac, dst_ip, protocol, dst_port)

    pkt_count   = 0
    error_count = 0
    public_alerts = set()

    try:
        cap = pyshark.FileCapture(
            pcap_path,
            keep_packets=False,   # prevent RAM exhaustion on large files
            use_json=True,
        )
    except Exception as e:
        print(red(f'[!] Failed to open PCAP: {e}'))
        print(yellow('[!] Ensure tshark/Wireshark is installed on this system.'))
        sys.exit(1)

    print(cyan('[~] Parsing packets... (this may take a moment for large files)'))

    for pkt in cap:
        pkt_count += 1
        try:
            # ── Extract MAC addresses ──
            src_mac = dst_mac = 'N/A'
            if hasattr(pkt, 'eth'):
                src_mac = pkt.eth.src.upper()
                dst_mac = pkt.eth.dst.upper()

            # ── Extract IP addresses ──
            src_ip = dst_ip = ''
            if hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
            elif hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
                dst_ip = pkt.ipv6.dst

            # ── Register devices ──
            for mac, ip in ((src_mac, src_ip), (dst_mac, dst_ip)):
                if mac and mac != 'N/A' and not mac.startswith('FF:FF'):
                    if mac not in devices:
                        devices[mac] = {
                            'mac': mac,
                            'ip': ip or '',
                            'ipv6': '',
                            'vendor': resolve_oui(mac),
                            'protocols': set(),
                        }
                    elif ip and not devices[mac]['ip']:
                        devices[mac]['ip'] = ip

            # ── Extract ports and protocol ──
            src_port = dst_port = 0
            if hasattr(pkt, 'tcp'):
                try:
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                except (ValueError, AttributeError):
                    pass
            elif hasattr(pkt, 'udp'):
                try:
                    src_port = int(pkt.udp.srcport)
                    dst_port = int(pkt.udp.dstport)
                except (ValueError, AttributeError):
                    pass

            protocol = detect_protocol(src_port, dst_port)

            # Tag protocol on source device
            if src_mac and src_mac != 'N/A' and src_mac in devices:
                devices[src_mac]['protocols'].add(protocol)

            # ── Public IP detection ──
            is_public_flow = False
            if src_ip and dst_ip:
                src_pub = not is_private_ip(src_ip) if src_ip else False
                dst_pub = not is_private_ip(dst_ip) if dst_ip else False
                if src_pub or dst_pub:
                    is_public_flow = True
                    alert_key = (src_ip, dst_ip, dst_port)
                    if alert_key not in public_alerts:
                        public_alerts.add(alert_key)
                        alert_public_ip(src_ip, dst_ip, dst_port)

            # ── Record communication flow ──
            if src_ip and dst_ip:
                flow_key = (src_mac, src_ip, dst_mac, dst_ip, protocol, dst_port)
                flows[flow_key]['count']    += 1
                flows[flow_key]['protocol']  = protocol
                flows[flow_key]['public']    = is_public_flow

        except AttributeError:
            pass
        except Exception:
            error_count += 1

    cap.close()

    print(green(f'[+] Parsed {pkt_count:,} packets | {error_count} errors | {len(devices)} unique devices | {len(flows)} unique flows\n'))

    # ─── Write ot_asset_inventory.csv ────────────────────────────────────────
    inv_path = 'ot_asset_inventory.csv'
    with open(inv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['MAC_Address', 'IP_Address', 'IPv6_Address', 'Vendor_OUI', 'Protocols_Observed'])
        for dev in sorted(devices.values(), key=lambda d: d['ip'] or ''):
            writer.writerow([
                dev['mac'],
                dev['ip'],
                dev['ipv6'],
                dev['vendor'],
                '; '.join(sorted(dev['protocols'] - {'Other'})) or 'N/A',
            ])
    print(green(f'[+] Asset inventory written → {inv_path}  ({len(devices)} devices)'))

    # ─── Write ot_communication_map.csv ──────────────────────────────────────
    map_path = 'ot_communication_map.csv'
    with open(map_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Source_IP', 'Source_MAC',
            'Destination_IP', 'Destination_MAC',
            'Protocol', 'Destination_Port',
            'Packet_Count', 'Public_Internet_Routing'
        ])
        for (src_mac, src_ip, dst_mac, dst_ip, protocol, dst_port), data in sorted(
            flows.items(), key=lambda x: (-x[1]['count'], x[0][1])
        ):
            writer.writerow([
                src_ip, src_mac,
                dst_ip, dst_mac,
                protocol, dst_port,
                data['count'],
                'TRUE' if data['public'] else 'FALSE',
            ])
    print(green(f'[+] Communication map written → {map_path}  ({len(flows)} flows)'))

    # ─── Summary to console ───────────────────────────────────────────────────
    industrial_flows = [(k, v) for k, v in flows.items() if v['protocol'] != 'Other']
    print(f'\n{cyan("─"*65)}')
    print(cyan('  Industrial Protocol Summary'))
    print(cyan('─'*65))

    proto_counts = defaultdict(int)
    for (_, _, _, _, protocol, _), data in industrial_flows:
        proto_counts[protocol] += data['count']

    if proto_counts:
        for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
            print(f'  {proto:<30} {count:>8,} packets')
    else:
        print('  No industrial protocol traffic detected in this capture.')

    if public_alerts:
        print(red(f'\n  [!] {len(public_alerts)} Public IP interaction(s) detected — review ot_communication_map.csv (Public_Internet_Routing=TRUE)'))
    else:
        print(green(f'\n  [+] No public IP interactions detected.'))

    print(cyan('─'*65))
    print(green(f'\n  Analysis complete. Review the CSV files for full detail.\n'))


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    print(green('\n[*] OT Passive Asset Fingerprinter'))
    print('[*] Select a PCAP or PCAPNG file to analyse...\n')

    pcap_path = select_pcap_file()

    if not pcap_path:
        print(yellow('[!] No file selected. Exiting.'))
        sys.exit(0)

    if not os.path.isfile(pcap_path):
        print(red(f'[!] File not found: {pcap_path}'))
        sys.exit(1)

    if not pcap_path.lower().endswith(('.pcap', '.pcapng')):
        print(red('[!] Selected file is not a .pcap or .pcapng file.'))
        sys.exit(1)

    analyse(pcap_path)


if __name__ == '__main__':
    main()
