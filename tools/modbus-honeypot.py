#!/usr/bin/env python3
"""
SABESB Industrial Modbus TCP Honeypot
Simulates a Water Treatment Plant PLC (Allen-Bradley ControlLogix equivalent)
responding to Modbus TCP requests on port 502.

Requirements: pymodbus>=3.6, scapy>=2.5 (or raw sockets fallback)
Run as root/sudo (required for raw sockets and port 502).

Usage:
    sudo python3 modbus-honeypot.py [--host 0.0.0.0] [--port 502] [--syslog-host <IP>] [--syslog-port 514]

EDUCATIONAL / LAB USE ONLY.
Do NOT deploy on a production OT network.
"""

import argparse
import json
import logging
import logging.handlers
import socket
import sys
import threading
import time
from datetime import datetime, timezone

# ─── Colour helpers (ANSI) ──────────────────────────────────────────────────
RESET  = '\033[0m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
GREEN  = '\033[92m'
BOLD   = '\033[1m'

def red(s):    return f'{BOLD}{RED}{s}{RESET}'
def yellow(s): return f'{BOLD}{YELLOW}{s}{RESET}'
def cyan(s):   return f'{BOLD}{CYAN}{s}{RESET}'
def green(s):  return f'{BOLD}{GREEN}{s}{RESET}'

# ─── Logging setup ──────────────────────────────────────────────────────────
log = logging.getLogger('modbus_honeypot')
log.setLevel(logging.DEBUG)

def setup_logging(log_file='honeypot_alerts.log', syslog_host=None, syslog_port=514):
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    # Rotating file handler — JSON structured
    fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=10_000_000, backupCount=5)
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    log.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(ch)

    # Optional syslog export
    if syslog_host:
        try:
            sh = logging.handlers.SysLogHandler(address=(syslog_host, syslog_port))
            sh.setLevel(logging.INFO)
            sh.setFormatter(logging.Formatter('modbus_honeypot: %(message)s'))
            log.addHandler(sh)
            log.info(green(f'[*] Syslog export enabled → {syslog_host}:{syslog_port}'))
        except Exception as e:
            log.warning(f'[!] Syslog setup failed: {e}')


def emit_json(event_type: str, src_ip: str, details: dict):
    """Write a structured JSON alert to the log."""
    record = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': event_type,
        'source_ip': src_ip,
        **details
    }
    log.info(json.dumps(record))
    return record


# ─── Realistic Water Treatment Plant DataBlock ──────────────────────────────
# Simulates: WTP chlorination / pump control PLC
#
# Coils (0/1 — discrete output):
#   0  = Main Feed Pump Running
#   1  = Recirculation Pump Running
#   2  = Chemical Dosing Pump Active
#   3  = High-Level Alarm Active
#   4  = Emergency Stop Engaged
#
# Discrete Inputs (read-only):
#   0  = Float Switch — High Level (True = tank full)
#   1  = Float Switch — Low Level
#   2  = Turbidity Alarm (True = turbidity high)
#   3  = Chlorine Residual Low Alarm
#
# Input Registers (read-only, raw sensor values):
#   0  = Flow Rate (L/min × 10, e.g. 2450 = 245.0 L/min)
#   1  = Raw Water Turbidity (NTU × 100, e.g. 120 = 1.20 NTU)
#   2  = pH Value (× 100, e.g. 720 = 7.20)
#   3  = Chlorine Residual (ppm × 100, e.g. 85 = 0.85 ppm)
#   4  = Tank Level (mm, e.g. 3200 = 3.2m)
#
# Holding Registers (read/write — setpoints, targets):
#   0  = Chlorine Dosing Setpoint (ppm × 100, e.g. 100 = 1.00 ppm) — CROWN JEWEL
#   1  = pH Target (× 100, e.g. 720 = 7.20)
#   2  = Minimum Flow Setpoint (L/min × 10)
#   3  = High Level Alarm Threshold (mm)
#   4  = Low Level Alarm Threshold (mm)
#   5  = Dosing Pump Speed (% × 10, e.g. 650 = 65.0%)
#   6  = Treatment Stage (0=offline, 1=standby, 2=running, 3=flush)
#   7  = Maintenance Mode Flag (0=normal, 1=maintenance — disables alarms)

INITIAL_COILS     = [True,  True,  True,  False, False]
INITIAL_DI        = [False, True,  False, False]
INITIAL_IR        = [2450,  120,   720,   85,    3200]
INITIAL_HR        = [100,   720,   2000,  3800,  400,   650,   2,     0]

coils   = list(INITIAL_COILS)
d_input = list(INITIAL_DI)
i_regs  = list(INITIAL_IR)
h_regs  = list(INITIAL_HR)
data_lock = threading.Lock()


# ─── Modbus TCP server ───────────────────────────────────────────────────────
MODBUS_EXCEPTION_BASE = 0x80

FC_READ_COILS     = 0x01
FC_READ_DI        = 0x02
FC_READ_IR        = 0x04
FC_READ_HR        = 0x03
FC_WRITE_COIL     = 0x05
FC_WRITE_COILS    = 0x0F
FC_WRITE_HR       = 0x06
FC_WRITE_HRS      = 0x10

FC_NAMES = {
    0x01: 'Read Coils',
    0x02: 'Read Discrete Inputs',
    0x03: 'Read Holding Registers',
    0x04: 'Read Input Registers',
    0x05: 'Write Single Coil',
    0x06: 'Write Single Register',
    0x0F: 'Write Multiple Coils',
    0x10: 'Write Multiple Registers',
}

WRITE_SEVERITY = {
    FC_WRITE_COIL:  'WRITE_COIL',
    FC_WRITE_COILS: 'WRITE_COILS',
    FC_WRITE_HR:    'WRITE_REGISTER',
    FC_WRITE_HRS:   'WRITE_REGISTERS',
}

CROWN_JEWEL_HR = {0: 'ChlorineDosingSetpoint', 6: 'TreatmentStage', 7: 'MaintenanceModeFlag'}


def parse_mbap(data: bytes):
    """Parse Modbus Application Protocol header (6 bytes)."""
    if len(data) < 6:
        return None
    tid    = int.from_bytes(data[0:2], 'big')
    proto  = int.from_bytes(data[2:4], 'big')
    length = int.from_bytes(data[4:6], 'big')
    return tid, proto, length


def build_response(tid: int, unit_id: int, payload: bytes) -> bytes:
    header = tid.to_bytes(2,'big') + b'\x00\x00' + len(payload).to_bytes(2,'big')
    return header + payload


def process_request(data: bytes, src_ip: str) -> bytes:
    if len(data) < 8:
        return b''

    tid, proto, length = parse_mbap(data)
    unit_id = data[6]
    fc      = data[7]
    pdu     = data[8:]

    fc_name = FC_NAMES.get(fc, f'FC_0x{fc:02X}')

    # ── Read requests ──
    if fc == FC_READ_COILS:
        start = int.from_bytes(pdu[0:2], 'big')
        count = int.from_bytes(pdu[2:4], 'big')
        with data_lock:
            vals = coils[start:start+count]
        byte_count = (count + 7) // 8
        bit_byte = 0
        for i, v in enumerate(vals):
            if v:
                bit_byte |= (1 << i)
        payload = bytes([unit_id, fc, byte_count, bit_byte])
        emit_json('MODBUS_READ', src_ip, {'fc': fc, 'fc_name': fc_name, 'start': start, 'count': count})
        return build_response(tid, unit_id, payload)

    elif fc == FC_READ_DI:
        start = int.from_bytes(pdu[0:2], 'big')
        count = int.from_bytes(pdu[2:4], 'big')
        with data_lock:
            vals = d_input[start:start+count]
        byte_count = (count + 7) // 8
        bit_byte = sum((1 << i) for i, v in enumerate(vals) if v)
        payload = bytes([unit_id, fc, byte_count, bit_byte])
        emit_json('MODBUS_READ', src_ip, {'fc': fc, 'fc_name': fc_name, 'start': start, 'count': count})
        return build_response(tid, unit_id, payload)

    elif fc == FC_READ_HR:
        start = int.from_bytes(pdu[0:2], 'big')
        count = int.from_bytes(pdu[2:4], 'big')
        with data_lock:
            vals = h_regs[start:start+count]
        byte_count = count * 2
        reg_bytes = b''.join(v.to_bytes(2, 'big') for v in vals)
        payload = bytes([unit_id, fc, byte_count]) + reg_bytes
        emit_json('MODBUS_READ', src_ip, {'fc': fc, 'fc_name': fc_name, 'start': start, 'count': count, 'values': vals})
        return build_response(tid, unit_id, payload)

    elif fc == FC_READ_IR:
        start = int.from_bytes(pdu[0:2], 'big')
        count = int.from_bytes(pdu[2:4], 'big')
        with data_lock:
            vals = i_regs[start:start+count]
        byte_count = count * 2
        reg_bytes = b''.join(v.to_bytes(2, 'big') for v in vals)
        payload = bytes([unit_id, fc, byte_count]) + reg_bytes
        emit_json('MODBUS_READ', src_ip, {'fc': fc, 'fc_name': fc_name, 'start': start, 'count': count, 'values': vals})
        return build_response(tid, unit_id, payload)

    # ── Write Single Coil ──
    elif fc == FC_WRITE_COIL:
        addr  = int.from_bytes(pdu[0:2], 'big')
        value = pdu[2] == 0xFF
        with data_lock:
            old_val = coils[addr] if addr < len(coils) else None
            if addr < len(coils):
                coils[addr] = value
        console_msg = red(f'[!] WRITE COIL — Src: {src_ip} | Addr: {addr} | Value: {value} | Old: {old_val}')
        log.warning(console_msg)
        emit_json('MODBUS_WRITE_COIL', src_ip, {'fc': fc, 'fc_name': fc_name, 'address': addr, 'value': value, 'previous_value': old_val, 'severity': 'HIGH'})
        echo = pdu[0:4]
        payload = bytes([unit_id, fc]) + echo
        return build_response(tid, unit_id, payload)

    # ── Write Single Holding Register ──
    elif fc == FC_WRITE_HR:
        addr  = int.from_bytes(pdu[0:2], 'big')
        value = int.from_bytes(pdu[2:4], 'big')
        with data_lock:
            old_val = h_regs[addr] if addr < len(h_regs) else None
            if addr < len(h_regs):
                h_regs[addr] = value
        crown = CROWN_JEWEL_HR.get(addr)
        severity = 'CRITICAL' if crown else 'HIGH'
        tag = f' [{crown}]' if crown else ''
        console_msg = red(f'[!!] WRITE REGISTER{tag} — Src: {src_ip} | Addr: {addr} | New: {value} | Old: {old_val}')
        log.warning(console_msg)
        emit_json('MODBUS_WRITE_REGISTER', src_ip, {'fc': fc, 'fc_name': fc_name, 'address': addr, 'new_value': value, 'previous_value': old_val, 'tag': crown, 'severity': severity})
        echo = pdu[0:4]
        payload = bytes([unit_id, fc]) + echo
        return build_response(tid, unit_id, payload)

    # ── Write Multiple Holding Registers ──
    elif fc == FC_WRITE_HRS:
        start  = int.from_bytes(pdu[0:2], 'big')
        count  = int.from_bytes(pdu[2:4], 'big')
        byte_c = pdu[4]
        vals   = [int.from_bytes(pdu[5 + i*2:7 + i*2], 'big') for i in range(count)]
        crowns = {start + i: (CROWN_JEWEL_HR[start + i], vals[i]) for i in range(count) if (start + i) in CROWN_JEWEL_HR}
        with data_lock:
            old_vals = h_regs[start:start+count]
            for i, v in enumerate(vals):
                if start + i < len(h_regs):
                    h_regs[start + i] = v
        console_msg = red(f'[!!] WRITE MULTIPLE REGISTERS — Src: {src_ip} | Start: {start} | Count: {count} | Values: {vals}')
        if crowns:
            console_msg += red(f' *** CROWN JEWEL WRITE: {crowns} ***')
        log.warning(console_msg)
        emit_json('MODBUS_WRITE_REGISTERS', src_ip, {'fc': fc, 'fc_name': fc_name, 'start': start, 'count': count, 'new_values': vals, 'previous_values': old_vals, 'crown_jewels': {str(k): v[0] for k,v in crowns.items()}, 'severity': 'CRITICAL' if crowns else 'HIGH'})
        payload = bytes([unit_id, fc]) + pdu[0:4]
        return build_response(tid, unit_id, payload)

    # ── Write Multiple Coils ──
    elif fc == FC_WRITE_COILS:
        start  = int.from_bytes(pdu[0:2], 'big')
        count  = int.from_bytes(pdu[2:4], 'big')
        byte_c = pdu[4]
        bit_data = pdu[5:5+byte_c]
        vals = [(bit_data[i//8] >> (i % 8)) & 1 for i in range(count)]
        with data_lock:
            old_vals = coils[start:start+count]
            for i, v in enumerate(vals):
                if start + i < len(coils):
                    coils[start + i] = bool(v)
        console_msg = red(f'[!] WRITE MULTIPLE COILS — Src: {src_ip} | Start: {start} | Values: {[bool(v) for v in vals]}')
        log.warning(console_msg)
        emit_json('MODBUS_WRITE_COILS', src_ip, {'fc': fc, 'fc_name': fc_name, 'start': start, 'count': count, 'new_values': [bool(v) for v in vals], 'previous_values': old_vals, 'severity': 'HIGH'})
        payload = bytes([unit_id, fc]) + pdu[0:4]
        return build_response(tid, unit_id, payload)

    else:
        # Unknown function code — respond with exception
        emit_json('MODBUS_UNKNOWN_FC', src_ip, {'fc': fc, 'fc_name': fc_name, 'severity': 'MEDIUM'})
        payload = bytes([unit_id, MODBUS_EXCEPTION_BASE | fc, 0x01])  # exception code 01 = illegal function
        return build_response(tid, unit_id, payload)


def handle_client(conn: socket.socket, addr: tuple):
    src_ip = addr[0]
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            response = process_request(data, src_ip)
            if response:
                conn.sendall(response)
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.debug(f'Client handler error ({src_ip}): {e}')
    finally:
        conn.close()


def run_modbus_server(host: str, port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except PermissionError:
        log.error(red(f'[!] Cannot bind to port {port}: permission denied. Run as root/sudo.'))
        sys.exit(1)
    srv.listen(10)
    log.info(green(f'[*] Modbus TCP honeypot listening on {host}:{port}'))
    while True:
        try:
            conn, addr = srv.accept()
            src_ip = addr[0]
            log.info(cyan(f'[~] New connection from {src_ip}:{addr[1]}'))
            emit_json('TCP_CONNECT', src_ip, {'port': port, 'severity': 'LOW'})
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            log.debug(f'Accept error: {e}')


# ─── Network sniffer (raw socket — requires root) ────────────────────────────
ICMP_PROTO = 1
TCP_PROTO  = 6

def run_sniffer(honeypot_ip: str, monitored_ports: list):
    """Detect pings and TCP SYN scans targeting the honeypot using raw sockets."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        if sys.platform == 'win32':
            s.bind((honeypot_ip, 0))
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        log.warning(yellow('[!] Raw socket sniffer requires root. Network detection disabled.'))
        return
    except Exception as e:
        log.warning(yellow(f'[!] Sniffer init failed: {e}. Network detection disabled.'))
        return

    log.info(green(f'[*] Network sniffer active — monitoring pings and port scans'))

    try:
        while True:
            try:
                raw, addr = s.recvfrom(65535)
                src_ip = addr[0]
                if src_ip == honeypot_ip:
                    continue

                # Parse IP header
                ip_header_len = (raw[0] & 0x0F) * 4
                proto = raw[9]
                dst_ip_bytes = raw[16:20]
                dst_ip = '.'.join(str(b) for b in dst_ip_bytes)

                if dst_ip != honeypot_ip and honeypot_ip != '0.0.0.0':
                    continue

                if proto == ICMP_PROTO:
                    icmp_type = raw[ip_header_len]
                    if icmp_type == 8:  # Echo Request
                        msg = cyan(f'[~] ICMP PING from {src_ip}')
                        log.info(msg)
                        emit_json('ICMP_PING', src_ip, {'icmp_type': icmp_type, 'severity': 'LOW'})

                elif proto == TCP_PROTO:
                    tcp_offset = ip_header_len
                    if len(raw) < tcp_offset + 14:
                        continue
                    dst_port = int.from_bytes(raw[tcp_offset+2:tcp_offset+4], 'big')
                    flags    = raw[tcp_offset + 13]
                    syn_flag = bool(flags & 0x02)
                    ack_flag = bool(flags & 0x10)

                    if syn_flag and not ack_flag and dst_port in monitored_ports:
                        msg = yellow(f'[~] TCP SYN SCAN — Src: {src_ip} → Port: {dst_port}')
                        log.info(msg)
                        emit_json('TCP_SYN_SCAN', src_ip, {'destination_port': dst_port, 'severity': 'MEDIUM'})

            except Exception:
                pass
    finally:
        s.close()


# ─── CLI entry point ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='SABESB Industrial Modbus TCP Honeypot')
    parser.add_argument('--host',         default='0.0.0.0',       help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port',         type=int, default=502,    help='Modbus TCP port (default: 502)')
    parser.add_argument('--log-file',     default='honeypot_alerts.log', help='Alert log file path')
    parser.add_argument('--syslog-host',  default=None,             help='Remote syslog server IP')
    parser.add_argument('--syslog-port',  type=int, default=514,    help='Remote syslog port (default: 514)')
    parser.add_argument('--monitored-ports', default='502,44818,20000,102', help='CSV port list to watch for SYN scans')
    args = parser.parse_args()

    setup_logging(args.log_file, args.syslog_host, args.syslog_port)

    monitored_ports = [int(p) for p in args.monitored_ports.split(',')]

    print(green(f'\n{"="*60}'))
    print(green(f'  SABESB Modbus TCP Honeypot — WTP Chlorination PLC Sim'))
    print(green(f'{"="*60}'))
    print(f'  Listening  : {args.host}:{args.port}')
    print(f'  Log file   : {args.log_file}')
    print(f'  Syslog     : {args.syslog_host or "disabled"}')
    print(f'  Alerts:')
    print(red(  f'    RED    = Write attempts (CRITICAL/HIGH)'))
    print(yellow(f'    YELLOW = Scans / SYN attempts'))
    print(cyan(  f'    CYAN   = Connections / Pings'))
    print(green(f'{"="*60}\n'))

    # Start sniffer in background thread
    sniffer_thread = threading.Thread(
        target=run_sniffer,
        args=(args.host if args.host != '0.0.0.0' else '127.0.0.1', monitored_ports),
        daemon=True
    )
    sniffer_thread.start()

    # Run Modbus server (blocking)
    run_modbus_server(args.host, args.port)


if __name__ == '__main__':
    main()
