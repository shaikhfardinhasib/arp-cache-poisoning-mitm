#!/usr/bin/env python3
"""
Defense-side detector, meant to run on the victim (or any node on the
same network) while an attack from main.py is happening elsewhere.

It builds up a table of which MAC address has claimed each IP, and
raises an alert the moment an IP that was already known suddenly gets
claimed by a different MAC -- which is exactly what happens the moment
ARP poisoning starts.

Usage:
    sudo python3 detector.py <interface>
    sudo python3 detector.py            # lists interfaces if none given
"""
import sys
from scapy.all import sniff, ARP, get_if_list

observed = {}    # ip -> mac we've legitimately seen so far
alerted = set()  # (ip, mac) pairs already reported, so we don't spam the console


def handle_arp(packet):
    """
    Process one sniffed ARP packet: learn a new IP->MAC binding, or
    raise an alert if an already-known IP suddenly claims a different MAC.

    Called once per ARP packet by main()'s sniff() loop. This is the
    core detection logic: ARP poisoning fundamentally works by making a
    known IP suddenly answer from a new MAC, so watching for exactly
    that change is enough to catch it without deeper packet inspection.
    """
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]
    ip, mac = arp.psrc, arp.hwsrc.lower()

    if ip == "0.0.0.0":  # ARP probes (e.g. DHCP address checks), not real bindings
        return

    known_mac = observed.get(ip)

    if known_mac is None:
        # First time seeing this IP: record it as the trusted baseline.
        # (This trust-on-first-use approach means an attacker already
        # poisoning the network before the detector starts would have
        # their spoofed MAC learned as if it were legitimate.)
        observed[ip] = mac
        print(f"[Detector] Learned mapping: {ip} -> {mac}")
        return

    if known_mac != mac:
        # The same IP is now answering from a different MAC than before
        # -- this is the signature of ARP poisoning, but it also happens
        # legitimately (DHCP re-lease to a different device, NIC swap,
        # a laptop reconnecting after switching Wi-Fi adapters), hence
        # "Possible" rather than a certain verdict.
        key = (ip, mac)
        if key not in alerted:
            print(f"[ALERT] Possible ARP spoofing! {ip} was {known_mac}, now claimed by {mac}")
            alerted.add(key)  # de-duplicate: don't reprint on every repeated poison packet
    else:
        # The claimed MAC matches the trusted baseline for this IP, so
        # there is nothing to warn about. observed[ip] is never updated
        # once set above, so known_mac is the original baseline for the
        # life of the process; this discard is a defensive no-op unless
        # that baseline MAC itself was ever added to `alerted`, which
        # the branch above never does (it only adds the *conflicting* MAC).
        alerted.discard((ip, known_mac))


def main():
    """
    Parse the interface argument and start sniffing ARP traffic.

    Takes the interface as a CLI argument (rather than auto-detecting)
    since this typically runs on the victim/monitoring machine, which is
    a different host than the attacker and may have several adapters
    where guessing wrong would mean silently watching the wrong network.
    """
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    if iface is None:
        # No interface named: list what's available instead of guessing,
        # so the operator can re-run with the right one.
        print("[*] No interface given. Available interfaces:")
        for i in get_if_list():
            print(f"    {i}")
        print("[*] Re-run as: sudo python3 detector.py <interface>")
        sys.exit(1)

    print(f"[*] ARP anomaly detector running on {iface}. Ctrl+C to stop.\n")
    # store=0: we only need each ARP packet processed once by handle_arp,
    # not kept in memory -- this detector runs indefinitely so buffering
    # everything would eventually exhaust memory.
    sniff(filter="arp", prn=handle_arp, store=0, iface=iface)


if __name__ == "__main__":
    main()
