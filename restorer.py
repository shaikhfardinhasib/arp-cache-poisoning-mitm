#!/usr/bin/env python3
"""
Restorer: on exit, sends genuine ARP replies to both the victim and the
gateway so their caches go back to pointing at each other's real MAC
addresses instead of ours. Run when the attack is stopped, so the network
is left in the same state it was found in.
"""
import time
from scapy.all import Ether, ARP, sendp
from config import TARGET_CONFIG


def restore_network():
    """
    Send genuine (non-spoofed) ARP replies so the victim and gateway
    re-learn each other's real MAC addresses.

    Called from main.py's SIGINT/SIGTERM handler so the attack cleans up
    after itself; without this, both hosts would keep routing traffic
    through the attacker (or through nothing, once poisoner.py stops
    refreshing the caches) until their ARP entries naturally time out.
    """
    print("\n[*] Restoring original ARP tables...")
    interface = TARGET_CONFIG["interface"]
    gateway_ip = TARGET_CONFIG["gateway_ip"]
    gateway_mac = TARGET_CONFIG["gateway_mac"]
    victim_ip = TARGET_CONFIG["victim_ip"]
    victim_mac = TARGET_CONFIG["victim_mac"]

    # Guards against a Ctrl+C that arrives before target discovery
    # finished (TARGET_CONFIG only partially filled in) -- there is
    # nothing valid to restore yet, so bail out instead of sending
    # spoofed-looking packets with missing/None fields.
    if not gateway_ip or not victim_ip:
        print("[-] Target data missing. Skipping restoration.")
        return

    # Sent a handful of times rather than once, since a single reply can
    # get lost and we'd rather be certain both caches are actually fixed.
    # Here op=2/hwsrc are the *real* MACs (unlike poisoner.py), so these
    # are legitimate ARP replies, not spoofed ones.
    for _ in range(5):
        sendp(Ether(dst=victim_mac, src=gateway_mac) / ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac, hwsrc=gateway_mac), iface=interface, verbose=False)
        sendp(Ether(dst=gateway_mac, src=victim_mac) / ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac, hwsrc=victim_mac), iface=interface, verbose=False)
        time.sleep(0.5)  # small gap between bursts so replies aren't dropped by rate limiting
    print("[+] Network state restored successfully.")
