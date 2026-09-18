#!/usr/bin/env python3
"""
Shared configuration and network discovery helpers.

Everything about the target network (interface, gateway, victim) is
discovered at runtime instead of being typed into the code, since the
attacker doesn't know in advance which machine/interface it'll be run on.
"""
from scapy.all import Ether, ARP, srp, conf, get_if_list, get_if_hwaddr
import subprocess
# Populated once main.py finishes device selection, then read by every
# other module (poisoner, forwarder, sniffer, restorer).
TARGET_CONFIG = {
    "interface": None,
    "attacker_mac": None,
    "gateway_ip": None,
    "gateway_mac": None,
    "victim_ip": None,
    "victim_mac": None,
}


def get_default_gateway():
    """
    Read the default gateway IP straight from the OS routing table.

    Asking the OS (via scapy's route table) instead of hardcoding an IP
    means the script works unmodified on any network. Scapy's route()
    returns a (net, netmask, gateway, iface, ...) tuple for the route
    that would be used to reach "0.0.0.0"; index 2 is the gateway IP.
    """
    return conf.route.route("0.0.0.0")[2]


def choose_interface():
    """
    List every network interface and let the operator pick one.

    Scapy's own default guess (conf.iface) isn't reliable on a machine
    with more than one adapter (Wi-Fi + Ethernet, a VPN, etc.), so we
    just ask instead of guessing wrong silently.
    """
    interfaces = get_if_list()
    print("\n[+] Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        marker = "  <- scapy's default guess" if iface == conf.iface.name else ""
        print(f"  {idx:<3} {iface}{marker}")

    try:
        choice = int(input("\n[?] Select the interface connected to the target network: "))
        return interfaces[choice]
    except (ValueError, IndexError):
        print("[-] Invalid selection. Exiting.")
        raise SystemExit(1)




def get_arp_cache(attacker_mac):
    """
    Read the OS's ARP cache - any devices missed by the broadcast scan
    are picked up from here. Parse the output of the 'ip neigh show' command.

    A device can be silent (asleep, or filtering broadcast ARP requests)
    and still show up here, because the OS learned about it from earlier
    traffic. This acts as a fallback source of targets on top of the
    active scan in scan_network().
    """
    try:
        result = subprocess.run(['ip', 'neigh', 'show'],
                                capture_output=True, text=True)
        devices = []
        for line in result.stdout.splitlines():
            parts = line.split()
            # A valid neighbour line has a 'lladdr' (MAC) field; entries
            # without one (e.g. "FAILED" state) have no usable MAC yet.
            if 'lladdr' not in parts:
                continue
            ip  = parts[0]
            mac = parts[parts.index('lladdr') + 1]
            # Only trust entries the kernel considers current/plausible.
            # STALE/DELAY/PROBE are still worth taking since they were
            # verified recently and just haven't been re-confirmed yet.
            state_ok = any(s in parts for s in
                           ['REACHABLE', 'STALE', 'DELAY', 'PROBE'])
            if state_ok and mac.lower() != attacker_mac.lower():
                devices.append({'ip': ip, 'mac': mac})
        return devices
    except Exception:
        # 'ip neigh show' can be missing/fail on non-Linux setups; treat
        # that as "no extra devices found" rather than crashing the scan.
        return []


def scan_network(interface):
    """
    Scan the network for devices using ARP broadcast and merge with OS ARP cache entries.

    The active broadcast scan (send "who has X?" to every IP in the
    subnet, op=1) finds anything currently listening, but some devices
    ignore broadcast ARP or are momentarily asleep. Merging in the OS's
    own ARP cache as a second source catches those without needing a
    second, slower scan pass.
    """
    gateway_ip  = get_default_gateway()
    # Assumes a standard /24 home/lab network (e.g. 192.168.1.0/24);
    # good enough for the typical classroom/hotspot setup this targets.
    subnet      = ".".join(gateway_ip.split('.')[:3]) + ".0/24"
    attacker_mac = get_if_hwaddr(interface)

    print(f"[*] Scanning network {subnet} on interface {interface}...")
    # timeout=10s gives slower Wi-Fi clients (phones, IoT devices) enough
    # time to answer; a short timeout would silently miss real hosts.
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        timeout=10, iface=interface, verbose=False
    )

    devices  = []
    seen_ips = set()

    for _, rcv in ans:
        # The attacker's own NIC answers its own broadcast; skip it so
        # we don't list ourselves as a possible victim/gateway.
        if rcv[ARP].hwsrc.lower() == attacker_mac.lower():
            continue
        ip, mac = rcv[ARP].psrc, rcv[ARP].hwsrc
        devices.append({'ip': ip, 'mac': mac})
        seen_ips.add(ip)

    # Add anything the broadcast scan missed but the OS already knew
    # about, without creating duplicate entries for IPs found twice.
    for entry in get_arp_cache(attacker_mac):
        if entry['ip'] not in seen_ips:
            devices.append(entry)
            seen_ips.add(entry['ip'])
            print(f"[*] Added from ARP cache: {entry['ip']} ({entry['mac']})")

    return gateway_ip, devices, attacker_mac