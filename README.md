# ARP Cache Poisoning + Man-in-the-Middle (MITM)

> **CSE406 — Cyber Security Sessional | BUET**  
> Roni Datta (2105148) · Shaikh Fardin Hasib (2105146)

---

## Overview

This project implements a classic **ARP Cache Poisoning** attack that establishes a
**Man-in-the-Middle (MITM)** position between a victim host and its default gateway
on a shared Wi-Fi/LAN network.

ARP (Address Resolution Protocol) has no authentication — any host can claim to own
any IP address, and every other host will believe it. This project exploits that flaw:
the attacker sends forged ARP replies to both the victim and the gateway, tricking each
into routing all traffic through the attacker's machine. The attacker forwards the
traffic transparently (so the victim's internet keeps working) while silently inspecting
every packet.

A separate script (`detector.py`) demonstrates how the attack can be detected by
watching for sudden IP-to-MAC mapping changes in ARP traffic.

**Concepts demonstrated:** ARP protocol internals · Layer 2 spoofing · MITM positioning ·
packet forwarding at the socket level · plaintext vs. encrypted traffic analysis ·
TLS ClientHello/SNI parsing · anomaly-based intrusion detection.

---

## Project Structure

```
final_project/
├── main.py           # Entry point — discovers network, picks victim, launches all modules
├── config.py         # Shared config state + network discovery (scan, gateway lookup)
├── poisoner.py       # Sends forged ARP replies every ~2s to poison both caches
├── forwarder.py      # Relays intercepted packets to keep victim online (MITM, not DoS)
├── sniffer.py        # Reads traffic: prints HTTP payloads, extracts HTTPS SNI, saves pcap
├── restorer.py       # Heals both ARP caches on Ctrl+C — must always run on exit
├── detector.py       # Defense script — alerts when an IP's MAC suddenly changes
├── requirements.txt  # Python dependencies (scapy)
└── screenshots/      # Evidence captures from a live run
```

---

## How It Works

```
Normal flow (no attack):
  Victim ─────────────────────────────────► Gateway ──► Internet
         "gateway_ip is at GATEWAY_MAC"

Poisoned flow (after attack):
  Victim ──────────► Attacker ───────────► Gateway ──► Internet
         "gateway_ip           (forwards       (sees traffic
          is at MY_MAC"  ◄──    everything)     from attacker,
                 "victim_ip         ▲            not victim)
                  is at MY_MAC"     │
                                 Attacker reads
                                 everything here
```

The attack runs in four phases, all coordinated by `main.py`:

| Phase | Module | What happens |
|---|---|---|
| **1 — Cache Poisoning** | `poisoner.py` | Sends forged ARP replies to both victim and gateway every ~2s. Each believes the attacker's MAC is the other party's address. |
| **2 — Forwarding** | `forwarder.py` | Captures mis-delivered frames and re-sends them to their real destination. Victim's internet stays up — attack stays invisible. |
| **3 — Sniffing** | `sniffer.py` | Reads passing traffic: HTTP payloads printed in full, HTTPS SNI hostname extracted from TLS handshake, all saved to `.pcap`. |
| **4 — Restoration** | `restorer.py` | Triggered on Ctrl+C — sends correct ARP replies to heal both caches and leave the network as it was found. |

---

## Requirements

| Requirement | Notes |
|---|---|
| OS | Linux (tested on Ubuntu 22.04 and Kali Linux) |
| Python | 3.x |
| scapy | >= 2.5.0 |
| Privileges | `sudo` / root — required for raw socket access |
| Network | Attacker, victim, and gateway must all be on the **same** Wi-Fi/LAN |

---

## First-Time Setup

Do this once before your first run.

### Step 1 — Install Scapy

**On Ubuntu:**
```bash
pip3 install scapy
```

**On Kali / Debian (pip will fail — use apt instead):**
```bash
sudo apt install python3-scapy -y
```

> ⚠️ On Kali/Debian, `pip3 install scapy` fails with an
> `externally-managed-environment` error (PEP 668 protection).
> The `apt` method is the correct fix. See [Issue 1](#issue-1----pip3-install-fails-on-kalidebian).

Verify installation:
```bash
python3 -c "import scapy; print('scapy OK')"
```

### Step 2 — Enable IP Forwarding (Attacker machine)

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Verify:
```bash
cat /proc/sys/net/ipv4/ip_forward   # must print 1
```

> Without this, intercepted packets are dropped by the kernel. The victim loses
> internet connection — that is a DoS, not a MITM. This step is mandatory.

### Step 3 — Disable Windows Firewall (Victim machine, if Windows)

Open Command Prompt as Administrator:
```cmd
netsh advfirewall set allprofiles state off
```

> Windows Firewall blocks ARP broadcast replies by default, making the victim
> invisible to the network scan. **Re-enable it after testing** (see Cleanup).
> See [Issue 2](#issue-2----windows-laptop-not-appearing-in-the-arp-scan).

---

## Network Topology

```
         WiFi Router / Mobile Hotspot
               /              \
              /                \
        Victim (V)         Attacker (M)
     Windows / any OS       Linux
     (just browses)       runs main.py
```

> ⚠️ All three must be on the **same L2 broadcast domain** (same WiFi network).
> ARP cannot cross routers — the attack only works within one subnet.
>
> If using a **mobile hotspot**: test with `ping` between the two laptops first.
> If ping fails, AP Isolation is ON and the attack won't work.
> See [Issue 3](#issue-3----ap-isolation-on-mobile-hotspot-blocks-the-attack).

---

## Running the Attack — Step by Step

### Before Each Run — Quick Checklist

```
[ ] Both laptops on the same WiFi
[ ] sudo sysctl -w net.ipv4.ip_forward=1   (Attacker)
[ ] Windows Firewall off                    (Victim, if Windows)
[ ] ping works between the two laptops      (test AP isolation)
```

---

### Step 1 — Take ARP Snapshot Before Attack (Victim machine)

On the victim (Windows), open Command Prompt and run:
```cmd
arp -a
```

Note the gateway's MAC address under your WiFi interface section:
```
Interface: 192.168.0.107 --- 0x2
  Internet Address    Physical Address      Type
  192.168.0.1         40-ed-00-7b-9e-1d     dynamic   ← this is the real gateway MAC
```

> Save this screenshot — you'll compare it to the poisoned state later.

---

### Step 2 — Ping the Victim First (Attacker machine)

```bash
ping -c 2 <victim_ip>
```

> This moves the victim's ARP entry from `STALE` to `REACHABLE`, making it visible
> to the scan. Skip this and the victim may not appear in the device list.
> See [Issue 2 — Cause 3](#issue-2----windows-laptop-not-appearing-in-the-arp-scan).

---

### Step 3 — Start the Attack (Attacker machine)

```bash
sudo python3 main.py
```

**Interactive prompts:**

```
[!] Lab/demo use only -- run this only against devices you own or
    have explicit permission to test.

[+] Available network interfaces:
  0   lo
  1   enp42s0
  2   wlo1  <- scapy's default guess
  ...

[?] Select the interface connected to the target network: 2
```
→ Enter the number of your WiFi interface (usually the one marked as scapy's guess).

```
[*] Scanning network 192.168.0.0/24 on interface wlo1...

[+] Active devices found on network:
Index  IP Address         MAC Address
------------------------------------------
0      192.168.0.1        40:ed:00:7b:9e:1d  (Gateway)
1      192.168.0.107      64:6e:e0:ee:03:4a
2      192.168.0.117      48:45:e6:a0:9b:fb

[?] Enter the index number of the victim device: 1
```
→ Enter the index of the **victim** — never pick index 0 (the Gateway).

```
[+] Target locked -> Victim IP: 192.168.0.107 | Victim MAC: 64:6e:e0:ee:03:4a
[+] Gateway locked -> Gateway IP: 192.168.0.1 | Gateway MAC: 40:ed:00:7b:9e:1d
[*] Starting attack framework...

[*] Poisoner active: spoofing gateway (192.168.0.1) and victim (192.168.0.107)
[*] Forwarder active: routing traffic for 192.168.0.107...
[*] Sniffer active: monitoring 192.168.0.107... (saving evidence to mitm_capture.pcap)

[Forwarder] Relayed: Victim -> 142.250.206.67
[Forwarder] Relayed: 142.250.206.67 -> Victim
```
→ The `[Forwarder] Relayed:` lines confirm the attack is working.

---

### Step 4 — Verify the Poison (Victim machine)

On the victim (Windows), run:
```cmd
arp -a
```

The gateway's MAC should now be **the attacker's MAC**:
```
192.168.0.1    48-45-e6-a0-9b-fb    dynamic   ← attacker's MAC, not the real gateway
```

> If the MAC hasn't changed: run `arp -d *` on Windows to clear the cache and check again.
> See [Issue 6](#issue-6----arp-poisoning-not-taking-effect-on-windows).

---

### Step 5 — Capture HTTP Traffic (Victim machine)

On the victim, visit a **plain HTTP** site in the browser:
```
http://neverssl.com
http://httpforever.com
```

On the attacker terminal you should see:
```
[HTTP Intercepted] 192.168.0.107:54321 -> 34.223.124.45:80
    Payload: b'GET / HTTP/1.1\r\nHost: neverssl.com\r\nUser-Agent: Mozilla/5.0...'
```

> Chrome redirects most sites to HTTPS automatically. Use Firefox and type the
> `http://` prefix explicitly.

---

### Step 6 — Capture HTTPS Metadata (Victim machine)

Visit any HTTPS site:
```
https://www.youtube.com
https://www.facebook.com
```

On the attacker terminal:
```
[HTTPS ClientHello] 192.168.0.107 -> 142.250.206.67  SNI: www.youtube.com
[HTTPS Activity] Handled 50 secure packets (payload encrypted -- only metadata visible: size/timing/SNI).
```

> HTTPS payload is encrypted and cannot be read. Only the SNI (Server Name Indication)
> hostname leaks because it is sent in plaintext during the TLS handshake.

---

### Step 7 — Run the Detector (Victim machine / separate terminal)

Run this **while the attack is active** to demonstrate detection.

**On WSL (Kali):**
```bash
# Find your interface first
ip link show
# Look for the interface whose MAC matches your Windows WiFi adapter MAC
# (check Windows with: ipconfig /all)

sudo python3 detector.py eth2   # replace eth2 with your interface
```

**On a separate Linux machine:**
```bash
sudo python3 detector.py wlan0
```

Expected output:
```
[*] ARP anomaly detector running on eth2. Ctrl+C to stop.

[Detector] Learned mapping: 192.168.0.1  -> 40:ed:00:7b:9e:1d
[Detector] Learned mapping: 192.168.0.107 -> 64:6e:e0:ee:03:4a
[ALERT] Possible ARP spoofing! 192.168.0.1 was 40:ed:00:7b:9e:1d, now claimed by 48:45:e6:a0:9b:fb
```

> See [Issue 5](#issue-5----wsl-detectorpy-which-interface-to-use) if you're using WSL.

---

### Step 8 — Stop and Restore

Press `Ctrl+C` on the attacker terminal:
```
^C
[*] Shutting down and restoring the network...
[*] Restoring original ARP tables...
[+] Network state restored successfully.
```

Verify restoration on the victim (Windows):
```cmd
arp -d *
arp -a
```

The gateway should show its **original** MAC again:
```
192.168.0.1    40-ed-00-7b-9e-1d    dynamic   ← real gateway MAC restored ✓
```

---

## Cleanup (After Every Session)

**Attacker machine (Linux):**
```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

**Victim machine (Windows CMD as Administrator):**
```cmd
netsh advfirewall set allprofiles state on
```

Verify firewall is back on:
```cmd
netsh advfirewall show allprofiles | findstr "State"
# Should show: State   ON
```

---

## Defense: How `detector.py` Works

`detector.py` is a passive ARP anomaly detector. It builds a trust table on
first observation (trust-on-first-use): the first MAC seen claiming an IP is
recorded as legitimate. Every subsequent ARP frame for that IP is compared against
the stored MAC — if it differs, an `[ALERT]` is printed.

This is exactly the ARP poisoning signature: the poisoner repeatedly claims a
new MAC for the gateway's IP, which the detector catches immediately.

**What can cause false positives:**
- A device getting a new DHCP lease (IP reassigned to different MAC)
- A NIC being replaced on a machine
- A laptop switching between Wi-Fi and Ethernet (different MAC per adapter)

**Limitations:**
- Trust-on-first-use: if the attacker was poisoning before the detector started,
  the spoofed MAC gets learned as legitimate
- Detection only — it does not block the attack or restore ARP tables
- Must be on the same broadcast domain as the attack

---

## Issues Faced & Solutions

### Issue 1 — `pip3 install` fails on Kali/Debian

**Error:** `externally-managed-environment`  
**Cause:** PEP 668 — newer Debian/Kali block pip from modifying system Python.  
**Fix:**
```bash
sudo apt install python3-scapy -y
```

---

### Issue 2 — Windows laptop not appearing in the ARP scan

**Cause 1 — Windows Firewall blocks ARP broadcast replies**  
```cmd
netsh advfirewall set allprofiles state off
```
Re-enable after testing: `netsh advfirewall set allprofiles state on`

**Cause 2 — scan timeout too short for WiFi**  
Increased `timeout=2` to `timeout=10` in `config.py`. Also added OS ARP cache
fallback: after the broadcast scan, `ip neigh show` is parsed to find devices
the scan still missed.

**Cause 3 — ARP cache entry in STALE state**  
An entry in `STALE` state means the kernel hasn't verified the mapping recently,
making it unreliable for scanning.  
**Fix:** ping the victim once before running `main.py` — this forces the kernel
to verify and move the entry to `REACHABLE`.
```bash
ping -c 2 <victim_ip> && sudo python3 main.py
```

---

### Issue 3 — AP Isolation on mobile hotspot blocks the attack

**Cause:** Most mobile hotspots enable AP isolation by default, which blocks
Layer 2 frames between connected clients. ARP frames between victim and attacker
never get delivered.  
**Quick test:**
```bash
ping <victim_ip>   # if this fails, AP isolation is ON
```
**Fix options:**
- Use a real WiFi router (AP isolation usually off by default)
- Android hotspot sometimes works (no isolation setting exposed)
- iPhone hotspot: always isolated — **does not work**
- Configure Linux laptop as AP with `ap_isolate=0` in `hostapd.conf`

---

### Issue 4 — Ctrl+C not triggering ARP restoration

**Cause:** Scapy's `sniff()` installs its own SIGINT handler, intercepting
Ctrl+C before Python's `KeyboardInterrupt` reaches `main()`.  
**Fix:** Register `signal.signal(signal.SIGINT, handler)` explicitly **after**
`TARGET_CONFIG` is fully populated, so the handler always has the IP/MAC data
it needs to call `restore_network()`.

```python
# WRONG — registered before TARGET_CONFIG is filled, handler sees None values
signal.signal(signal.SIGINT, handle_exit)
TARGET_CONFIG["victim_ip"] = victim_ip   # filled after registration

# CORRECT — registered after TARGET_CONFIG is fully filled
TARGET_CONFIG["victim_ip"] = victim_ip
signal.signal(signal.SIGINT, handle_exit)   # handler now sees real values
```

---

### Issue 5 — WSL `detector.py`: which interface to use

**Cause:** Under WSL2 Mirrored Networking mode, the Windows WiFi adapter appears
inside WSL as a generic name (`eth0`, `eth2`, etc.) — not its Windows adapter name.  
**Fix:**
```bash
# Inside WSL:
ip link show
# Find the interface whose MAC matches your Windows WiFi MAC
# Check Windows MAC with: ipconfig /all (look for "Physical Address")
```
The matching interface is the one to pass to `detector.py`.

---

### Issue 6 — ARP poisoning not taking effect on Windows

**Cause:** Windows ARP implementation can ignore unsolicited updates or hold a
longer cache TTL than expected.  
**Fix:**
```cmd
arp -d *          :: clear the entire ARP cache
arp -a            :: verify — gateway should now show attacker's MAC
```

---

## Security Notes

> ⚠️ Only run this on networks you own or have **explicit written permission** to test.
> Unauthorized ARP poisoning is illegal in most jurisdictions.

| Action | Command |
|---|---|
| Re-enable Windows Firewall | `netsh advfirewall set allprofiles state on` |
| Disable IP forwarding | `sudo sysctl -w net.ipv4.ip_forward=0` |
| Clear poisoned ARP cache | `arp -d *` (Windows) |

Always let `restorer.py` finish after Ctrl+C. If the terminal is closed before
restoration completes, the victim's ARP cache remains poisoned until it expires
naturally (typically 30s–20min depending on OS).