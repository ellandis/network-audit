# Network Audit

A Python tool that maps a home or small-office network and rates its security risks. It runs the same checks a network technician would run by hand (`ipconfig`, `ping`, `tracert`, `nslookup`, `arp`), parses the output, identifies every device by manufacturer, and writes a single HTML report with risk findings and fixes.

Built as a hands-on project covering CompTIA Network+ topics: IP addressing and subnetting, NAT, routing, DNS, ARP and MAC addressing, and common LAN attack surfaces.

## What it does

| Step | Command | What the script extracts |
|---|---|---|
| Network config | `ipconfig /all` | Active adapter, IP, subnet mask, gateway, DNS servers, NetBIOS status. Skips disconnected and virtual adapters automatically. |
| Connectivity | `ping` | Loss, latency and TTL for the gateway, any upstream router, the internet (8.8.8.8) and DNS (google.com) |
| Path | `tracert` | Every hop to the internet, labeled Local or Internet, so the edge of the LAN is visible |
| DNS | `nslookup` | Which server answered and how many IPv4/IPv6 records came back |
| Discovery | parallel ping sweep + `arp -a` | Every device on the subnet, with manufacturer looked up from the MAC's OUI |
| Risk rating | — | Findings rated High / Medium / Investigate / Low, each with why it matters and how to fix it |

### Risk checks

- **IoT on a flat network:** cameras, TVs, consoles and smart plugs sharing a network with computers
- **NetBIOS over TCP/IP and LLMNR enabled:** legacy name-resolution protocols that let an attacker on the LAN capture password hashes (e.g. with Responder)
- **Duplicate MAC on multiple IPs:** usually a stale DHCP lease, but also a classic sign of ARP spoofing
- **Double NAT:** detected automatically when a private DNS server sits outside the local subnet
- **Unencrypted ISP DNS:** every lookup visible to the ISP

## How it works (highlights)

- **Double-NAT detection:** if a DNS server is a private address *outside* the local subnet, there is a second router upstream. The TTL then confirms it: replies from the mesh router arrive with TTL 64, from the ISP gateway with 63, one hop further.
- **Fast discovery:** a /22 has 1,022 hosts. Pinging them one at a time would take ~5 minutes; a `ThreadPoolExecutor` with 64 workers does it in ~20 seconds, and each ping fills the ARP table even for devices that ignore ICMP.
- **Randomized MAC detection:** phones use private Wi-Fi addresses. The script checks the locally-administered bit (`int(mac[1], 16) & 0b10`) and skips the vendor lookup for those.
- **Rate-limit-safe vendor lookups:** results are cached per OUI and requests are spaced to respect the free API's limit.
- **Safe HTML output:** every value from command output is passed through `html.escape()` before it goes into the report, so a malicious hostname can't inject script (XSS).

## Usage

Requires Windows and Python 3.10+. No third-party packages.

```
python audit.py
```

Takes about a minute. Produces `network_report.html` (open in a browser) and `network_report.json` (raw data). Both are git-ignored because they contain real MAC addresses.

Only run it on networks you own or have permission to scan.

## Findings on my network

Run against my own home network (AT&T fiber gateway + TP-Link Deco mesh, 192.168.68.0/22):

| Level | Finding |
|---|---|
| High | IoT devices (cameras, TVs, game consoles, streaming device) on the same flat network as computers |
| Medium | NetBIOS over TCP/IP enabled |
| Medium | LLMNR enabled (Windows default) |
| Low | Double NAT: Deco mesh behind the AT&T gateway |
| Low | DNS handled by the ISP gateway, unencrypted |

One earlier scan also flagged a Wyze camera's MAC at two IPs. A re-scan the next morning showed only one, confirming a stale DHCP lease rather than ARP spoofing.

## Bugs I hit and fixed

- **Traceroute crash on a timed-out hop.** The IP regex `[\d.]+` matched the period in `Request timed out.` and passed `"."` to `ipaddress`. Fixed by requiring a real IPv4 shape: `\d{1,3}(?:\.\d{1,3}){3}`. Lesson: parsing command output with a permissive pattern breaks the first time the output changes.
- **Vendor API returning HTTP 429.** Firing lookups back to back hit the rate limit. Fixed with a per-OUI cache and a delay between requests.

## Limitations

- Windows only (parses Windows command output).
- Each scan is a snapshot: sleeping phones and TVs may not appear.
- Vendor-based IoT detection can't tell a TP-Link router from a TP-Link smart plug, and misses brands not in the keyword list.

## Next steps

- Remediate the findings and publish a before/after comparison
- Diff scans over time to alert on new devices
- Check devices for risky open ports (Telnet 23, SMB 445, RDP 3389)
