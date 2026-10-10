import subprocess
import re
import ipaddress
import time
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import html
from datetime import datetime


IOT_VENDORS = ["wyze", "espressif", "vizio", "lg innotek", "shiyuan", "google",
               "sony", "roku","nintendo", "amazon", "ring", "tuya", "samsung"]


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return result.stdout

def get_active_adapter():
    """Find the adapter that has an IPv4 address AND a default gateway."""
    output = run ("ipconfig /all")

    # Each adapter section starts with a line that isn't indented
    blocks = re.split(r"\n(?=\S)", output)

    for block in blocks:
        ip = re.search(r"IPv4 Address[ .]*: ([\d.]+)", block)
        gateway = re.search(r"Default Gateway[ .]*: ([\d.]+)", block)
        if not (ip and gateway):
            continue  # skip disconnected or gateway-less adapters (like VirtualBox)

        mask = re.search(r"Subnet Mask[ .]*: ([\d.]+)", block)
        mac = re.search(r"Physical Address[ .]*: ([\w-]+)", block)
        name = block.splitlines()[0].rstrip(":")
        netbios = re.search(r"NetBIOS over Tcpip[ .]*: (\w+)", block)


        # DNS can span several lines: first one after the colon, extras indented below
        dns = []
        dns_match = re.search(r"DNS Servers[ .]*: ([\d.]+)((?:\n\s+[\d.]+)*)", block)
        if dns_match:
            dns.append(dns_match.group(1))
            dns += dns_match.group(2).split()

        return {
            "adapter": name,
            "ip": ip.group(1),
            "mask": mask.group(1) if mask else None,
            "gateway": gateway.group(1),
            "mac": mac.group(1) if mac else None,
            "dns": dns,
            "netbios": netbios.group(1) if netbios else "Unknown",
        }
    return None

def ping(host):
    """Ping a host 4 times and pull out the key numbers."""
    output = run(f"ping -n 4 {host}")

    loss = re.search(r"\((\d+)% loss\)", output)
    avg = re.search(r"Average = (\d+)ms", output)
    ttl = re.search(r"TTL=(\d+)", output)
    resolved = re.search(r"Pinging \S+ \[([\d.]+)\]", output)  # only appears for names like google.com

    return {
        "host": host,
        "resolved_ip": resolved.group(1) if resolved else None,
        "loss_pct": int(loss.group(1)) if loss else 100,
        "avg_ms": int(avg.group(1)) if avg else None,
        "ttl": int(ttl.group(1)) if ttl else None,
        "reachable": avg is not None,
    }

def find_upstream_router(info):
    """A DNS server outside our own subnet is a sign of a second router (double NAT)."""
    network = ipaddress.ip_network(f"{info['ip']}/{info['mask']}", strict=False)
    for server in info["dns"]:
        addr = ipaddress.ip_address(server)
        if addr.is_private and addr not in network:
            return server
    return None

def traceroute(host, max_hops=20):
    """Run tracert and return one entry per hop."""
    output = run(f"tracert -h {max_hops} -w 1000 {host}")
    hops = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue  # skip header lines like "Tracing route to..."
        hop_num, rest = int(m.group(1)), m.group(2)

        times = [int(t) for t in re.findall(r"<?(\d+) ms", rest)]
        ip = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?\s*$", rest)
        name = re.search(r"ms\s+([\w.-]+)\s+\[", rest)

        if ip:
            addr = ip.group(1)
            owner = "Local" if ipaddress.ip_address(addr).is_private else "Internet"
        else:
            addr, owner = None, "No reply"

        hops.append({
            "hop": hop_num,
            "ip": addr,
            "name": name.group(1) if name else None,
            "avg_ms": round(sum(times) / len(times)) if times else None,
            "owner": owner,
        })
    return hops

def dns_lookup(name):
    """Run nslookup and report which server answered and what it returned."""
    output = run(f"nslookup {name}")
    server = re.search(r"Address:\s+([\d.]+)", output)

    answer_part = output.split("Name:", 1)[1] if "Name:" in output else ""
    ipv4 = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", answer_part)
    ipv6 = re.findall(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b", answer_part)

    return {
        "server": server.group(1) if server else None,
        "ipv4": ipv4,
        "ipv6": ipv6,
    }

def ping_sweep(network):
    """Ping every address once, in parallel, so devices show up in the ARP table."""
    def quick_ping(ip):
        run(f"ping -n 1 -w 300 {ip}")
    hosts = [str(h) for h in network.hosts()]
    with ThreadPoolExecutor(max_workers=64) as pool:
        pool.map(quick_ping, hosts)

def read_arp_table(my_ip):
    """Return the dynamic ARP entries for our active interface only."""
    output = run("arp -a")
    devices, in_section = [], False
    for line in output.splitlines():
        if line.startswith("Interface:"):
            in_section = my_ip in line  # only read the Wi-Fi section, skip VirtualBox
            continue
        m = re.match(r"\s*([\d.]+)\s+([0-9a-f-]{17})\s+dynamic", line)
        if in_section and m:
            devices.append({"ip": m.group(1), "mac": m.group(2)})
    return devices

def is_randomized(mac):
    """The second hex digit of a locally administered MAC is 2, 6, A or E."""
    return int(mac[1], 16) & 0b10 != 0

_vendor_cache = {}

def lookup_vendor(mac):
    """Look up the manufacturer from the first 3 bytes (the OUI)."""
    if is_randomized(mac):
        return "Randomized (private address)"
    oui = mac[:8].upper()
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    try:
        with urllib.request.urlopen(f"https://api.macvendors.com/{oui}", timeout=5) as resp:
            vendor = resp.read().decode()
    except urllib.error.HTTPError as e:
        vendor = "Unknown" if e.code == 404 else f"Lookup failed ({e.code})"
    except Exception:
        vendor = "Lookup failed"
    _vendor_cache[oui] = vendor
    time.sleep(1.1)  # free API allows about 1 request per second
    return vendor

def assess_risks(info, network, upstream, devices):
    """Turn everything we collected into a list of rated findings."""
    risks = []

    if info["netbios"] == "Enabled":
        risks.append(("Medium", "NetBIOS over TCP/IP enabled",
                      "Attackers on the same network can spoof name replies and capture password hashes.",
                      "Disable NetBIOS in the Wi-Fi adapter's IPv4 > Advanced > WINS settings."))

    llmnr = run(r'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast')
    if "0x0" not in llmnr:
        risks.append(("Medium", "LLMNR enabled (Windows default)",
                      "Same hash-capture attack as NetBIOS via multicast name lookups.",
                      "Set the EnableMulticast registry value to 0, or use Group Policy."))

    iot = [d for d in devices if any(v in d["vendor"].lower() for v in IOT_VENDORS)]
    if iot and network.num_addresses > 256:
        risks.append(("High", f"{len(iot)} IoT devices on the same flat network",
                      "Cameras, TVs and smart plugs rarely get updates; a compromised one can reach every computer here.",
                      "Move IoT devices to the router's IoT or guest network."))

    mac_counts = Counter(d["mac"] for d in devices)
    for mac, count in mac_counts.items():
        if count > 1:
            ips = ", ".join(d["ip"] for d in devices if d["mac"] == mac)
            risks.append(("Investigate", f"One MAC on multiple IPs ({mac})",
                          f"Seen at {ips}. Usually a stale DHCP lease, but also a sign of ARP spoofing.",
                          "Re-run arp -a later; confirm the device in the router's client list."))

    if upstream:
        risks.append(("Low", f"Double NAT via {upstream}",
                      "Two routers to secure; breaks port forwarding and some VPNs.",
                      "Put the mesh in access point mode or enable IP passthrough on the ISP gateway."))

    if all(ipaddress.ip_address(s).is_private for s in info["dns"]):
        risks.append(("Low", "DNS handled by local routers, unencrypted",
                      "The ISP can log every domain looked up.",
                      "Use encrypted DNS (Cloudflare 1.1.1.1 or Quad9) with DNS over HTTPS."))

    order = {"High": 0, "Medium": 1, "Investigate": 2, "Low": 3}
    return sorted(risks, key=lambda r: order[r[0]])

LEVEL_COLORS = {"High": "#c0392b", "Medium": "#d35400", "Investigate": "#8e44ad", "Low": "#2471a3"}

def write_report(path, info, network, upstream, pings, hops, dns, devices, risks):
    """Build a single self-contained HTML report from everything collected."""
    e = lambda v: "&mdash;" if v is None else html.escape(str(v))
    ms = lambda v: "&mdash;" if v is None else f"{v} ms"
    badge = lambda lvl: f'<span class="badge" style="background:{LEVEL_COLORS[lvl]}">{lvl}</span>'

    def table(headers, rows):
        head = "".join(f"<th>{h}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
        return f"<table><tr>{head}</tr>{body}</table>"

    counts = Counter(r[0] for r in risks)
    cards = "".join(
        f'<div class="card"><b style="color:{LEVEL_COLORS[l]}">{counts.get(l, 0)}</b>{l}</div>'
        for l in LEVEL_COLORS)

    sections = [
        ("Risk findings", table(["Level", "Finding", "Why it matters", "Fix"],
                                [[badge(l), e(t), e(w), e(f)] for l, t, w, f in risks])),
        ("Network configuration", table(["Item", "Value"], [
            ["Adapter", e(info["adapter"])], ["IP address", e(info["ip"])],
            ["Network", f"{e(network)} ({network.num_addresses - 2} usable hosts)"],
            ["Gateway", e(info["gateway"])], ["Upstream router", e(upstream)],
            ["DNS servers", e(", ".join(info["dns"]))], ["NetBIOS", e(info["netbios"])]])),
        ("Connectivity tests", table(["Target", "Result", "Loss", "Avg latency", "TTL", "Resolved IP"],
                                     [[e(p["host"]), "PASS" if p["reachable"] else "<b>FAIL</b>", f'{p["loss_pct"]}%',
                                       ms(p["avg_ms"]), e(p["ttl"]), e(p["resolved_ip"])] for p in pings])),
        ("Traceroute to 8.8.8.8", table(["Hop", "IP", "Hostname", "Avg", "Segment"],
                                        [[h["hop"], e(h["ip"]), e(h["name"]), ms(h["avg_ms"]), e(h["owner"])] for h in hops])),
        ("DNS check (google.com)", f"<p>Answered by <b>{e(dns['server'])}</b>: "
                                   f"{len(dns['ipv4'])} IPv4 and {len(dns['ipv6'])} IPv6 addresses.</p>"),
        (f"Devices found ({len(devices)})", table(["IP", "MAC", "Manufacturer"],
                                                  [[e(d["ip"]), e(d["mac"]), e(d["vendor"])] for d in devices])),
    ]
    body = "".join(f"<h2>{title}</h2>{content}" for title, content in sections)

    page = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Home Network Audit</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:auto;padding:24px;color:#222}}
h1{{margin-bottom:0}} .sub{{color:#666;margin-top:4px}}
.cards{{display:flex;gap:12px;margin:20px 0}}
.card{{flex:1;border:1px solid #ddd;border-radius:8px;padding:12px;text-align:center}}
.card b{{display:block;font-size:28px}}
table{{border-collapse:collapse;width:100%;margin-bottom:8px}}
th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left;vertical-align:top}}
th{{background:#f4f6f8}} .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px}}
</style></head><body>
<h1>Home Network Audit</h1>
<p class="sub">Generated {datetime.now():%B %d, %Y at %I:%M %p} on {e(info["adapter"])}</p>
<div class="cards">{cards}</div>{body}</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(page)



if __name__ == "__main__":
    info = get_active_adapter()
    if not info:
        raise SystemExit("No active network adapter with a gateway found.")
    network = ipaddress.ip_network(f"{info['ip']}/{info['mask']}", strict=False)
    print(f"Network: {network} ({network.num_addresses - 2} usable hosts)\n")

    upstream = find_upstream_router(info)
    targets = [info["gateway"]] + ([upstream] if upstream else []) + ["8.8.8.8", "google.com"]
    pings = []
    for t in targets:
        r = ping(t)
        pings.append(r)
        print(f"{'PASS' if r['reachable'] else 'FAIL'}  {t:15} loss={r['loss_pct']}%  avg={r['avg_ms']}ms")

    print("\nRunning traceroute (~30 seconds)...")
    hops = traceroute("8.8.8.8")
    dns = dns_lookup("google.com")

    print("Sweeping the network for devices (~20 seconds)...")
    ping_sweep(network)
    devices = read_arp_table(info["ip"])
    for dev in devices:
        dev["vendor"] = lookup_vendor(dev["mac"])
    print(f"Found {len(devices)} devices.")

    risks = assess_risks(info, network, upstream, devices)

    write_report("network_report.html", info, network, upstream, pings, hops, dns, devices, risks)
    with open("network_report.json", "w") as f:
        json.dump({"info": info, "network": str(network), "upstream": upstream, "pings": pings,
                   "hops": hops, "dns": dns, "devices": devices, "risks": risks}, f, indent=2)
    print("\nSaved network_report.html and network_report.json")