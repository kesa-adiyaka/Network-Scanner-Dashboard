import sys
import os
import ssl
import struct
import subprocess
import re
import socket
import urllib.request
import time
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, IP, TCP, DNS, DNSQR, srp, sr1

OUI_DATABASE = {}

# ----------------------------------------------------------------------
# Passive TCP/IP stack fingerprint table (fallback signal only — see
# classify_device priority order below; self-reported data always wins).
# ----------------------------------------------------------------------
TTL_SIGNATURES = {
    64: "Linux / Android / macOS",
    128: "Windows",
    255: "Network Gear (Cisco/Solaris)",
}

WINDOW_SIGNATURES = {
    65535: "Windows / macOS",
    64240: "Linux (modern kernel)",
    5840: "Linux (older kernel)",
    14600: "Linux (older kernel)",
    8192: "Windows (legacy)",
}

# mDNS service types worth asking about directly. Each one that answers
# is a self-reported hint about device class, which beats TTL/window
# guessing outright.
MDNS_SERVICE_TYPES = {
    "_airplay._tcp.local.": "Apple Device (AirPlay)",
    "_googlecast._tcp.local.": "Google Cast / Chromecast",
    "_homekit._tcp.local.": "HomeKit Accessory",
    "_spotify-connect._tcp.local.": "Spotify Connect Device",
    "_ipp._tcp.local.": "Network Printer",
    "_printer._tcp.local.": "Network Printer",
    "_device-info._tcp.local.": "Apple Device",
    "_smb._tcp.local.": "File Share Host",
    "_ssh._tcp.local.": "SSH-Capable Host",
}
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

BANNER_SIGNATURES = [
    (re.compile(r"OpenSSH", re.I), "Linux / Unix Server"),
    (re.compile(r"nginx", re.I), "Web Server (Linux likely)"),
    (re.compile(r"apache", re.I), "Web Server (Linux likely)"),
    (re.compile(r"lighttpd", re.I), "Embedded / Router Web UI"),
    (re.compile(r"RouterOS", re.I), "Network Gear (MikroTik)"),
    (re.compile(r"Microsoft-IIS", re.I), "Windows Server"),
    (re.compile(r"Windows", re.I), "Windows Machine"),
]


# ----------------------------------------------------------------------
# OUI / hostname / basic ARP (unchanged from Phase 1)
# ----------------------------------------------------------------------

def load_oui_database():
    """Parses local oui.txt file and loads MAC-to-Vendor mappings."""
    global OUI_DATABASE
    oui_file_path = "oui.txt"

    if not os.path.exists(oui_file_path):
        return

    try:
        with open(oui_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if "(base 16)" in line:
                    parts = line.split("(base 16)")
                    if len(parts) == 2:
                        oui_prefix = parts[0].strip().upper()
                        company_name = parts[1].strip()
                        OUI_DATABASE[oui_prefix] = company_name
    except Exception:
        pass


def get_local_cidr():
    """Dynamically fetches the active network route in CIDR notation."""
    try:
        route_output = subprocess.check_output("ip route show default", shell=True, text=True)
        interface_match = re.search(r'dev (\S+)', route_output)
        if interface_match:
            interface = interface_match.group(1)
            addr_output = subprocess.check_output(f"ip route show dev {interface}", shell=True, text=True)
            cidr_match = re.search(r'([\d.]+/\d+)', addr_output)
            if cidr_match:
                return cidr_match.group(1)
    except Exception:
        pass
    return "192.168.1.0/24"


def resolve_vendor_locally(mac_address):
    """Looks up device manufacturer using loaded OUI database."""
    oui = "".join(mac_address.split(":")[:3]).upper()
    return OUI_DATABASE.get(oui, "Unknown")


def resolve_hostname(ip_address):
    """Performs a standard reverse DNS lookup to resolve the device's network hostname."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown-Host"


def probe_open_ports(ip_address):
    """Checks a handful of common ports and returns which ones are open."""
    ports_to_check = [22, 80, 443, 445, 8080, 8443, 62078]
    open_ports = []

    for port in ports_to_check:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            continue

    return open_ports


def fingerprint_stack(ip_address, open_ports):
    """Active TTL/window fingerprint via a single SYN probe. Fallback signal only."""
    probe_port = open_ports[0] if open_ports else 80

    try:
        pkt = IP(dst=ip_address) / TCP(dport=probe_port, flags="S")
        response = sr1(pkt, timeout=1, verbose=False)
    except Exception:
        response = None

    if response is None or not response.haslayer(TCP):
        return "Unknown", "Unknown", None, None

    raw_ttl = response[IP].ttl
    raw_window = response[TCP].window

    ttl_guess = "Unknown"
    for known_ttl in sorted(TTL_SIGNATURES.keys()):
        if raw_ttl <= known_ttl:
            ttl_guess = TTL_SIGNATURES[known_ttl]
            break

    window_guess = WINDOW_SIGNATURES.get(raw_window, "Unknown")

    return ttl_guess, window_guess, raw_ttl, raw_window


# ----------------------------------------------------------------------
# Banner grabbing — self-reported service identity, no guessing.
# ----------------------------------------------------------------------

def grab_banner(ip_address, open_ports):
    """
    Attempts to pull a service banner from the first useful open port.
    HTTP(S): sends a HEAD request and reads the Server: header.
    SSH: just reads what the server sends immediately on connect.
    Returns the raw banner string, or None if nothing usable was grabbed.
    """
    if 22 in open_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect((ip_address, 22))
                banner = s.recv(128).decode(errors="ignore").strip()
                if banner:
                    return banner
        except Exception:
            pass

    for port, use_tls in [(80, False), (8080, False), (443, True), (8443, True)]:
        if port not in open_ports:
            continue
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(1.5)
            raw_sock.connect((ip_address, port))
            sock = raw_sock
            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock)
            request = f"HEAD / HTTP/1.0\r\nHost: {ip_address}\r\n\r\n".encode()
            sock.sendall(request)
            response = sock.recv(1024).decode(errors="ignore")
            sock.close()
            match = re.search(r"Server:\s*(.+)", response, re.I)
            if match:
                return match.group(1).strip()
        except Exception:
            continue

    return None


def match_banner_signature(banner_text):
    """Maps a raw banner string to a human-readable device/OS category."""
    if not banner_text:
        return None
    for pattern, label in BANNER_SIGNATURES:
        if pattern.search(banner_text):
            return label
    return None


# ----------------------------------------------------------------------
# mDNS discovery — one broadcast round covering the whole subnet at once,
# not per-device. Devices that answer are self-announcing their service.
# ----------------------------------------------------------------------

def query_mdns_services(timeout=2.0):
    """
    Sends PTR queries for a curated list of common mDNS service types and
    collects which source IPs respond to which. Returns {ip: [service_labels]}.
    """
    results = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("", MDNS_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.3)

        for service_name in MDNS_SERVICE_TYPES:
            try:
                query = DNS(rd=1, qd=DNSQR(qname=service_name, qtype="PTR"))
                sock.sendto(bytes(query), (MDNS_ADDR, MDNS_PORT))
            except Exception:
                continue

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception:
                break

            src_ip = addr[0]
            try:
                dns_resp = DNS(data)
                if dns_resp.ancount == 0:
                    continue
                for i in range(dns_resp.ancount):
                    rr = dns_resp.an[i]
                    rrname = rr.rrname.decode(errors="ignore") if isinstance(rr.rrname, bytes) else str(rr.rrname)
                    for svc_key, label in MDNS_SERVICE_TYPES.items():
                        if svc_key.rstrip(".") in rrname:
                            results.setdefault(src_ip, set()).add(label)
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if sock:
            sock.close()

    return {ip: sorted(labels) for ip, labels in results.items()}


# ----------------------------------------------------------------------
# SSDP discovery — devices self-report friendlyName/modelName via the
# LOCATION XML document. This is the strongest identity signal available.
# ----------------------------------------------------------------------

def query_ssdp_devices(timeout=2.0):
    """Sends an SSDP M-SEARCH and collects SERVER/LOCATION headers per source IP."""
    results = {}
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST:{SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN:"ssdp:discover"\r\n'
        "MX:2\r\n"
        "ST:ssdp:all\r\n\r\n"
    ).encode()

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        sock.sendto(message, (SSDP_ADDR, SSDP_PORT))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            src_ip = addr[0]
            text = data.decode(errors="ignore")
            server_match = re.search(r"SERVER:\s*(.+)", text, re.I)
            location_match = re.search(r"LOCATION:\s*(.+)", text, re.I)
            entry = results.setdefault(src_ip, {})
            if server_match:
                entry["server"] = server_match.group(1).strip()
            if location_match:
                entry["location"] = location_match.group(1).strip()
    except Exception:
        pass
    finally:
        if sock:
            sock.close()

    return results


def fetch_ssdp_description(location_url):
    """
    Fetches the UPnP device description XML at the given LOCATION URL and
    pulls out friendlyName / modelName — the device's own self-description.
    """
    try:
        with urllib.request.urlopen(location_url, timeout=1.5) as resp:
            body = resp.read(4096).decode(errors="ignore")
        friendly = re.search(r"<friendlyName>(.*?)</friendlyName>", body, re.I)
        model = re.search(r"<modelName>(.*?)</modelName>", body, re.I)
        return (
            friendly.group(1).strip() if friendly else None,
            model.group(1).strip() if model else None,
        )
    except Exception:
        return None, None


# ----------------------------------------------------------------------
# Classification + confidence scoring
# ----------------------------------------------------------------------

def classify_device(device_info):
    """
    Priority order, strongest self-reported evidence first:
      1. SSDP friendlyName/modelName (device literally states what it is)
      2. mDNS service advertisement (device announces a known service)
      3. Banner signature (service version string)
      4. Vendor + port + TTL/window fallback heuristic
    """
    ssdp = device_info.get("ssdp", {})
    if ssdp.get("model_name") or ssdp.get("friendly_name"):
        parts = [p for p in [ssdp.get("model_name"), ssdp.get("friendly_name")] if p]
        return " / ".join(parts)[:40]

    mdns_labels = device_info.get("mdns_services", [])
    if mdns_labels:
        return mdns_labels[0]

    banner_label = match_banner_signature(device_info.get("banner"))
    if banner_label:
        return banner_label

    vendor_lower = device_info["vendor"].lower()
    open_ports = device_info["open_ports"]
    ttl_guess = device_info["ttl_guess"]
    window_guess = device_info["window_guess"]

    if "apple" in vendor_lower:
        return "Apple (iPhone/iPad)" if 62078 in open_ports else "Apple (Mac)"
    if any(v in vendor_lower for v in ["samsung", "xiaomi", "huawei"]):
        return "Android Device"
    if any(v in vendor_lower for v in ["raspberry", "espressif", "sonos", "nest", "ring", "ecobee", "philips"]):
        return "IoT / Embedded"
    if any(v in vendor_lower for v in ["cisco", "netgear", "tp-link", "ubiquiti", "mikrotik", "asus"]) and (80 in open_ports or 443 in open_ports):
        return "Network Gear (Router/AP)"

    if 445 in open_ports:
        return "Windows Machine"
    if 22 in open_ports and "Linux" in ttl_guess:
        return "Linux / Server"
    if ttl_guess == "Windows" or window_guess.startswith("Windows"):
        return "Windows Machine"
    if "Linux" in ttl_guess or "Linux" in window_guess:
        return "Linux / Server"
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        return "Web Device / IoT"

    return "Generic Endpoint"


def compute_confidence(device_info):
    """
    Weighted score, 0-100, plus the reasons that contributed. Self-reported
    signals (SSDP/mDNS/banner) dominate; inferred signals (TTL/window/vendor)
    fill the gap when nothing self-reported is available.
    """
    score = 0
    reasons = []

    ssdp = device_info.get("ssdp", {})
    if ssdp.get("model_name") or ssdp.get("friendly_name"):
        score += 40
        reasons.append("SSDP device description (friendlyName/modelName)")

    if device_info.get("mdns_services"):
        score += 30
        reasons.append(f"mDNS service advertisement ({device_info['mdns_services'][0]})")

    if device_info.get("banner"):
        score += 25
        reasons.append("Service banner grabbed")

    if device_info["vendor"] != "Unknown":
        score += 15
        reasons.append("OUI vendor match")

    if device_info["ttl_guess"] != "Unknown":
        score += 5
        reasons.append("TTL fingerprint")
    if device_info["window_guess"] != "Unknown":
        score += 5
        reasons.append("TCP window fingerprint")

    score = min(score, 100)
    if score >= 70:
        tier = "High"
    elif score >= 40:
        tier = "Medium"
    else:
        tier = "Low"

    return score, tier, reasons


# ----------------------------------------------------------------------
# Per-device enrichment worker
# ----------------------------------------------------------------------

def process_discovered_device(device_info, mdns_map, ssdp_map):
    ip = device_info["ip"]
    device_info["hostname"] = resolve_hostname(ip)

    open_ports = probe_open_ports(ip)
    device_info["open_ports"] = open_ports

    ttl_guess, window_guess, raw_ttl, raw_window = fingerprint_stack(ip, open_ports)
    device_info["ttl_guess"] = ttl_guess
    device_info["window_guess"] = window_guess
    device_info["raw_ttl"] = raw_ttl
    device_info["raw_window"] = raw_window

    device_info["banner"] = grab_banner(ip, open_ports)
    device_info["mdns_services"] = mdns_map.get(ip, [])

    ssdp_entry = ssdp_map.get(ip, {})
    friendly_name, model_name = (None, None)
    if ssdp_entry.get("location"):
        friendly_name, model_name = fetch_ssdp_description(ssdp_entry["location"])
    device_info["ssdp"] = {
        "server": ssdp_entry.get("server"),
        "friendly_name": friendly_name,
        "model_name": model_name,
    }

    device_info["device_type"] = classify_device(device_info)
    device_info["is_known_vendor"] = device_info["vendor"] != "Unknown"

    score, tier, reasons = compute_confidence(device_info)
    device_info["confidence_score"] = score
    device_info["confidence_tier"] = tier
    device_info["confidence_reasons"] = reasons

    return device_info


def scan_arp_network(target_ip_range):
    """Performs an ARP sweep, runs mDNS/SSDP discovery once, then enriches every device."""
    print(f"[*] Initializing hardware discovery on: {target_ip_range}")

    ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_layer = ARP(pdst=target_ip_range)
    packet = ether_layer / arp_layer

    try:
        answered, _ = srp(packet, timeout=3, verbose=False)
    except PermissionError:
        print("\n[-] Critical: Root privileges required.")
        sys.exit(1)

    raw_devices = []
    for _, receive in answered:
        raw_devices.append({
            "ip": receive.psrc,
            "mac": receive.hwsrc,
            "vendor": resolve_vendor_locally(receive.hwsrc)
        })

    print(f"[*] Found {len(raw_devices)} alive targets.")
    print("[*] Running mDNS service discovery...")
    mdns_map = query_mdns_services(timeout=2.0)
    print("[*] Running SSDP discovery...")
    ssdp_map = query_ssdp_devices(timeout=2.0)
    print("[*] Grabbing banners, fingerprinting, and scoring confidence...")

    enriched_devices = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(process_discovered_device, dev, mdns_map, ssdp_map)
            for dev in raw_devices
        ]
        for future in futures:
            enriched_devices.append(future.result())

    return enriched_devices


# ----------------------------------------------------------------------
# CLI report rendering
# ----------------------------------------------------------------------
BOX_WIDTH = 92


def _row(cols_widths_pairs):
    return " ".join(f"{str(text):<{width}}"[:width] for text, width in cols_widths_pairs)


def print_report(devices, target_range, elapsed_seconds):
    line = "=" * BOX_WIDTH
    thin = "-" * BOX_WIDTH

    print(f"\n{line}")
    print("NETSCAN PIPELINE - DISCOVERY REPORT".center(BOX_WIDTH))
    print(line)
    print(f"Target Range : {target_range}")
    print(f"Hosts Alive  : {len(devices)}")
    unknown_count = sum(1 for d in devices if not d["is_known_vendor"])
    low_conf_count = sum(1 for d in devices if d["confidence_tier"] == "Low")
    print(f"Unknown Vendor Devices : {unknown_count}")
    print(f"Low Confidence IDs     : {low_conf_count}")
    print(line)

    header = _row([
        ("IP Address", 15), ("Hostname", 20), ("Device / OS Guess", 28),
        ("Confidence", 12), ("Active Ports", 15)
    ])
    print(header)
    print(thin)

    sorted_devices = sorted(devices, key=lambda x: tuple(map(int, x['ip'].split('.'))))

    for dev in sorted_devices:
        ports_str = str(dev["open_ports"]) if dev["open_ports"] else "[]"
        conf_str = f"{dev['confidence_tier']} ({dev['confidence_score']})"
        flag = "  *** UNKNOWN VENDOR ***" if not dev["is_known_vendor"] else ""
        print(_row([
            (dev["ip"], 15),
            (dev["hostname"][:18], 20),
            (dev["device_type"][:26], 28),
            (conf_str, 12),
            (ports_str, 15),
        ]) + flag)

    print(line)
    print(f"Scan completed in {elapsed_seconds:.2f} seconds. {len(devices)} hosts found alive.")
    print(line)

    print("\nDetail:")
    print(thin)
    for dev in sorted_devices:
        print(f"  {dev['ip']:<15} MAC={dev['mac']:<18} Vendor={dev['vendor']:<18} "
              f"TTL={dev['raw_ttl']} Window={dev['raw_window']}")
        if dev["banner"]:
            print(f"      Banner : {dev['banner'][:70]}")
        if dev["mdns_services"]:
            print(f"      mDNS   : {', '.join(dev['mdns_services'])}")
        if dev["ssdp"]["friendly_name"] or dev["ssdp"]["model_name"]:
            print(f"      SSDP   : friendlyName={dev['ssdp']['friendly_name']} modelName={dev['ssdp']['model_name']}")
        print(f"      Confidence reasons: {', '.join(dev['confidence_reasons']) if dev['confidence_reasons'] else 'none'}")


def main():
    load_oui_database()
    target_network = sys.argv[1] if len(sys.argv) > 1 else get_local_cidr()

    start = time.time()
    discovered_devices = scan_arp_network(target_network)
    elapsed = time.time() - start

    print_report(discovered_devices, target_network, elapsed)


if __name__ == "__main__":
    main()
