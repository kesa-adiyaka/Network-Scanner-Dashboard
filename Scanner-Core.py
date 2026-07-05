import sys
import os
import subprocess
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, IP, TCP, srp, sr1

OUI_DATABASE = {}

# ----------------------------------------------------------------------
# Passive TCP/IP stack fingerprint table.
# Real stacks don't always match textbook values exactly (NAT, VPNs,
# and QoS shapers can rewrite TTL / window), so this is treated as a
# weighted hint, not ground truth. It gets combined with OUI vendor
# data and open-port signatures in classify_device().
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
    ports_to_check = [22, 80, 443, 445, 8080, 8443, 5353, 62078]
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
    """
    Active TCP/IP stack fingerprint: sends a single SYN to an open port
    (falls back to 80 if none confirmed open) and inspects the SYN-ACK's
    IP TTL and TCP window size. Cheap, single-packet, and far more
    reliable than port-guessing alone.

    Returns (ttl_guess, window_guess, raw_ttl, raw_window) — any of the
    first two may be "Unknown" if no response or no signature match.
    """
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

    # TTLs decrement per hop, so match to the nearest signature below
    # the observed value rather than requiring an exact hit.
    ttl_guess = "Unknown"
    for known_ttl in sorted(TTL_SIGNATURES.keys()):
        if raw_ttl <= known_ttl:
            ttl_guess = TTL_SIGNATURES[known_ttl]
            break

    window_guess = WINDOW_SIGNATURES.get(raw_window, "Unknown")

    return ttl_guess, window_guess, raw_ttl, raw_window


def classify_device(vendor, open_ports, ttl_guess, window_guess):
    """
    Merges three independent signals - OUI vendor, open ports, and
    stack fingerprint - into one OS/device-type label. Vendor strings
    win when they're unambiguous (e.g. "Apple" tells you more than a
    TTL of 64 ever could); otherwise fall back to stack + port heuristics.
    """
    vendor_lower = vendor.lower()

    if "apple" in vendor_lower:
        if 62078 in open_ports:
            return "Apple (iPhone/iPad)"
        return "Apple (Mac)"
    if "samsung" in vendor_lower or "xiaomi" in vendor_lower or "huawei" in vendor_lower:
        return "Android Device"
    if any(v in vendor_lower for v in ["raspberry", "espressif", "sonos", "nest", "ring", "ecobee", "philips"]):
        return "IoT / Embedded"
    if any(v in vendor_lower for v in ["cisco", "netgear", "tp-link", "ubiquiti", "mikrotik", "asus"]) and (80 in open_ports or 443 in open_ports):
        return "Network Gear (Router/AP)"

    # No decisive vendor signal — lean on stack fingerprint + ports.
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
    if ttl_guess == "Network Gear (Cisco/Solaris)":
        return "Network Gear"

    return "Generic Endpoint"


def process_discovered_device(device_info):
    """Worker function to enrich basic ARP discovery data with hostname, ports, and OS/device type."""
    ip = device_info["ip"]
    device_info["hostname"] = resolve_hostname(ip)
    open_ports = probe_open_ports(ip)
    device_info["open_ports"] = open_ports

    ttl_guess, window_guess, raw_ttl, raw_window = fingerprint_stack(ip, open_ports)
    device_info["ttl_guess"] = ttl_guess
    device_info["window_guess"] = window_guess
    device_info["raw_ttl"] = raw_ttl
    device_info["raw_window"] = raw_window

    device_info["device_type"] = classify_device(
        device_info["vendor"], open_ports, ttl_guess, window_guess
    )
    device_info["is_known_vendor"] = device_info["vendor"] != "Unknown"

    return device_info


def scan_arp_network(target_ip_range):
    """Performs an asynchronous ARP Request sweep, then enriches results."""
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

    print(f"[*] Found {len(raw_devices)} alive targets. Fingerprinting OS & enriching data...")

    enriched_devices = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(process_discovered_device, raw_devices)
        for res in results:
            enriched_devices.append(res)

    return enriched_devices


# ----------------------------------------------------------------------
# CLI report rendering
# ----------------------------------------------------------------------
BOX_WIDTH = 78


def _row(cols_widths_pairs):
    """Builds one formatted row string from (text, width) pairs."""
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
    print(f"Unknown Vendor Devices : {unknown_count}")
    print(line)

    header = _row([
        ("IP Address", 15), ("Hostname", 20), ("OS Guess", 22), ("Active Ports", 18)
    ])
    print(header)
    print(thin)

    sorted_devices = sorted(devices, key=lambda x: tuple(map(int, x['ip'].split('.'))))

    for dev in sorted_devices:
        ports_str = str(dev["open_ports"]) if dev["open_ports"] else "[]"
        flag = " *** UNKNOWN VENDOR ***" if not dev["is_known_vendor"] else ""
        print(_row([
            (dev["ip"], 15),
            (dev["hostname"][:18], 20),
            (dev["device_type"][:20], 22),
            (ports_str, 18),
        ]) + flag)

    print(line)
    print(f"Scan completed in {elapsed_seconds:.2f} seconds. {len(devices)} hosts found alive.")
    print(line)

    # Detail section: MAC + vendor + raw fingerprint values, useful for
    # verifying why a device got classified the way it did.
    print("\nDetail:")
    print(thin)
    for dev in sorted_devices:
        print(f"  {dev['ip']:<15} MAC={dev['mac']:<18} Vendor={dev['vendor']:<20} "
              f"TTL={dev['raw_ttl']} ({dev['ttl_guess']})  Window={dev['raw_window']} ({dev['window_guess']})")


def main():
    import time
    load_oui_database()
    target_network = sys.argv[1] if len(sys.argv) > 1 else get_local_cidr()

    start = time.time()
    discovered_devices = scan_arp_network(target_network)
    elapsed = time.time() - start

    print_report(discovered_devices, target_network, elapsed)


if __name__ == "__main__":
    main()
