#!/usr/bin/env python3
"""
device_scan.py - list every device connected to your router and guess what it is.

Run on a computer connected to your network (macOS, Linux or Windows):

    python3 device_scan.py              # scan + look up manufacturers online
    python3 device_scan.py --offline    # do not send MAC prefixes to the vendor lookup service

Uses only the Python 3 standard library. It only pings and reads, it changes nothing.
Phones that sleep may not answer; run it twice if a device is missing.
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
import urllib.request

OS = platform.system()

# Ports that hint at the type of device
PORT_HINTS = {
    62078: "iPhone/iPad",
    8008: "Chromecast / Google TV / Android TV",
    8009: "Chromecast / Google TV / Android TV",
    7000: "Apple TV / AirPlay",
    9100: "Printer",
    631: "Printer",
    554: "Camera (RTSP)",
    1400: "Sonos speaker",
    5555: "Android device",
    3389: "Windows PC",
    445: "PC / NAS (file sharing)",
    548: "Mac / NAS",
    22: "Computer / server",
    80: "Has web page",
    443: "Has web page",
}

HOSTNAME_HINTS = [
    (r"iphone", "iPhone"), (r"ipad", "iPad"), (r"macbook|imac|mac-?mini|-mbp|mbp-", "Mac"),
    (r"apple-?tv", "Apple TV"), (r"watch", "Smart watch"),
    (r"android|galaxy|sm-[a-z]\d|redmi|xiaomi|huawei|oppo|vivo|oneplus|pixel|honor|realme", "Android phone"),
    (r"desktop-|laptop|pc-|win-|windows", "Windows PC"),
    (r"tv|bravia|webos|tizen|roku|firetv|fire-tv|shield", "Smart TV / TV box"),
    (r"playstation|ps4|ps5|xbox|nintendo|switch", "Game console"),
    (r"echo|alexa|amazon", "Amazon Echo / Alexa"), (r"google-?home|nest", "Google Nest / Home"),
    (r"printer|epson|canon|brother|hp[a-f0-9]{6}|officejet|laserjet", "Printer"),
    (r"cam|ipc|hikvision|dahua|ezviz|imou|ring|doorbell", "Camera"),
    (r"esp|tasmota|shelly|tuya|smartplug|plug|bulb|light", "Smart home device"),
]

VENDOR_HINTS = [
    (r"apple", "Apple device (iPhone/iPad/Mac)"),
    (r"samsung", "Samsung (phone/TV)"),
    (r"huawei|honor|xiaomi|oppo|vivo|oneplus|realme|motorola|zte", "Android phone"),
    (r"google", "Google (Pixel/Nest/Chromecast)"),
    (r"amazon", "Amazon (Echo/Fire TV/Kindle)"),
    (r"sony", "Sony (PlayStation/TV)"), (r"microsoft", "Microsoft (Xbox/Surface)"),
    (r"nintendo", "Nintendo console"), (r"lg electronics", "LG (TV/phone)"),
    (r"tp-link|tplink|netgear|asus|d-link|linksys|ubiquiti|zyxel|mikrotik|tenda", "Network gear / extender"),
    (r"hikvision|dahua|ezviz|hangzhou", "Camera"),
    (r"espressif|tuya|shelly|sonoff|itead", "Smart home device"),
    (r"intel|realtek|liteon|lite-on|azurewave|hon hai|foxconn|dell|lenovo|hewlett|hp inc|giga-byte|micro-star|asustek",
     "Computer / laptop"),
    (r"epson|canon|brother|seiko", "Printer"), (r"roku|tcl|hisense|vizio", "Smart TV"),
]


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              shell=isinstance(cmd, str)).stdout
    except Exception:
        return ""


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet is sent for UDP connect
        return s.getsockname()[0]
    finally:
        s.close()


def default_gateway():
    if OS == "Windows":
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", run("route print -4"))
    elif OS == "Darwin":
        m = re.search(r"gateway:\s*(\S+)", run(["route", "-n", "get", "default"]))
    else:
        m = re.search(r"default via (\S+)", run(["ip", "route"]))
    return m.group(1) if m else None


def ping_once(ip):
    if OS == "Windows":
        out = run(["ping", "-n", "1", "-w", "700", ip], timeout=3)
        return "TTL=" in out.upper()
    flag = "-W" if OS == "Linux" else "-t"
    try:
        return subprocess.run(["ping", "-c", "1", flag, "1", ip], capture_output=True, timeout=3).returncode == 0
    except Exception:
        return False


def open_ports(ip):
    found = []
    for port in PORT_HINTS:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            if s.connect_ex((ip, port)) == 0:
                found.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return found


def arp_table():
    out = run("arp -a")
    table = {}
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", line)
        if ip and mac:
            parts = re.split(r"[:-]", mac.group(0))
            norm = ":".join(p.zfill(2) for p in parts).upper()
            if norm not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                table[ip.group(1)] = norm
    return table


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def is_random_mac(mac):
    return mac[1] in "26AE"  # locally administered bit = privacy (random) address


def lookup_vendor(mac, cache):
    prefix = mac[:8]
    if prefix in cache:
        return cache[prefix]
    vendor = ""
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{prefix}",
                                     headers={"User-Agent": "device-scan"})
        with urllib.request.urlopen(req, timeout=5) as r:
            vendor = r.read().decode(errors="ignore").strip()
            if vendor.startswith("{"):
                vendor = ""
    except Exception:
        pass
    time.sleep(1.1)  # free API allows ~1 request/second
    cache[prefix] = vendor
    return vendor


def guess_type(ip, gw, me, name, vendor, mac, ports):
    if ip == gw:
        return "Router"
    if ip == me:
        return "This computer"
    n = name.lower()
    for pat, label in HOSTNAME_HINTS:
        if re.search(pat, n):
            return label
    for p in (62078, 7000, 8008, 9100, 554, 1400, 5555, 3389, 548):
        if p in ports:
            return PORT_HINTS[p]
    v = vendor.lower()
    for pat, label in VENDOR_HINTS:
        if re.search(pat, v):
            return label
    if mac and is_random_mac(mac):
        return "Phone/tablet (private Wi-Fi address)"
    if 445 in ports or 22 in ports:
        return "Computer"
    return "Unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true", help="skip online manufacturer lookup")
    ap.add_argument("--subnet", help="network to scan, e.g. 192.168.1.0/24 (default: your /24)")
    args = ap.parse_args()

    me = local_ip()
    gw = default_gateway()
    net = ipaddress.ip_network(args.subnet or f"{me}/24", strict=False)
    print(f"Scanning {net} (this computer {me}, router {gw}) ...")

    with cf.ThreadPoolExecutor(64) as ex:
        alive = {ip for ip, ok in zip(map(str, net.hosts()), ex.map(ping_once, map(str, net.hosts()))) if ok}
    arp = arp_table()
    hosts = sorted((alive | {ip for ip in arp if ipaddress.ip_address(ip) in net}) | {me},
                   key=ipaddress.ip_address)

    print(f"Found {len(hosts)} devices. Identifying them ...")
    with cf.ThreadPoolExecutor(32) as ex:
        names = dict(zip(hosts, ex.map(hostname, hosts)))
        ports = dict(zip(hosts, ex.map(open_ports, hosts)))

    cache, rows = {}, []
    for ip in hosts:
        mac = arp.get(ip, "")
        vendor = ""
        if mac and not args.offline and not is_random_mac(mac):
            vendor = lookup_vendor(mac, cache)
        if mac and is_random_mac(mac) and not vendor:
            vendor = "(private/random MAC)"
        rows.append((ip, mac, names[ip], vendor, guess_type(ip, gw, me, names[ip], vendor, mac, ports[ip])))

    print(f"\n{'IP':15} {'MAC':17} {'TYPE':36} {'MANUFACTURER':28} NAME")
    print("-" * 120)
    for ip, mac, name, vendor, kind in rows:
        print(f"{ip:15} {mac or '-':17} {kind[:36]:36} {(vendor or '-')[:28]:28} {name or '-'}")

    print(f"\nTOTAL: {len(rows)} devices")
    counts = {}
    for r in rows:
        counts[r[4]] = counts.get(r[4], 0) + 1
    for kind, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {c:3}  {kind}")

    with open("devices.json", "w") as f:
        json.dump([dict(zip(("ip", "mac", "name", "vendor", "type"), r)) for r in rows], f, indent=2)
    print("\nSaved to devices.json. Devices marked Unknown: check the router's client list, "
          "and if you don't recognise one, change your Wi-Fi password.")


if __name__ == "__main__":
    main()
