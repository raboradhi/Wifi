#!/usr/bin/env python3
"""
router_doctor.py - find what is slowing down your home network.

Run it on a computer connected to your Wi-Fi (macOS, Linux or Windows):

    python3 router_doctor.py            # full test (~1 minute)
    python3 router_doctor.py --quick    # skip the download / bufferbloat test

Only the Python 3 standard library is used. Nothing is changed on your router.
"""

import argparse
import platform
import re
import socket
import statistics
import struct
import subprocess
import threading
import time
import urllib.request

OS = platform.system()  # 'Darwin', 'Linux', 'Windows'
INTERNET_HOSTS = ["1.1.1.1", "8.8.8.8"]
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=100000000"
findings = []  # (severity, message, fix)


def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              shell=isinstance(cmd, str)).stdout
    except Exception:
        return ""


def flag(sev, msg, fix):
    findings.append((sev, msg, fix))


def header(t):
    print(f"\n=== {t} ===")


# ---------------------------------------------------------------- gateway
def default_gateway():
    if OS == "Windows":
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", run("route print -4"))
    elif OS == "Darwin":
        m = re.search(r"gateway:\s*(\S+)", run(["route", "-n", "get", "default"]))
    else:
        m = re.search(r"default via (\S+)", run(["ip", "route"]))
    return m.group(1) if m else None


# ---------------------------------------------------------------- ping
def ping(host, count=20):
    if OS == "Windows":
        out = run(["ping", "-n", str(count), "-w", "1000", host], timeout=count * 2 + 10)
    else:
        out = run(["ping", "-c", str(count), "-i", "0.2", "-W", "1", host], timeout=count * 2 + 10)
    times = [float(x) for x in re.findall(r"time[=<]\s*([\d.]+)", out)]
    loss = 100.0 * (count - len(times)) / count
    if not times:
        return None
    jitter = statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0
    return {"avg": statistics.mean(times), "max": max(times), "jitter": jitter, "loss": loss}


def fmt(r):
    if not r:
        return "no reply (100% loss)"
    return f"avg {r['avg']:.1f} ms, max {r['max']:.1f} ms, jitter {r['jitter']:.1f} ms, loss {r['loss']:.0f}%"


# ---------------------------------------------------------------- DNS
def dns_query_time(server, name):
    """Raw UDP DNS A query; returns ms or None."""
    qid = 0x1234
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    q += struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        t = time.perf_counter()
        s.sendto(q, (server, 53))
        s.recvfrom(512)
        return (time.perf_counter() - t) * 1000
    except Exception:
        return None
    finally:
        s.close()


def system_dns_time(name):
    t = time.perf_counter()
    try:
        socket.getaddrinfo(name, 443)
        return (time.perf_counter() - t) * 1000
    except Exception:
        return None


# ---------------------------------------------------------------- Wi-Fi
def wifi_info():
    info = {}
    if OS == "Windows":
        out = run("netsh wlan show interfaces")
        for key, pat in [("ssid", r"^\s*SSID\s*:\s*(.+)$"), ("signal", r"Signal\s*:\s*(\d+)%"),
                         ("channel", r"Channel\s*:\s*(\d+)"), ("band", r"Band\s*:\s*(.+)$"),
                         ("radio", r"Radio type\s*:\s*(.+)$"), ("rate", r"Receive rate \(Mbps\)\s*:\s*([\d.]+)")]:
            m = re.search(pat, out, re.M)
            if m:
                info[key] = m.group(1).strip()
        if "signal" in info:  # convert % to approx dBm
            info["rssi"] = int(info["signal"]) / 2 - 100
        nets = run("netsh wlan show networks mode=bssid")
        info["neighbors"] = re.findall(r"Channel\s*:\s*(\d+)", nets)
    elif OS == "Darwin":
        out = run(["system_profiler", "SPAirPortDataType"], timeout=60)
        cur = out.split("Current Network Information:")
        if len(cur) > 1:
            block, _, rest = cur[1].partition("Other Local Wi-Fi Networks:")
            for key, pat in [("ssid", r"^\s*(.+):\s*$"), ("channel", r"Channel:\s*(\d+)"),
                             ("radio", r"PHY Mode:\s*(\S+)"), ("rate", r"Transmit Rate:\s*(\d+)")]:
                m = re.search(pat, block, re.M)
                if m:
                    info[key] = m.group(1).strip()
            m = re.search(r"Signal / Noise:\s*(-?\d+) dBm / (-?\d+) dBm", block)
            if m:
                info["rssi"], info["noise"] = int(m.group(1)), int(m.group(2))
            info["neighbors"] = re.findall(r"Channel:\s*(\d+)", rest)
    else:
        out = run(["nmcli", "-t", "-f", "ACTIVE,SSID,CHAN,SIGNAL,RATE", "dev", "wifi", "list"])
        for line in out.splitlines():
            parts = line.split(":")
            if parts[0] == "yes" and len(parts) >= 5:
                info.update(ssid=parts[1], channel=parts[2], signal=parts[3],
                            rate=parts[4].split()[0], rssi=int(parts[3]) / 2 - 100)
            elif len(parts) >= 3:
                info.setdefault("neighbors", []).append(parts[2])
        if not info:
            iw = run("iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1").strip()
            if iw:
                link = run(["iw", "dev", iw, "link"])
                m = re.search(r"signal:\s*(-?\d+)", link)
                if m:
                    info["rssi"] = int(m.group(1))
                m = re.search(r"tx bitrate:\s*([\d.]+)", link)
                if m:
                    info["rate"] = m.group(1)
                m = re.search(r"freq:\s*(\d+)", link)
                if m:
                    info["band"] = "2.4 GHz" if int(m.group(1)) < 3000 else "5/6 GHz"
    return info


def analyse_wifi(w):
    header("Wi-Fi connection")
    if not w:
        print("No Wi-Fi details found (wired connection, or the OS tool is unavailable).")
        return
    for k in ("ssid", "band", "channel", "radio", "rate", "signal", "rssi", "noise"):
        if k in w:
            print(f"  {k:8}: {w[k]}")
    rssi = w.get("rssi")
    if rssi is not None:
        if rssi < -75:
            flag("HIGH", f"Weak Wi-Fi signal ({rssi:.0f} dBm).",
                 "Move closer to the router, raise it off the floor, away from walls/microwaves, "
                 "or add a mesh node / access point.")
        elif rssi < -67:
            flag("MED", f"Mediocre Wi-Fi signal ({rssi:.0f} dBm).",
                 "Fine for browsing, but video calls/streaming may suffer. Consider router placement.")
    if "noise" in w and rssi is not None and rssi - w["noise"] < 25:
        flag("MED", f"Low signal-to-noise ratio ({rssi - w['noise']} dB).",
             "Interference nearby: change the Wi-Fi channel or move the router.")
    ch = w.get("channel")
    if ch and ch.isdigit():
        ch = int(ch)
        if ch <= 14:
            flag("MED", f"Connected on 2.4 GHz (channel {ch}).",
                 "2.4 GHz is slow and crowded. Use the 5 GHz (or 6 GHz) network if your router has one.")
            if ch not in (1, 6, 11):
                flag("LOW", f"2.4 GHz channel {ch} overlaps neighbours.",
                     "Set the router's 2.4 GHz channel to 1, 6 or 11, with 20 MHz width.")
        same = sum(1 for n in w.get("neighbors", []) if n.isdigit() and int(n) == ch)
        if same >= 4:
            flag("MED", f"{same} other networks share channel {ch}.",
                 "Pick a less crowded channel in the router's wireless settings.")
    rate = w.get("rate")
    if rate:
        try:
            if float(rate) < 100:
                flag("MED", f"Low Wi-Fi link rate ({rate} Mbps).",
                     "Usually caused by distance, 2.4 GHz, or an old Wi-Fi standard on the device/router.")
        except ValueError:
            pass
    radio = (w.get("radio") or "").lower()
    if re.search(r"802\.11[bg]\b|802\.11g", radio):
        flag("HIGH", f"Very old Wi-Fi standard in use ({w['radio']}).",
             "Disable legacy b/g modes on the router, or upgrade the router/device.")


# ---------------------------------------------------------------- devices
def count_devices():
    out = run("arp -a")
    ips = set(re.findall(r"(\d+\.\d+\.\d+\.\d+)", out))
    return len([i for i in ips if not i.startswith(("224.", "239.", "255.")) and not i.endswith(".255")])


# ---------------------------------------------------------------- download + bufferbloat
def speed_and_bufferbloat(target):
    header("Speed and bufferbloat test (~20 s)")
    idle = ping(target, 15)
    result = {"bytes": 0, "secs": 0}

    def dl():
        t = time.perf_counter()
        try:
            with urllib.request.urlopen(DOWNLOAD_URL, timeout=20) as r:
                while time.perf_counter() - t < 12:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    result["bytes"] += len(chunk)
        except Exception as e:
            result["error"] = str(e)
        result["secs"] = time.perf_counter() - t

    th = threading.Thread(target=dl)
    th.start()
    time.sleep(1.5)
    loaded = ping(target, 30)
    th.join()
    mbps = result["bytes"] * 8 / 1e6 / max(result["secs"], 0.1)
    print(f"  download     : {mbps:.1f} Mbps" + (f" (error: {result['error']})" if "error" in result else ""))
    print(f"  idle ping    : {fmt(idle)}")
    print(f"  loaded ping  : {fmt(loaded)}")
    if idle and loaded:
        bloat = loaded["avg"] - idle["avg"]
        print(f"  latency added under load: {bloat:.0f} ms")
        if bloat > 100:
            flag("HIGH", f"Severe bufferbloat: latency jumps {bloat:.0f} ms while downloading.",
                 "Turn on SQM / Smart Queue / 'QoS' (fq_codel or CAKE) in the router, set to ~90% of "
                 "your plan speed. This is the #1 cause of lag during calls/gaming when others use the internet.")
        elif bloat > 30:
            flag("MED", f"Moderate bufferbloat (+{bloat:.0f} ms under load).",
                 "Enable SQM / Smart QoS on the router if available.")
    if mbps and mbps < 25 and "error" not in result:
        flag("MED", f"Download speed is low ({mbps:.1f} Mbps).",
             "Compare with your plan. Test with a cable to the router: if wired is fast, the problem is Wi-Fi; "
             "if wired is slow too, contact your ISP.")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="skip download/bufferbloat test")
    args = ap.parse_args()

    print(f"Router Doctor - {platform.platform()}")

    gw = default_gateway()
    header("Router (gateway)")
    print(f"  gateway IP: {gw or 'not found'}")
    gw_ping = ping(gw) if gw else None
    print(f"  ping      : {fmt(gw_ping)}")
    if gw and gw_ping:
        if gw_ping["loss"] > 2:
            flag("HIGH", f"Packet loss to your own router ({gw_ping['loss']:.0f}%).",
                 "This is a Wi-Fi/local problem: interference, weak signal, or a failing router. "
                 "Reboot the router and test again closer to it.")
        if gw_ping["avg"] > 10 or gw_ping["jitter"] > 10:
            flag("HIGH" if gw_ping["avg"] > 30 else "MED",
                 f"Slow/unsteady link to your own router (avg {gw_ping['avg']:.0f} ms, jitter {gw_ping['jitter']:.0f} ms). "
                 "Should be under ~5 ms.",
                 "Wi-Fi interference or congestion. Try 5 GHz, change channel, move closer, or reboot the router.")
    elif gw:
        flag("MED", "Router does not answer ping.", "Some routers block ping. If other tests are fine, ignore this.")

    header("Internet")
    inet = None
    for h in INTERNET_HOSTS:
        r = ping(h)
        print(f"  {h:10}: {fmt(r)}")
        inet = inet or r
    if inet and gw_ping:
        extra = inet["avg"] - gw_ping["avg"]
        if inet["loss"] > 2 and gw_ping["loss"] <= 2:
            flag("HIGH", f"Packet loss beyond your router ({inet['loss']:.0f}%) but not to it.",
                 "The problem is the modem/ISP line. Reboot the modem; if it continues, call your ISP.")
        if extra > 60:
            flag("MED", f"High latency from router to internet (+{extra:.0f} ms).",
                 "Could be your ISP, or the router is overloaded. Reboot the modem and router.")
    elif not inet:
        flag("HIGH", "No reply from the internet.", "Check modem lights / ISP outage.")

    header("DNS")
    name = "example.com"
    sysdns = system_dns_time(f"rd{int(time.time())}.{name}") or system_dns_time(name)
    print(f"  system resolver : {sysdns:.0f} ms" if sysdns else "  system resolver : failed")
    best = None
    for s in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        t = dns_query_time(s, name)
        print(f"  {s:15} : {t:.0f} ms" if t else f"  {s:15} : failed")
        if t and (best is None or t < best[1]):
            best = (s, t)
    if sysdns and best and sysdns > 150 and sysdns > best[1] * 2:
        flag("MED", f"Slow DNS ({sysdns:.0f} ms vs {best[1]:.0f} ms for {best[0]}).",
             f"Set DNS in your router to {best[0]} (and a second one, e.g. 8.8.8.8). Pages will start loading faster.")

    analyse_wifi(wifi_info())

    header("Devices on the network")
    n = count_devices()
    print(f"  devices seen recently: {n} (only those this computer has talked to; real number may be higher)")
    if n > 25:
        flag("LOW", f"Many devices on the network ({n}+).",
             "Check the router's client list for unknown devices; change the Wi-Fi password if needed. "
             "Look for devices doing big uploads/backups/cameras.")

    if not args.quick:
        speed_and_bufferbloat(INTERNET_HOSTS[0])

    header("RESULT")
    if not findings:
        print("No problems detected. If it still feels slow, run this again while it is slow,\n"
              "and also run it with a cable plugged into the router to compare.")
    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    for i, (sev, msg, fix) in enumerate(sorted(findings, key=lambda f: order[f[0]]), 1):
        print(f"\n{i}. [{sev}] {msg}\n   Fix: {fix}")
    print("\nAlso always worth doing: reboot router+modem, update router firmware, "
          "and replace routers older than ~5 years.")


if __name__ == "__main__":
    main()
