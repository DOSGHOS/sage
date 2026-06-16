#!/usr/bin/env python3
import argparse
import json
from collections import defaultdict, Counter
from scapy.all import conf, PcapReader
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS, Dot15d4Beacon, Dot15d4Cmd

# Zigbee layers (names vary slightly across Scapy versions)
try:
    from scapy.layers.zigbee import ZigbeeNWK, ZigbeeAPS, ZigbeeAppDataPayload, ZigbeeSecurityHeader
except Exception:
    ZigbeeNWK = ZigbeeAPS = ZigbeeAppDataPayload = ZigbeeSecurityHeader = None

conf.dot15d4_protocol = "zigbee"  # crucial: parse 802.15.4 as Zigbee

def get_dot15d4(pkt):
    if pkt.haslayer(Dot15d4):
        return pkt[Dot15d4]
    if Dot15d4FCS and pkt.haslayer(Dot15d4FCS):
        return pkt[Dot15d4FCS]
    return None

def fmt_addr(a):
    if a is None:
        return None
    if isinstance(a, int):
        return f"0x{a:04x}" if a <= 0xFFFF else f"0x{a:016x}"
    return str(a)

def beacon_assoc_permit(beacon):
    # Association-permit is bit 15 of superframe spec
    for fld in ("superframe_spec", "sf_spec", "superframe"):
        v = getattr(beacon, fld, None)
        if isinstance(v, int):
            return bool((v >> 15) & 0x1)
    return False

def classify_findings(assets, nets, include_example_cves=True):
    vulns = []
    def add_v(scope, vid, title, severity, cwe, description, evidence, panid=None, asset=None, related_cves=None):
        vulns.append({
            "scope": scope, "id": vid, "title": title, "severity": severity, "cwe": cwe,
            "description": description, "evidence": evidence,
            "panid": panid, "asset": asset,
            "related_cves": related_cves if include_example_cves else []
        })

    # Network-level
    for panid, net in nets.items():
        if net["permit_join_seen"]:
            add_v(
                scope="network", vid="ZB-NET-PERMIT-JOIN",
                title="Permit-Join activity observed",
                severity="High",
                cwe="CWE-284 (Improper Access Control)",
                description="Permit-join beacons or ZDO Mgmt_Permit_Joining seen; new devices may join.",
                evidence={"permit_join": True},
                panid=panid,
                related_cves=[],
            )

    # Asset-level
    for aid, a in assets.items():
        if a["profiles"].get("0xc05e", 0) > 0:
            add_v(
                scope="asset", vid="ZB-ZLL-LEGACY",
                title="Legacy Zigbee Light Link (ZLL) traffic",
                severity="Medium",
                cwe="CWE-326 (Inadequate Encryption Strength) / legacy commissioning weaknesses",
                description="ZLL commissioning is legacy vs Zigbee 3.0 and historically weaker.",
                evidence={"profiles": list(a["profiles"].items())},
                asset=aid,
                related_cves=["CVE-2020-6007"]  # example context, not proof
            )
        if a["unencrypted_aps_frames"] > 0:
            add_v(
                scope="asset", vid="ZB-APS-PLAINTEXT",
                title="Unencrypted Zigbee APS frames observed",
                severity="High",
                cwe="CWE-311 (Missing Encryption)",
                description="APS frames without Zigbee security header indicate plaintext app data.",
                evidence={"count": a["unencrypted_aps_frames"]},
                asset=aid,
                related_cves=[]
            )
        if a["join_events"] > 0 or a["device_announces"] > 0:
            add_v(
                scope="asset", vid="ZB-JOIN-ACTIVITY",
                title="Join/Association activity observed",
                severity="Medium",
                cwe="CWE-285 (Improper Authorization) – contextual",
                description="Association or Device Announce frames seen. If unintended, onboarding may be open.",
                evidence={"assoc": a["join_events"], "announces": a["device_announces"]},
                asset=aid,
                related_cves=[]
            )
    return vulns

def analyze_pcap(path):
    assets = defaultdict(lambda: {
        "short_addrs": set(),
        "ext_addrs": set(),
        "panids": set(),
        "profiles": Counter(),
        "clusters": Counter(),
        "frames": 0,
        "unencrypted_aps_frames": 0,
        "join_events": 0,
        "device_announces": 0
    })
    nets = defaultdict(lambda: {"devices": set(), "permit_join_seen": False})
    findings = []

    try:
        reader = PcapReader(path)
    except Exception as e:
        return {"pcap": path, "error": f"Could not read: {e}", "networks": [], "assets": [], "findings": [], "vulns": []}

    for p in reader:
        d15 = get_dot15d4(p)
        if d15 is None:
            continue

        panid = getattr(d15, "dest_panid", None) or getattr(d15, "src_panid", None)

        # MAC src addressing
        mac_src = getattr(d15, "src_addr", None)
        short_src = mac_src if isinstance(mac_src, int) and mac_src <= 0xFFFF else None
        ext_src = mac_src if isinstance(mac_src, int) and mac_src and mac_src > 0xFFFF else None

        # Prefer extended, then short, then NWK source
        nwk_src = None
        if ZigbeeNWK and p.haslayer(ZigbeeNWK):
            try:
                nwk_src = getattr(p[ZigbeeNWK], "source", None)
            except Exception:
                nwk_src = None
        key = fmt_addr(ext_src) or fmt_addr(short_src) or fmt_addr(nwk_src) or "unknown"

        a = assets[key]
        a["frames"] += 1
        if short_src: a["short_addrs"].add(fmt_addr(short_src))
        if ext_src:   a["ext_addrs"].add(fmt_addr(ext_src))
        if panid:
            pan_s = fmt_addr(panid)
            a["panids"].add(pan_s)
            nets[pan_s]["devices"].add(key)

        # Beacons and MAC commands
        if p.haslayer(Dot15d4Beacon):
            if beacon_assoc_permit(p[Dot15d4Beacon]) and panid:
                nets[fmt_addr(panid)]["permit_join_seen"] = True
                findings.append({"type": "beacon_association_permit", "panid": fmt_addr(panid), "src": key})

        if p.haslayer(Dot15d4Cmd):
            cmd = p[Dot15d4Cmd].cmd_id
            if cmd in (0x01, 0x02):  # Assoc Req/Resp
                a["join_events"] += 1

        # Zigbee APS/ZCL metadata
        profile = cluster = None
        if ZigbeeAppDataPayload and p.haslayer(ZigbeeAppDataPayload):
            app = p[ZigbeeAppDataPayload]
            profile = getattr(app, "profile", None)
            cluster = getattr(app, "cluster", None)
        elif ZigbeeAPS and p.haslayer(ZigbeeAPS):
            aps = p[ZigbeeAPS]
            profile = getattr(aps, "profile", None)
            cluster = getattr(aps, "cluster", None)

        if profile is not None:
            a["profiles"][f"0x{profile:04x}"] += 1
        if cluster is not None:
            a["clusters"][f"0x{cluster:04x}"] += 1
            if cluster == 0x0013:  # Device Announce
                a["device_announces"] += 1
            if cluster in (0x0036, 0x8036) and panid:  # Mgmt Permit Joining
                nets[fmt_addr(panid)]["permit_join_seen"] = True
                findings.append({"type": "permit_join_observed", "panid": fmt_addr(panid), "src": key})

        # Unencrypted APS heuristic: APS present but no ZigbeeSecurityHeader
        if (ZigbeeAPS and p.haslayer(ZigbeeAPS)) or (ZigbeeAppDataPayload and p.haslayer(ZigbeeAppDataPayload)):
            if ZigbeeSecurityHeader and not p.haslayer(ZigbeeSecurityHeader):
                a["unencrypted_aps_frames"] += 1

    reader.close()

    vulns = classify_findings(assets, nets, include_example_cves=True)

    report = {
        "pcap": path,
        "networks": [
            {"panid": panid, "device_count": len(net["devices"]), "permit_join_seen": net["permit_join_seen"]}
            for panid, net in nets.items()
        ],
        "assets": [
            {
                "id": aid,
                "panids": sorted(a["panids"]),
                "short_addrs": sorted(a["short_addrs"]),
                "ext_addrs": sorted(a["ext_addrs"]),
                "frames_seen": a["frames"],
                "top_profiles": a["profiles"].most_common(5),
                "top_clusters": a["clusters"].most_common(5),
                "hints": {
                    "unencrypted_aps_frames": a["unencrypted_aps_frames"],
                    "join_events": a["join_events"],
                    "device_announces": a["device_announces"]
                }
            }
            for aid, a in assets.items()
        ],
        "findings": findings,
        "vulns": vulns
    }
    return report

def print_table(vulns):
    if not vulns:
        print("No vulnerabilities found.")
        return
    cols = ["Scope", "ID", "Severity", "CWE", "PANID", "Asset", "Title", "Related CVEs"]
    print("-" * 110)
    print("{:<8} {:<20} {:<8} {:<40} {:<8} {:<18} {}".format("Scope","ID","Severity","CWE","PANID","Asset","Title"))
    print("-" * 110)
    for v in vulns:
        print("{:<8} {:<20} {:<8} {:<40} {:<8} {:<18} {}".format(
            v["scope"], v["id"], v["severity"], v["cwe"][:40],
            v.get("panid") or "-", v.get("asset") or "-", v["title"]
        ))
        if v.get("related_cves"):
            print(" " * 10 + "Related CVEs: " + ", ".join(v["related_cves"]))
    print("-" * 110)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Zigbee non-IP vulnerability scanner (offline pcap/pcapng)")
    ap.add_argument("pcaps", nargs="+", help="Paths to .pcap or .pcapng files")
    ap.add_argument("--json", action="store_true", help="Print full JSON report")
    args = ap.parse_args()

    all_reports = [analyze_pcap(p) for p in args.pcaps]

    for r in all_reports:
        print(f"\n=== Report for: {r.get('pcap')} ===")
        if "error" in r:
            print(f"Error: {r['error']}")
            continue
        print_table(r["vulns"])
        if args.json:
            print(json.dumps(r, indent=2))
