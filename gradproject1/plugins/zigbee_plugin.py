#!/usr/bin/env python3
"""
Advanced Zigbee Protocol Vulnerability Scanner Plugin
Based on latest CVE research and real-world attack patterns (2023-2025)
"""
import os, struct, binascii
from typing import Dict, Any, List, Set, Tuple
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, Packet, conf
    from scapy.layers.dot15d4 import Dot15d4, Dot15d4Data, Dot15d4Beacon, Dot15d4Cmd
    from scapy.layers.zigbee import ZigbeeNWK, ZigbeeAppDataPayload, ZigbeeSecurityHeader
    
    conf.dot15d4_protocol = "zigbee"
    
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ZigbeePlugin:
    name = "Zigbee"
    
    DEFAULT_KEYS = [
        b'\x5A\x69\x67\x42\x65\x65\x41\x6C\x6C\x69\x61\x6E\x63\x65\x30\x39',
        b'\x00' * 16,
        b'\xFF' * 16,
        b'\x01\x03\x05\x07\x09\x0B\x0D\x0F\x00\x02\x04\x06\x08\x0A\x0C\x0D',
    ]
    
    def supports(self, pcap_path: str) -> bool:
        return os.path.exists(pcap_path) and pcap_path.lower().endswith(('.pcap', '.pcapng'))
    
    def scan(self, pcap_path: str) -> Dict[str, Any]:
        if not SCAPY_AVAILABLE:
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "error": "Scapy with Zigbee support required. Run: pip install scapy pycryptodome",
                "vulns": []
            }
        
        vulns = []
        stats = {"total": 0, "zigbee": 0, "encrypted": 0, "unencrypted": 0}
        
        try:
            conf.dot15d4_protocol = "zigbee"
            packets = rdpcap(pcap_path)
            stats["total"] = len(packets)
            
            zb_packets = [p for p in packets if Dot15d4 in p or ZigbeeNWK in p]
            stats["zigbee"] = len(zb_packets)
            
            if not zb_packets:
                return {
                    "protocol": self.name,
                    "pcap": pcap_path,
                    "statistics": stats,
                    "vulns": []
                }
            
            vulns.extend(self._check_unencrypted_traffic(zb_packets, stats))
            vulns.extend(self._check_weak_keys(zb_packets))
            vulns.extend(self._check_insecure_joining(zb_packets))
            vulns.extend(self._check_replay_vulnerability(zb_packets))
            vulns.extend(self._check_key_transport_security(zb_packets))
            vulns.extend(self._check_wormhole_attack(zb_packets))
            vulns.extend(self._check_dos_patterns(zb_packets))
            vulns.extend(self._check_trust_center_issues(zb_packets))
            vulns.extend(self._check_routing_vulnerabilities(zb_packets))
            
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "statistics": stats,
                "vulns": vulns,
                "risk_score": self._calculate_risk_score(vulns),
                "topology":   self._build_topology(zb_packets),
            }
            
        except Exception as e:
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "error": f"Scan error: {str(e)}",
                "vulns": []
            }

    def _extract_nwk(self, pkt):
        """Manually extract ZigbeeNWK from packet - handles Scapy dissection issues"""
        from scapy.layers.dot15d4 import Dot15d4FCS
        # Try direct layer first
        if ZigbeeNWK in pkt:
            return pkt[ZigbeeNWK]
        # Try manual parse from payload bytes
        for layer_cls in [Dot15d4FCS, Dot15d4]:
            if layer_cls in pkt:
                payload = bytes(pkt[layer_cls].payload)
                if len(payload) >= 8:
                    try:
                        nwk = ZigbeeNWK(payload)
                        if hasattr(nwk, 'seqnum'):
                            return nwk
                    except Exception:
                        pass
        return None


    def _build_topology(self, packets: list) -> dict:
        """
        يبني topology حقيقية من الـ packets.
        يستخرج:
        - nodes: كل src/dst شاف في الـ traffic
        - edges: كل اتصال src→dst مع عدد الـ packets وحالة التشفير
        """
        from collections import defaultdict
        node_info   = {}   # addr → {count, encrypted, unencrypted, role}
        edge_info   = defaultdict(lambda: {"count":0,"encrypted":0,"unencrypted":0})

        for pkt in packets:
            nwk = self._extract_nwk(pkt)
            if nwk is None:
                continue

            src = getattr(nwk, 'source',      None)
            dst = getattr(nwk, 'destination', None)
            if src is None:
                continue

            try:
                flags_val = int(nwk.flags) if nwk.flags != '' else 0
            except (TypeError, ValueError):
                flags_val = 0
            encrypted = bool(flags_val & 0x08)

            # Register source node
            if src not in node_info:
                node_info[src] = {"count":0,"encrypted":0,"unencrypted":0,"role":"device"}
            node_info[src]["count"] += 1
            if encrypted:
                node_info[src]["encrypted"]   += 1
            else:
                node_info[src]["unencrypted"] += 1

            # Coordinator = destination 0x0000
            if dst is not None:
                if dst == 0x0000:
                    if dst not in node_info:
                        node_info[dst] = {"count":0,"encrypted":0,"unencrypted":0,"role":"coordinator"}
                    node_info[dst]["role"] = "coordinator"
                    node_info[dst]["count"] += 1

                edge_key = (src, dst)
                edge_info[edge_key]["count"] += 1
                if encrypted:
                    edge_info[edge_key]["encrypted"]   += 1
                else:
                    edge_info[edge_key]["unencrypted"] += 1

        # تحويل لـ lists
        ZIGBEE_TYPES = {
            0x0000: "Coordinator / Hub",
            0x1001: "Smart Bulb",
            0x1002: "Door Sensor",
            0x1003: "Smart Plug",
            0x1004: "Temperature Sensor",
            0x1005: "Motion Sensor",
            0x1006: "Smart Lock",
            0x1007: "Thermostat",
        }
        nodes = [
            {
                "id":          f"0x{addr:04X}",
                "label":       "Coordinator" if info["role"]=="coordinator" else f"0x{addr:04X}",
                "device_type": ZIGBEE_TYPES.get(addr, "Coordinator / Hub" if info["role"]=="coordinator" else "Zigbee Device"),
                "role":        info["role"],
                "packet_count":info["count"],
                "encrypted":   info["encrypted"],
                "unencrypted": info["unencrypted"],
                "secure":      info["unencrypted"] == 0,
                "protocol":    "Zigbee",
            }
            for addr, info in node_info.items()
        ]

        edges = [
            {
                "from":        f"0x{src:04X}",
                "to":          f"0x{dst:04X}",
                "count":       info["count"],
                "encrypted":   info["encrypted"],
                "unencrypted": info["unencrypted"],
                "secure":      info["encrypted"] >= info["unencrypted"],
            }
            for (src, dst), info in edge_info.items()
        ]

        return {"nodes": nodes, "edges": edges}

    def _check_unencrypted_traffic(self, packets: List, stats: Dict) -> List[Dict]:
        """Unencrypted data transmission"""
        vulns = []
        unenc_packets = []
        sensitive_commands = []
        
        for i, pkt in enumerate(packets):
            nwk = self._extract_nwk(pkt)
            if nwk is not None:
                try:
                    flags_val = int(nwk.flags) if nwk.flags != '' else 0
                except (TypeError, ValueError):
                    flags_val = 0
                
                sec_enabled = (flags_val & 0x08) != 0
                
                if not sec_enabled:
                    unenc_packets.append(i)
                    stats["unencrypted"] += 1
                    if ZigbeeAppDataPayload in pkt:
                        sensitive_commands.append(i)
                else:
                    stats["encrypted"] += 1
        
        if unenc_packets:
            severity = "CRITICAL" if len(unenc_packets) > 50 else "HIGH"
            percentage = (len(unenc_packets) / len(packets)) * 100
            
            vulns.append({
                "id": "ZIGBEE-001",
                "fix_code": '\n// Fix: Enable APS Encryption (Silicon Labs Zigbee SDK)\nEmberInitialSecurityState securityState;\nsecurityState.bitmask = EMBER_STANDARD_SECURITY_MODE\n                      | EMBER_TRUST_CENTER_GLOBAL_LINK_KEY\n                      | EMBER_HAVE_PRECONFIGURED_KEY;\n// Set a strong random 128-bit network key\nEmberKeyData networkKey = {{0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,\n                            0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89}};\nsecurityState.networkKey = networkKey;\nemberSetInitialSecurityState(&securityState);\n\n// TI Z-Stack (OSAL) equivalent:\n// In f8wConfig.cfg: -DSECURE=1\n// In ZDApp.c: zgConfigPANID = YOUR_PANID;\n',
                "severity": severity,
                "title": "Unencrypted Zigbee Network Traffic",
                "description": "Network transmits data without APS-level encryption, allowing eavesdropping",
                "cve": [],
                "evidence": f"{len(unenc_packets)} unencrypted packets ({percentage:.1f}% of traffic)",
                "affected_packets": unenc_packets[:20],
                "sensitive_data": len(sensitive_commands) > 0,
                "remediation": "Enable APS encryption (Security Level 5) on all data frames",
                "references": ["ZigBee 3.0 Security Specification Section 4.3"]
            })
        
        return vulns
    
    def _check_weak_keys(self, packets: List) -> List[Dict]:
        """Default or weak encryption keys"""
        vulns = []
        key_transport_count = 0
        secure_key_transport = 0
        install_code_indicators = 0
        encrypted_key_transport = 0
        
        for pkt in packets:
            if ZigbeeAppDataPayload in pkt:
                payload = pkt[ZigbeeAppDataPayload]
                if hasattr(payload, 'cluster') and payload.cluster == 0x0000:
                    if hasattr(payload, 'data'):
                        data = bytes(payload.data) if hasattr(payload.data, '__iter__') else b''
                        if len(data) > 0 and data[0] == 0x05:
                            key_transport_count += 1
                            if ZigbeeSecurityHeader in pkt:
                                encrypted_key_transport += 1
                            if len(data) > 36:
                                key_material = data[20:36]
                                if len(set(key_material)) > 8:
                                    install_code_indicators += 1
                                    secure_key_transport += 1
            
            if Dot15d4Cmd in pkt:
                cmd_id = getattr(pkt[Dot15d4Cmd], 'cmd_id', None)
                if cmd_id == 0x01:
                    if hasattr(pkt[Dot15d4Cmd], 'allocate_address'):
                        install_code_indicators += 1
        
        is_vulnerable = False
        evidence_parts = []
        
        if key_transport_count > 0:
            unencrypted_transports = key_transport_count - encrypted_key_transport
            if unencrypted_transports > 0:
                is_vulnerable = True
                evidence_parts.append(f"{unencrypted_transports} unencrypted key transport(s)")
            if key_transport_count > 2 and secure_key_transport == 0:
                is_vulnerable = True
                evidence_parts.append(f"{key_transport_count} key transports without install code derivation")
            if install_code_indicators > 0 and encrypted_key_transport > 0:
                is_vulnerable = False
        
        if is_vulnerable and evidence_parts:
            vulns.append({
                "id": "ZIGBEE-002",
                "fix_code": '\n// Fix: Use Install Codes instead of default Trust Center Link Key\n// Silicon Labs SDK — generate install code per device\n\n// 1. Generate 16-byte install code + 2-byte CRC\nuint8_t installCode[18] = { /* unique per device */ };\n\n// 2. Derive link key from install code using AES-MMO hash\nEmberKeyData derivedKey;\nemberAesHashSimple(sizeof(installCode), installCode,\n                   (uint8_t*)&derivedKey);\n\n// 3. Add the derived key to Trust Center\nemberAddOrUpdateKeyTableEntry(&deviceEUI64,\n                               true,  // is link key\n                               &derivedKey);\n\n// Zigbee2MQTT config.yaml:\n// advanced:\n//   network_key: GENERATE\n//   pan_id: GENERATE\n',
                "severity": "CRITICAL",
                "title": "Default/Weak Trust Center Link Key",
                "description": "Network may be using default Zigbee keys (ZigBeeAlliance09) or lacks install codes",
                "cve": ["CVE-2019-15911"],
                "evidence": " | ".join(evidence_parts),
                "attack_vector": "Attacker can decrypt traffic and join network with known default keys",
                "remediation": "Use install codes for key derivation, implement unique per-device keys",
                "references": ["Zigbee 3.0 Base Device Behavior Specification r22"]
            })
        
        return vulns
    
    def _check_insecure_joining(self, packets: List) -> List[Dict]:
        """Insecure network joining procedure"""
        vulns = []
        assoc_req = []
        unsecure_rejoin = []
        
        for i, pkt in enumerate(packets):
            if Dot15d4Cmd in pkt:
                cmd_id = getattr(pkt[Dot15d4Cmd], 'cmd_id', None)
                if cmd_id == 0x01:
                    assoc_req.append(i)
                if cmd_id == 0x06:
                    if ZigbeeSecurityHeader not in pkt:
                        unsecure_rejoin.append(i)
        
        if unsecure_rejoin or len(assoc_req) > 10:
            vulns.append({
                "id": "ZIGBEE-003",
                "fix_code": '\n// Fix: Restrict Join Window + Require Install Codes\n// Silicon Labs SDK\n\n// Allow joining for 60 seconds only\nemberPermitJoining(60);\n\n// After commissioning, close the network\nemberPermitJoining(0);\n\n// Zigbee2MQTT: permit_join: false (in configuration.yaml)\n// Home Assistant ZHA: disable Allow joining after commissioning\n\n// Require install code authentication:\n// zigbeeAlliance.setJoinPolicy(INSTALL_CODE_ONLY);\n',
                "severity": "HIGH",
                "title": "Insecure Network Join/Rejoin Procedure",
                "description": "Devices joining network without proper security validation",
                "cve": [],
                "evidence": f"{len(assoc_req)} join attempts, {len(unsecure_rejoin)} insecure rejoins",
                "attack_vector": "Unauthorized device can join network during join window",
                "remediation": "Implement secure commissioning with install codes, limit join window time",
                "references": ["Zigbee Smart Energy Security Whitepaper"]
            })
        
        return vulns
    
    def _check_replay_vulnerability(self, packets: List) -> List[Dict]:
        """Frame counter reuse and replay attack detection"""
        vulns = []
        frame_counters = defaultdict(list)
        replay_candidates = []
        
        for i, pkt in enumerate(packets):
            nwk = self._extract_nwk(pkt)
            if nwk is not None:
                src = getattr(nwk, 'source', None)
                seqnum = getattr(nwk, 'seqnum', None)
                
                if src and seqnum is not None:
                    if seqnum in frame_counters[src]:
                        replay_candidates.append((i, src, seqnum))
                    frame_counters[src].append(seqnum)
        
        for src, counters in frame_counters.items():
            if len(counters) > 1:
                for i in range(len(counters) - 1):
                    if counters[i+1] < counters[i]:
                        replay_candidates.append((i, src, "non-monotonic"))
        
        if replay_candidates:
            vulns.append({
                "id": "ZIGBEE-004",
                "fix_code": '\n// Fix: Enforce Frame Counter Validation\n// Silicon Labs SDK — enable frame counter checking\n\n// In security options:\nsecurityState.bitmask |= EMBER_REQUIRE_ENCRYPTED_KEY_TRANSPORT;\n\n// Reject replayed frames (frame counter must be strictly increasing)\n// This is enabled by default in Zigbee 3.0 compliant stacks\n\n// TI Z-Stack:\n// In nwk_globals.h:\n// #define NWK_MAX_DUPLICATE_REJECTION_ENTRIES 5\n// #define DUPLICATE_REJECTION_EXPIRY_TIME 5000  // 5 seconds\n\n// Verify frame counter in application layer:\nif (incomingFrameCounter <= lastFrameCounter[srcAddr]) {\n    // Reject packet — possible replay attack\n    return EMBER_ERR_FATAL;\n}\nlastFrameCounter[srcAddr] = incomingFrameCounter;\n',
                "severity": "MEDIUM",
                "title": "Replay Attack Vulnerability",
                "description": "Duplicate or non-monotonic frame sequence numbers detected",
                "cve": [],
                "evidence": f"{len(replay_candidates)} suspicious frame sequences",
                "attack_vector": "Attacker can replay captured packets to inject commands",
                "remediation": "Implement strict frame counter validation and freshness checks",
                "references": ["IEEE 802.15.4 Security"],
                "technical_details": replay_candidates[:5]
            })
        
        return vulns
    
    def _check_key_transport_security(self, packets: List) -> List[Dict]:
        """Insecure key transport"""
        vulns = []
        key_transport_pkts = []
        unencrypted_key_transport = []
        
        for i, pkt in enumerate(packets):
            if ZigbeeAppDataPayload in pkt:
                payload = pkt[ZigbeeAppDataPayload]
                if hasattr(payload, 'cluster') and payload.cluster == 0x0000:
                    is_transport_key = False
                    if hasattr(payload, 'data'):
                        try:
                            data = bytes(payload.data) if hasattr(payload.data, '__iter__') else b''
                            if len(data) > 0 and data[0] == 0x05:
                                is_transport_key = True
                        except (TypeError, ValueError):
                            pass
                    if is_transport_key:
                        key_transport_pkts.append(i)
                        if ZigbeeSecurityHeader not in pkt:
                            unencrypted_key_transport.append(i)
        
        if key_transport_pkts:
            if unencrypted_key_transport:
                severity = "CRITICAL"
                evidence = f"{len(key_transport_pkts)} key transport operations, {len(unencrypted_key_transport)} unencrypted"
            else:
                severity = "MEDIUM"
                evidence = f"{len(key_transport_pkts)} key transport operations (encrypted but in-band)"
            
            vulns.append({
                "id": "ZIGBEE-005",
                "fix_code": '\n// Fix: Secure Key Transport using Install Codes\n// Never transport network key in plaintext\n\n// Silicon Labs: Always use encrypted key transport\nsecurityState.bitmask |= EMBER_HAVE_PRECONFIGURED_KEY\n                       | EMBER_REQUIRE_ENCRYPTED_KEY_TRANSPORT;\n\n// Verify key transport is encrypted before joining:\nvoid emberZigbeeKeyEstablishmentHandler(EmberEUI64 partner,\n                                        EmberKeyStatus status) {\n    if (status != EMBER_KEY_ESTABLISHMENT_SUCCESS) {\n        // Reject device — key negotiation failed securely\n        emberLeaveRequest(partner, false);\n    }\n}\n',
                "severity": severity,
                "title": "Insecure Key Transport Mechanism",
                "description": "Network keys transported in-band without proper protection",
                "cve": ["CVE-2019-15911"],
                "evidence": evidence,
                "unencrypted_count": len(unencrypted_key_transport),
                "attack_vector": "Attacker can intercept network key during device commissioning" if unencrypted_key_transport else "In-band key transport vulnerable to man-in-the-middle",
                "remediation": "Use out-of-band commissioning or install codes for key derivation",
                "references": ["Zigbee Alliance JC-001-001 Install Code Memo"]
            })
        
        return vulns
    
    def _check_wormhole_attack(self, packets: List) -> List[Dict]:
        """Wormhole attack pattern detection"""
        vulns = []
        route_records = defaultdict(list)
        suspicious_routes = []
        
        for pkt in packets:
            nwk = self._extract_nwk(pkt)
            if nwk is not None:
                src = getattr(nwk, 'source', None)
                dst = getattr(nwk, 'destination', None)
                radius = getattr(nwk, 'radius', None)
                
                if src and dst and radius:
                    route_key = (src, dst)
                    route_records[route_key].append(radius)
                    if radius < 2 and len(route_records[route_key]) > 5:
                        suspicious_routes.append(route_key)
        
        if suspicious_routes:
            vulns.append({
                "id": "ZIGBEE-006",
                "fix_code": '\n// Fix: Implement Packet Leashes to Prevent Wormhole Attacks\n// Use timestamp + location verification\n\n// 1. Add temporal leash — timestamp in each packet\ntypedef struct {\n    uint32_t timestamp;\n    uint16_t srcAddr;\n    uint8_t  data[MAX_PAYLOAD];\n} SecurePacket;\n\n// 2. Reject packets older than threshold\n#define MAX_PACKET_AGE_MS 1000  // 1 second\nuint32_t now = halCommonGetInt32uMillisecondTick();\nif ((now - packet.timestamp) > MAX_PACKET_AGE_MS) {\n    return; // Drop stale packet\n}\n\n// 3. Enable geographic routing restrictions in coordinator\n// zigbeeGateway.setMaxHopCount(10);\n',
                "severity": "HIGH",
                "title": "Potential Wormhole Attack Pattern",
                "description": "Abnormal routing patterns suggesting tunneled connections",
                "evidence": f"{len(suspicious_routes)} suspicious route patterns detected",
                "attack_vector": "Two colluding nodes create tunnel to disrupt routing",
                "remediation": "Implement geographic packet leashes and temporal packet leashes",
                "technical_details": list(suspicious_routes)[:5]
            })
        
        return vulns
    
    def _check_dos_patterns(self, packets: List) -> List[Dict]:
        """DoS attack pattern detection"""
        vulns = []
        src_packet_count = Counter()
        beacon_flood = 0
        
        for pkt in packets:
            # Read source from ZigbeeNWK layer
            nwk = self._extract_nwk(pkt)
            if nwk is not None:
                src = getattr(nwk, 'source', None)
                if src:
                    src_packet_count[src] += 1
            
            # Beacon detection
            if Dot15d4Beacon in pkt:
                beacon_flood += 1
            elif Dot15d4 in pkt and ZigbeeNWK not in pkt:
                # fcf_frametype=0 على packet بدون ZigbeeNWK = beacon حقيقي
                try:
                    if getattr(pkt[Dot15d4], 'fcf_frametype', -1) == 0:
                        beacon_flood += 1
                except Exception:
                    pass
        
        max_src = src_packet_count.most_common(1)
        if max_src and max_src[0][1] > len(packets) * 0.7:
            vulns.append({
                "id": "ZIGBEE-007",
                "fix_code": '\n// Fix: Implement Rate Limiting per Source Node\n// Silicon Labs SDK — add packet rate limiter\n\n#define MAX_PACKETS_PER_SECOND 20\n#define RATE_WINDOW_MS 1000\n\nstatic uint32_t packetCount[MAX_NODES] = {0};\nstatic uint32_t windowStart[MAX_NODES] = {0};\n\nbool isRateLimited(uint16_t srcAddr) {\n    uint32_t now = halCommonGetInt32uMillisecondTick();\n    uint8_t idx  = srcAddr % MAX_NODES;\n\n    if ((now - windowStart[idx]) > RATE_WINDOW_MS) {\n        windowStart[idx] = now;\n        packetCount[idx] = 0;\n    }\n    packetCount[idx]++;\n    return packetCount[idx] > MAX_PACKETS_PER_SECOND;\n}\n\n// In message handler:\nif (isRateLimited(senderAddr)) {\n    emberSendRemoveDevice(coordinatorEUI64, senderEUI64);\n    return;\n}\n',
                "severity": "MEDIUM",
                "title": "Potential DoS Attack - Packet Flooding",
                "description": "Single source generating excessive traffic",
                "evidence": f"Source {max_src[0][0]:04x} sent {max_src[0][1]} packets ({(max_src[0][1]/len(packets)*100):.1f}%)",
                "attack_vector": "Resource exhaustion attack on coordinator or routers",
                "remediation": "Implement rate limiting and packet filtering"
            })
        
        if beacon_flood > len(packets) * 0.2:
            vulns.append({
                "id": "ZIGBEE-008",
                "fix_code": '\n// Fix: Configure Beacon Filtering on Routers\n// Silicon Labs SDK\n\n// 1. Enable beacon filtering\nemberSetBeaconClassificationParams(\n    EMBER_BEACON_CLASSIFICATION_LONG_UPTIME |\n    EMBER_BEACON_CLASSIFICATION_BAD_PARENT_CONNECTIVITY\n);\n\n// 2. Limit beacon requests\n// In zigbee_app_framework_common.c:\n#define BEACON_REQUEST_RATE_LIMIT 5  // max 5 per second\n\n// 3. TI Z-Stack — disable beacon mode for non-coordinators:\n// In ZDApp.c: if device is router, reject beacon scan requests\n// zgDeviceLogicalType = ZG_DEVICETYPE_ROUTER;\n// devState = DEV_ROUTER;\n',
                "severity": "MEDIUM",
                "title": "Potential DoS Attack - Beacon Flooding",
                "description": "Excessive beacon frames detected",
                "evidence": f"{beacon_flood} beacon frames ({(beacon_flood/len(packets)*100):.1f}% of traffic)",
                "attack_vector": "Beacon spam to cause network instability",
                "remediation": "Configure beacon filtering on routers"
            })
        
        return vulns
    
    def _check_trust_center_issues(self, packets: List) -> List[Dict]:
        """Trust Center security misconfigurations"""
        vulns = []
        tc_activity = {"device_announce": 0, "leave_requests": 0, "key_updates": 0}
        
        for pkt in packets:
            if ZigbeeAppDataPayload in pkt:
                payload = pkt[ZigbeeAppDataPayload]
                cluster = getattr(payload, 'cluster', None)
                if cluster == 0x0013:
                    tc_activity["device_announce"] += 1
                elif cluster == 0x0034:
                    tc_activity["leave_requests"] += 1
        
        if tc_activity["device_announce"] > 50:
            vulns.append({
                "id": "ZIGBEE-009",
                "fix_code": '\n// Fix: Monitor and Rate-Limit Device Announcements\n// Detect abnormal join/leave activity\n\n#define MAX_ANNOUNCES_PER_MINUTE 10\nstatic uint8_t announceCount = 0;\nstatic uint32_t announceWindowStart = 0;\n\nvoid emberNewNodeJoinedHandler(EmberEUI64 newNodeId,\n                                EmberNodeId nodeId) {\n    uint32_t now = halCommonGetInt32uMillisecondTick();\n    if ((now - announceWindowStart) > 60000) {\n        announceWindowStart = now;\n        announceCount = 0;\n    }\n    if (++announceCount > MAX_ANNOUNCES_PER_MINUTE) {\n        // Block further joins temporarily\n        emberPermitJoining(0);\n        // Alert network administrator\n        sendSecurityAlert(EXCESSIVE_JOIN_ACTIVITY);\n    }\n}\n',
                "severity": "MEDIUM",
                "title": "Excessive Trust Center Activity",
                "description": "Unusually high device join/leave activity",
                "evidence": f"{tc_activity['device_announce']} device announcements",
                "attack_vector": "Possible network reconnaissance or join attack",
                "remediation": "Monitor and limit device enrollment rate"
            })
        
        return vulns
    
    def _check_routing_vulnerabilities(self, packets: List) -> List[Dict]:
        """Routing protocol vulnerabilities"""
        vulns = []
        route_requests = []
        route_replies = []
        
        for i, pkt in enumerate(packets):
            nwk = self._extract_nwk(pkt)
            if nwk is not None:
                frame_type = getattr(nwk, 'frametype', None)
                if frame_type == 1:
                    route_requests.append(i)
                elif frame_type == 2:
                    route_replies.append(i)
        
        if len(route_requests) > len(packets) * 0.15:
            vulns.append({
                "id": "ZIGBEE-010",
                "fix_code": '\n// Fix: Secure Routing with Route Authentication\n// Prevent sinkhole and selective forwarding attacks\n\n// 1. Enable route request authentication\nsecurityState.bitmask |= EMBER_NO_FRAME_COUNTER_RESET;\n\n// 2. Validate route replies\nvoid emberIncomingRouteRecordHandler(EmberNodeId source,\n                                     EmberEUI64 sourceEui,\n                                     uint8_t lastHopLqi,\n                                     int8_t lastHopRssi,\n                                     uint8_t relayCount,\n                                     uint8_t *relayList) {\n    // Verify relay count is reasonable\n    if (relayCount > MAX_EXPECTED_HOPS) {\n        // Suspicious routing — possible sinkhole attack\n        emberSetRadioPower(3); // reduce range\n        sendSecurityAlert(SUSPICIOUS_ROUTING);\n    }\n}\n\n// 3. Monitor route request storms\n// If RREQ > threshold per second → possible attack\n',
                "severity": "MEDIUM",
                "title": "Routing Protocol Manipulation",
                "description": "Excessive route discovery packets detected",
                "cve": [],
                "evidence": f"{len(route_requests)} route requests, {len(route_replies)} replies",
                "attack_vector": "Selective forwarding or sinkhole attack",
                "remediation": "Implement secure routing with authentication"
            })
        
        return vulns
    
    def _calculate_risk_score(self, vulns: List[Dict]) -> int:
        """Calculate overall risk score (0-100)"""
        if not vulns:
            return 0
        severity_scores = {"CRITICAL": 35, "HIGH": 15, "MEDIUM": 10, "LOW": 5}
        total = sum(severity_scores.get(v["severity"], 0) for v in vulns)
        return min(total, 100)
