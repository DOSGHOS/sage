#!/usr/bin/env python3
import os, hashlib
from typing import Dict, Any, List, Tuple, Set
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, Packet
    from scapy.layers.bluetooth import *
    from scapy.layers.bluetooth4LE import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class BLEPlugin:
    name = "BLE"
    
    # BLE Security Levels
    SEC_LEVEL_NO_SECURITY = 0
    SEC_LEVEL_UNAUTHENTICATED = 1
    SEC_LEVEL_AUTHENTICATED = 2
    SEC_LEVEL_SECURE_CONNECTIONS = 3
    
    def supports(self, pcap_path: str) -> bool:
        return os.path.exists(pcap_path) and pcap_path.lower().endswith(('.pcap', '.pcapng'))
    
    def scan(self, pcap_path: str) -> Dict[str, Any]:
        if not SCAPY_AVAILABLE:
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "error": "Scapy with BLE support required",
                "vulns": []
            }
        
        vulns = []
        stats = {
            "total": 0, "ble": 0, "encrypted": 0, "unencrypted": 0,
            "advertisements": 0, "data_packets": 0, "control_packets": 0
        }
        
        try:
            packets = rdpcap(pcap_path)

            from scapy.all import Raw
            packets = [p.__class__(bytes(p)) if not BTLE_DATA in p and Raw in p else p for p in packets]
            stats["total"] = 0  # will be set after filtering
            
            # Filter BLE packets
            ble_packets = self._filter_ble_packets(packets, stats)
            stats["ble"] = len(ble_packets)
            stats["total"] = len(ble_packets)
            
            if not ble_packets:
                return {
                    "protocol": self.name,
                    "pcap": pcap_path,
                    "statistics": stats,
                    "vulns": []
                }
            
            # Comprehensive security analysis
            vulns.extend(self._check_bluffs_vulnerability(ble_packets))
            vulns.extend(self._check_knob_attack(ble_packets))
            vulns.extend(self._check_pairing_security(ble_packets))
            vulns.extend(self._check_privacy_issues(ble_packets))
            vulns.extend(self._check_gatt_security(ble_packets, stats))
            vulns.extend(self._check_mitm_vulnerability(ble_packets))
            vulns.extend(self._check_relay_attack(ble_packets))
            vulns.extend(self._check_sweyntooth(ble_packets))
            vulns.extend(self._check_information_leakage(ble_packets))
            vulns.extend(self._check_dos_patterns(ble_packets))
            
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "statistics": stats,
                "vulns": vulns,
                "risk_score": self._calculate_risk_score(vulns),
                "devices_detected": self._count_unique_devices(ble_packets),
                "topology":   self._build_topology(ble_packets),
            }
            
        except Exception as e:
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "error": f"Scan error: {str(e)}",
                "vulns": []
            }
    

    def _build_topology(self, packets: list) -> dict:
        """
        يبني topology من BLE packets.
        يستخرج الـ MAC addresses الحقيقية من الـ advertisements والـ connections.
        """
        from collections import defaultdict
        try:
            from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV_IND, BTLE_CONNECT_REQ
        except ImportError:
            return {"nodes": [], "edges": []}

        node_info = {}
        edge_info = defaultdict(lambda: {"count":0,"encrypted":0,"unencrypted":0})

        for pkt in packets:
            # Advertiser devices — from ADV_IND or any BTLE_ADV
            for adv_cls in [BTLE_ADV_IND]:
                if adv_cls in pkt:
                    adv = pkt[adv_cls]
                    addr = getattr(adv, 'AdvA', None)
                    if addr is not None:
                        if isinstance(addr, str) and ":" in addr:
                            addr_str = addr.upper()
                        elif isinstance(addr, int):
                            addr_str = ":".join(f"{(addr>>(j*8))&0xFF:02X}" for j in range(5,-1,-1))
                        else:
                            addr_str = str(addr)
                        if addr_str in ("00:00:00:00:00:00","FF:FF:FF:FF:FF:FF"): continue
                        if addr_str not in node_info:
                            node_info[addr_str] = {
                                "count":0,"encrypted":0,"unencrypted":0,
                                "role":"advertiser"
                            }
                        node_info[addr_str]["count"] += 1

            # Fallback: any BTLE_ADV with AdvA field — skip, causes noise
            if False and BTLE_ADV_IND not in pkt and BTLE_ADV in pkt:
                adv = pkt[BTLE_ADV]
                addr = getattr(adv, 'AdvA', None)
                if addr is not None:
                    if isinstance(addr, str) and ":" in addr:
                        addr_str = addr.upper()
                    elif isinstance(addr, int):
                        addr_str = ":".join(f"{(addr>>(j*8))&0xFF:02X}" for j in range(5,-1,-1))
                    else:
                        addr_str = str(addr)
                    if addr_str in ("00:00:00:00:00:00","FF:FF:FF:FF:FF:FF"): continue
                    if addr_str not in node_info:
                        node_info[addr_str] = {
                            "count":0,"encrypted":0,"unencrypted":0,
                            "role":"advertiser"
                        }
                    node_info[addr_str]["count"] += 1

            # Connection requests — initiator + advertiser
            if BTLE_CONNECT_REQ in pkt:
                conn = pkt[BTLE_CONNECT_REQ]
                init_a = getattr(conn, 'InitA', None)
                adv_a  = getattr(conn, 'AdvA',  None)

                if init_a is not None:
                    s = str(init_a).upper()
                    if s not in node_info:
                        node_info[s] = {"count":0,"encrypted":0,"unencrypted":0,"role":"central"}
                    node_info[s]["role"]  = "central"
                    node_info[s]["count"] += 1

                if adv_a is not None:
                    s = str(adv_a).upper()
                    if s not in node_info:
                        node_info[s] = {"count":0,"encrypted":0,"unencrypted":0,"role":"peripheral"}
                    node_info[s]["role"]  = "peripheral"
                    node_info[s]["count"] += 1

                if init_a and adv_a:
                    key = (str(init_a).upper(), str(adv_a).upper())
                    edge_info[key]["count"] += 1

        BLE_TYPES = {
            "central":    "Phone / Central",
            "peripheral": "Peripheral Device",
            "advertiser": "BLE Advertiser",
        }
        nodes = [
            {
                "id":          addr,
                "label":       addr,
                "device_type": BLE_TYPES.get(info["role"], "BLE Device"),
                "role":        info["role"],
                "packet_count":info["count"],
                "encrypted":   info["encrypted"],
                "unencrypted": info["unencrypted"],
                "secure":      info["unencrypted"] == 0,
                "protocol":    "BLE",
            }
            for addr, info in node_info.items()
        ]

        edges = [
            {
                "from":      src,
                "to":        dst,
                "count":     info["count"],
                "encrypted": info["encrypted"],
                "unencrypted":info["unencrypted"],
                "secure":    True,  # connection requests are always first step
            }
            for (src, dst), info in edge_info.items()
        ]

        return {"nodes": nodes, "edges": edges}

    def _filter_ble_packets(self, packets: List, stats: Dict) -> List:
        """Extract and classify BLE packets"""
        ble_packets = []
        encrypted_conns = set()
        
        # أول مرحلة: اكتشف الـ connections المشفرة
        for pkt in packets:
            if BTLE in pkt:
                raw = bytes(pkt)
                if len(raw) > 6:
                    # LL_START_ENC_RSP = opcode 0x06 مع LLID=3
                    if raw[4] & 0x03 == 3 and len(raw) > 5 and raw[5] == 0x06:
                        access_addr = raw[:4]
                        encrypted_conns.add(bytes(access_addr))

        for pkt in packets:
            is_ble = False
            if BTLE in pkt or BTLE_ADV in pkt or BTLE_DATA in pkt:
                is_ble = True
            elif hasattr(pkt, 'haslayer'):
                if pkt.haslayer('BTLE') or pkt.haslayer('ATT_Hdr'):
                    is_ble = True
            
            if is_ble:
                ble_packets.append(pkt)
                if BTLE_ADV in pkt:
                    stats["advertisements"] += 1
                elif BTLE_DATA in pkt:
                    stats["data_packets"] += 1
                    # عدّ الـ encrypted/unencrypted بناءً على الـ connection
                    if BTLE in pkt:
                        raw = bytes(pkt)
                        addr = bytes(raw[:4]) if len(raw)>=4 else b''
                        if addr in encrypted_conns:
                            stats["encrypted"] += 1
                        else:
                            stats["unencrypted"] += 1
                elif BTLE_CTRL in pkt:
                    stats["control_packets"] += 1
        
        return ble_packets
    
    def _check_bluffs_vulnerability(self, packets: List) -> List[Dict]:
        """CVE-2023-24023: BLUFFS Attack - Session key derivation weakness"""
        vulns = []
        
        pairing_sessions = []
        weak_key_derivation = []
        
        for i, pkt in enumerate(packets):
            # Check for LL_ENC_REQ/RSP — try both BTLE_CTRL layer and raw bytes
            found_enc = False
            if BTLE_CTRL in pkt:
                ctrl = pkt[BTLE_CTRL]
                if hasattr(ctrl, 'opcode') and ctrl.opcode in [0x03, 0x05]:
                    found_enc = True
                    if hasattr(ctrl, 'rand') or hasattr(ctrl, 'skd'):
                        weak_key_derivation.append(i)
            # Fallback: check raw bytes directly
            if not found_enc:
                try:
                    raw = bytes(pkt)
                    # ابحث عن opcode 0x03 أو 0x05 في الـ raw bytes
                    for offset in range(len(raw)-1):
                        if raw[offset] in [0x03, 0x05]:
                            # تحقق إن قبله LLID=3 (control PDU)
                            # BTLE header: access_addr(4) + header(2) + payload
                            # header byte 0 bits[1:0] = LLID
                            if offset >= 6:
                                llid = raw[4] & 0x03
                                if llid == 3:
                                    found_enc = True
                                    break
                except Exception:
                    pass
            if found_enc:
                pairing_sessions.append(i)
        
        if pairing_sessions:
            vulns.append({
                "id": "BLE-001",
                "fix_code": '\n// Fix: Patch BLUFFS Attack (CVE-2023-24023)\n// Nordic nRF5 SDK — enforce minimum session key entropy\n\n// 1. Update to patched SoftDevice (S132/S140 v7.3.0+)\n// Download: https://www.nordicsemi.com/Software-and-tools/Software/nRF5-SDK\n\n// 2. Enforce minimum key length in pairing parameters\nble_gap_sec_params_t sec_params = {\n    .bond         = 1,\n    .mitm         = 1,\n    .lesc         = 1,  // LE Secure Connections (CRITICAL)\n    .keypress     = 0,\n    .io_caps      = BLE_GAP_IO_CAPS_DISPLAY_YESNO,\n    .min_key_size = 16, // Force maximum key size\n    .max_key_size = 16,\n};\n\n// 3. Reject legacy SMP pairing\nif (!peer_supports_lesc) {\n    sd_ble_gap_disconnect(conn_handle,\n        BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);\n}\n',
                "severity": "CRITICAL",
                "title": "BLUFFS Attack Vulnerability (CVE-2023-24023)",
                "description": "BLE session key derivation susceptible to forward/future secrecy attacks",
                "cve": ["CVE-2023-24023"],
                "evidence": f"{len(pairing_sessions)} encryption sessions detected",
                "attack_vector": "MITM can force weak session keys, decrypt past and future sessions",
                "affected_ble_versions": "Bluetooth 4.0 through 5.4",
                "remediation": "Upgrade to BLE stack with CVE-2023-24023 patch, enforce minimum 7-byte keys",
                "references": ["BLUFFS: Bluetooth Forward and Future Secrecy Attacks (IEEE S&P 2024)"],
                "technical_details": {
                    "sessions_analyzed": len(pairing_sessions),
                    "weak_derivation_patterns": len(weak_key_derivation)
                }
            })
        
        return vulns
    
    def _check_knob_attack(self, packets: List) -> List[Dict]:
        """CVE-2019-9506: KNOB Attack - Key negotiation vulnerability"""
        vulns = []
        
        key_negotiations = []
        short_keys_detected = []
        
        for i, pkt in enumerate(packets):
            if BTLE_CTRL in pkt:
                ctrl = pkt[BTLE_CTRL]
                
                # Check for encryption key length negotiation
                if hasattr(ctrl, 'opcode') and ctrl.opcode == 0x03:  # LL_ENC_REQ
                    key_negotiations.append(i)
                    
                    # KNOB: Check if key length < 7 bytes (weak)
                    if hasattr(ctrl, 'key_length'):
                        if ctrl.key_length < 7:
                            short_keys_detected.append((i, ctrl.key_length))
        
        if short_keys_detected:
            vulns.append({
                "id": "BLE-002",
                "fix_code": '\n// Fix: Prevent KNOB Attack (CVE-2019-9506)\n// Enforce minimum encryption key length = 16 bytes\n\n// Nordic nRF5 SDK\nble_opt_t opt;\nopt.gap_opt.preferred_phys.tx_phys = BLE_GAP_PHY_2MBPS;\n\n// Set minimum key size to 16 (128-bit)\nble_gap_sec_params_t sec_params = {\n    .min_key_size = 16,  // CRITICAL: never set below 7\n    .max_key_size = 16,\n    .lesc         = 1,   // Require LE Secure Connections\n};\n\n// Reject connections requesting shorter keys:\nvoid on_ble_evt(ble_evt_t const *p_ble_evt) {\n    if (p_ble_evt->evt.gap_evt.params.sec_params_request\n            .peer_params.max_key_size < 16) {\n        sd_ble_gap_sec_params_reply(conn_handle,\n            BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL);\n    }\n}\n',
                "severity": "CRITICAL",
                "title": "KNOB Attack - Weak Encryption Key Negotiation",
                "description": "BLE connection uses negotiated keys shorter than 7 bytes",
                "cve": ["CVE-2019-9506"],
                "evidence": f"{len(short_keys_detected)} weak key negotiations detected",
                "attack_vector": "MITM forces 1-byte encryption key, enabling real-time decryption",
                "remediation": "Enforce minimum key length of 7 bytes (56 bits) in BR/EDR connections",
                "references": ["KNOB: The Key Negotiation of Bluetooth Attack (USENIX Security 2019)"],
                "weak_keys": [{"packet": k[0], "key_length_bytes": k[1]} for k in short_keys_detected[:5]]
            })
        
        return vulns
    
    def _check_pairing_security(self, packets: List) -> List[Dict]:
        """CVE-2020-15802: Pairing method vulnerabilities"""
        vulns = []
        
        pairing_requests = []
        just_works_pairing = []
        no_mitm_protection = []
        legacy_pairing = []
        
        for i, pkt in enumerate(packets):
            if SM_Pairing_Request in pkt or SM_Pairing_Response in pkt:
                pairing_requests.append(i)
                
                sm = pkt[SM_Pairing_Request] if SM_Pairing_Request in pkt else pkt[SM_Pairing_Response]
                
                if hasattr(sm, 'authentication'):
                    auth = sm.authentication
                    
                    # Check MITM protection bit (0x04)
                    if not (auth & 0x04):
                        no_mitm_protection.append(i)
                        just_works_pairing.append(i)
                    
                    # Check for Secure Connections (0x08)
                    if not (auth & 0x08):
                        legacy_pairing.append(i)
                    
                    # Check bonding (0x01)
                    if not (auth & 0x01):
                        pass  # No bonding
        
        if just_works_pairing:
            vulns.append({
                "id": "BLE-003",
                "fix_code": '\n// Fix: Disable Just Works Pairing — Require MITM Protection\n// Nordic nRF5 SDK\n\nble_gap_sec_params_t sec_params = {\n    .bond    = 1,\n    .mitm    = 1,  // CRITICAL: require MITM protection\n    .lesc    = 1,  // Use LE Secure Connections\n    .io_caps = BLE_GAP_IO_CAPS_DISPLAY_YESNO,\n             // Use Numeric Comparison or Passkey Entry\n             // NOT BLE_GAP_IO_CAPS_NONE (Just Works)\n};\n\n// ESP32 (Arduino):\n// BLEDevice::setSecurityAuth(true, true, true); // bonding, MITM, SC\n// BLEDevice::setSecurityIOCap(ESP_IO_CAP_OUT); // display passkey\n\n// Zephyr RTOS:\n// CONFIG_BT_SMP_SC_ONLY=y\n// CONFIG_BT_SMP_SC_PAIR_ONLY=y\n',
                "severity": "CRITICAL",
                "title": "'Just Works' Pairing Method Detected",
                "description": "BLE pairing without MITM protection (Just Works method)",
                "cve": ["CVE-2020-15802", "CVE-2020-26558"],
                "evidence": f"{len(just_works_pairing)} Just Works pairing attempts",
                "attack_vector": "Passive eavesdropper can decrypt all pairing traffic",
                "remediation": "Use Passkey Entry or Numeric Comparison pairing methods",
                "affected_packets": just_works_pairing[:10]
            })
        
        if legacy_pairing:
            vulns.append({
                "id": "BLE-004",
                "fix_code": "\n// Fix: Enforce LE Secure Connections (BLE 4.2+)\n// Disable Legacy Pairing completely\n\n// Nordic nRF5 SDK\nble_gap_sec_params_t sec_params = {\n    .lesc = 1,  // Require LE Secure Connections (ECDH-based)\n    .mitm = 1,\n    .bond = 1,\n};\n\n// Reject legacy pairing requests:\nvoid on_sec_params_request(ble_gap_evt_sec_params_request_t *req) {\n    if (req->peer_params.lesc == 0) {\n        // Peer doesn't support LESC — disconnect\n        sd_ble_gap_disconnect(conn_handle,\n            BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);\n        return;\n    }\n}\n\n// Zephyr: CONFIG_BT_SMP_SC_ONLY=y\n// ESP-IDF: esp_ble_gap_set_security_param(\n//              ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH,\n//              &auth_option, sizeof(uint8_t));\n",
                "severity": "HIGH",
                "title": "Legacy Pairing Method (Pre-BLE 4.2)",
                "description": "Device using Legacy Pairing instead of Secure Connections",
                "cve": ["CVE-2018-5383"],
                "evidence": f"{len(legacy_pairing)} legacy pairing sessions",
                "attack_vector": "Susceptible to Invalid Curve Attack and passive eavesdropping",
                "remediation": "Enable LE Secure Connections (BLE 4.2+) with ECDH key exchange",
                "references": ["CVE-2018-5383: Invalid Curve Attack"]
            })
        
        return vulns
    
    def _check_privacy_issues(self, packets: List) -> List[Dict]:
        """Address randomization and privacy vulnerabilities"""
        vulns = []
        
        device_addresses = defaultdict(int)
        static_addresses = set()
        irk_resolution_failures = []
        
        for i, pkt in enumerate(packets):
            if BTLE in pkt:
                ble = pkt[BTLE]
                
                # Extract advertiser address
                if hasattr(ble, 'AdvA'):
                    addr = ble.AdvA
                    device_addresses[addr] += 1
                    
                    # Check if address is static (should be changing)
                    if device_addresses[addr] > 100:
                        static_addresses.add(addr)
        
        if static_addresses:
            vulns.append({
                "id": "BLE-005",
                "fix_code": '\n// Fix: Enable BLE Privacy — Resolvable Private Addresses (RPA)\n// Rotate MAC address every 15 minutes\n\n// Nordic nRF5 SDK\nble_gap_privacy_params_t privacy_params = {\n    .privacy_mode         = BLE_GAP_PRIVACY_MODE_DEVICE_PRIVACY,\n    .private_addr_type    = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_RESOLVABLE,\n    .private_addr_cycle_s = 900,  // Rotate every 15 minutes\n    .p_device_irk         = &irk, // Identity Resolving Key\n};\nsd_ble_gap_privacy_set(&privacy_params);\n\n// ESP32 (Arduino):\n// BLEDevice::setOwnAddrType(BLE_ADDR_TYPE_RPA_RANDOM);\n\n// Zephyr:\n// CONFIG_BT_PRIVACY=y\n// CONFIG_BT_RPA_TIMEOUT=900\n',
                "severity": "MEDIUM",
                "title": "Device Tracking via Static Addresses",
                "description": "BLE devices broadcasting static MAC addresses",
                "evidence": f"{len(static_addresses)} devices with static addresses detected",
                "attack_vector": "Device tracking and user profiling through address correlation",
                "remediation": "Enable BLE Privacy feature with address randomization (resolvable private addresses)",
                "tracked_devices": list(static_addresses)[:5],
                "references": ["Bluetooth Core Spec v5.3, Vol 6, Part B, Section 1.3"]
            })
        
        return vulns
    
    def _check_gatt_security(self, packets: List, stats: Dict) -> List[Dict]:
        """GATT service security analysis"""
        vulns = []
        
        gatt_operations = {
            "reads": [], "writes": [], "unencrypted_reads": [],
            "unencrypted_writes": [], "no_auth_writes": []
        }
        
        for i, pkt in enumerate(packets):
            if ATT_Hdr in pkt:
                # Check operation type
                if ATT_Read_Request in pkt or ATT_Read_By_Type_Request in pkt:
                    gatt_operations["reads"].append(i)
                    
                    if not self._is_encrypted_link(pkt):
                        gatt_operations["unencrypted_reads"].append(i)
                        
                elif ATT_Write_Request in pkt or ATT_Write_Command in pkt:
                    gatt_operations["writes"].append(i)
                    
                    if not self._is_encrypted_link(pkt):
                        gatt_operations["unencrypted_writes"].append(i)
        
        if gatt_operations["unencrypted_reads"] or gatt_operations["unencrypted_writes"]:
            severity = "CRITICAL" if gatt_operations["unencrypted_writes"] else "HIGH"
            
            vulns.append({
                "id": "BLE-006",
                "fix_code": '\n// Fix: Require Encryption for GATT Characteristics\n// Nordic nRF5 SDK — set security permissions on attributes\n\n// For sensitive characteristics (health data, control commands):\nble_gatts_attr_md_t attr_md;\nmemset(&attr_md, 0, sizeof(attr_md));\n\n// Require encryption AND authentication\nBLE_GAP_CONN_SEC_MODE_SET_ENC_WITH_MITM(&attr_md.read_perm);\nBLE_GAP_CONN_SEC_MODE_SET_ENC_WITH_MITM(&attr_md.write_perm);\n\n// For less sensitive data — encryption without MITM:\n// BLE_GAP_CONN_SEC_MODE_SET_ENC_NO_MITM(&attr_md.read_perm);\n\n// ESP32 (Arduino):\n// pCharacteristic->setAccessPermissions(\n//     ESP_GATT_PERM_READ_ENC_MITM | ESP_GATT_PERM_WRITE_ENC_MITM);\n\n// Zephyr:\n// BT_GATT_CHARACTERISTIC(&uuid, BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,\n//     BT_GATT_PERM_READ_ENCRYPT | BT_GATT_PERM_WRITE_ENCRYPT,\n//     read_cb, write_cb, NULL)\n',
                "severity": severity,
                "title": "Unencrypted GATT Operations",
                "description": "Sensitive GATT characteristics accessed without encryption",
                "evidence": f"{len(gatt_operations['unencrypted_reads'])} unencrypted reads, "
                           f"{len(gatt_operations['unencrypted_writes'])} unencrypted writes",
                "attack_vector": "Eavesdropper can intercept sensitive health, location, or control data",
                "remediation": "Require 'Encryption' and 'Authentication' permissions for sensitive characteristics",
                "gatt_security_levels": {
                    "reads_total": len(gatt_operations["reads"]),
                    "writes_total": len(gatt_operations["writes"]),
                    "insecure_operations": len(gatt_operations["unencrypted_reads"]) + 
                                          len(gatt_operations["unencrypted_writes"])
                }
            })
        
        return vulns
    
    def _check_mitm_vulnerability(self, packets: List) -> List[Dict]:
        """CVE-2023-45866: MITM attack patterns"""
        vulns = []
        
        connection_events = []
        suspicious_patterns = []
        
        for i, pkt in enumerate(packets):
            # Check for connection establishment
            if BTLE_CTRL in pkt:
                if hasattr(pkt[BTLE_CTRL], 'opcode'):
                    if pkt[BTLE_CTRL].opcode == 0x00:  # LL_CONNECTION_UPDATE_IND
                        connection_events.append(i)
                        
            # Look for suspicious re-pairing attempts
            if SM_Pairing_Request in pkt:
                # Multiple pairing requests in short time = suspicious
                if len([e for e in connection_events if abs(e - i) < 10]) > 1:
                    suspicious_patterns.append(i)
        
        if suspicious_patterns:
            vulns.append({
                "id": "BLE-007",
                "fix_code": '\n// Fix: Implement Connection Validation to Prevent MITM\n// Verify peer identity before accepting connection\n\n// Nordic nRF5 SDK — use Out-of-Band (OOB) verification\nble_gap_sec_params_t sec_params = {\n    .oob  = 1,   // Use OOB data (QR code, NFC, etc.)\n    .mitm = 1,\n    .lesc = 1,\n};\n\n// Alternatively, use Numeric Comparison:\nsec_params.io_caps = BLE_GAP_IO_CAPS_DISPLAY_YESNO;\n\n// On pairing confirmation, verify the 6-digit code matches:\nvoid on_passkey_display(uint32_t passkey) {\n    // Show passkey on device display\n    // User must confirm same number appears on both devices\n    display_show_passkey(passkey);\n}\n\n// Reject re-pairing attempts without user confirmation:\nstatic uint8_t pairing_attempts = 0;\nif (++pairing_attempts > 3) {\n    // Lock pairing for 30 minutes after 3 failed attempts\n    pairing_locked_until = now + (30 * 60 * 1000);\n}\n',
                "severity": "HIGH",
                "title": "MITM Attack Pattern Detected",
                "description": "Suspicious pairing/connection patterns indicating possible MITM",
                "cve": ["CVE-2023-45866"],
                "evidence": f"{len(suspicious_patterns)} suspicious pairing sequences",
                "attack_vector": "Attacker intercepts connection and impersonates legitimate device",
                "remediation": "Implement mutual authentication and out-of-band verification",
                "suspicious_packets": suspicious_patterns[:10]
            })
        
        return vulns
    
    def _check_relay_attack(self, packets: List) -> List[Dict]:
        """Link layer relay attack (NCC Group research 2022)"""
        vulns = []
        
        # Check for proximity authentication patterns
        proximity_auth = []
        rapid_connections = []
        
        connection_times = []
        
        for i, pkt in enumerate(packets):
            if BTLE_CTRL in pkt:
                if hasattr(pkt[BTLE_CTRL], 'opcode'):
                    if pkt[BTLE_CTRL].opcode in [0x00, 0x01]:  # Connection events
                        connection_times.append(i)
        
        # Check for rapid connection/disconnection (relay attack indicator)
        for i in range(len(connection_times) - 1):
            if connection_times[i+1] - connection_times[i] < 20:
                rapid_connections.append(connection_times[i])
        
        if rapid_connections:
            vulns.append({
                "id": "BLE-008",
                "fix_code": '\n// Fix: Prevent Relay Attacks with Cryptographic Distance Bounding\n// Measure round-trip time to verify physical proximity\n\n// Method 1: BLE Ranging using Hadamard sequences (BLE 5.1+)\n// Enable Direction Finding / Ranging\nble_gap_conn_params_t conn_params = {\n    .conn_sup_timeout = 400,  // 4 seconds max\n};\n\n// Method 2: Implement RTT challenge-response\n// If RTT > threshold, device is being relayed\n#define MAX_RTT_MS 10  // 10ms = ~3km max distance\n\nuint32_t challenge_sent_time = get_timestamp_ms();\nsend_challenge_to_device(random_nonce);\n\n// In response handler:\nuint32_t rtt = get_timestamp_ms() - challenge_sent_time;\nif (rtt > MAX_RTT_MS) {\n    // Possible relay attack — reject authentication\n    reject_authentication();\n}\n\n// Method 3: Use UWB (Ultra-Wideband) for precise ranging\n// Apple U1, NXP SR040 chips provide cm-level accuracy\n',
                "severity": "CRITICAL",
                "title": "BLE Link Layer Relay Attack Vulnerability",
                "description": "Rapid connection patterns suggesting relay attack on proximity authentication",
                "evidence": f"{len(rapid_connections)} suspicious rapid reconnection events",
                "attack_vector": "Attacker relays BLE link layer to bypass proximity checks (unlock cars/doors remotely)",
                "real_world_impact": "Tesla Model 3/Y, Kwikset smart locks vulnerable",
                "remediation": "Implement cryptographic distance bounding or UWB-based ranging",
                "references": ["NCC Group: BLE Proximity Authentication Relay Attacks (2022)"]
            })
        
        return vulns
    
    def _check_sweyntooth(self, packets: List) -> List[Dict]:
        """SweynTooth vulnerabilities (CVE-2019-16336 family)"""
        vulns = []
        
        malformed_packets = []
        crash_triggers = []
        
        for i, pkt in enumerate(packets):
            # Check for malformed L2CAP packets
            if L2CAP_Hdr in pkt:
                l2cap = pkt[L2CAP_Hdr]
                
                # Invalid length field
                if hasattr(l2cap, 'len'):
                    if l2cap.len == 0 or l2cap.len > 0xFFFF:
                        malformed_packets.append(i)
                        
            # Check for invalid ATT operations
            if ATT_Hdr in pkt:
                att = pkt[ATT_Hdr]
                
                # Invalid opcode
                if hasattr(att, 'opcode'):
                    if att.opcode > 0x1E:  # Invalid ATT opcode
                        crash_triggers.append(i)
        
        if malformed_packets or crash_triggers:
            vulns.append({
                "id": "BLE-009",
                "fix_code": '\n// Fix: Update BLE Stack Firmware (SweynTooth Patches)\n// Check and update to patched firmware versions\n\n// Texas Instruments CC2640R2:\n// Minimum safe version: BLE5-Stack 2.02.04\n// Download: https://www.ti.com/tool/SIMPLELINK-CC13X2-26X2-SDK\n\n// Nordic nRF52:\n// Minimum safe SoftDevice: S132 v7.0.1 / S140 v7.0.1\n// sdk_config.h:\n#define NRF_SDH_BLE_GATT_MAX_MTU_SIZE 247  // Correct MTU handling\n\n// Silabs EFR32:\n// Update to Gecko SDK 3.2.0+\n\n// Add input validation in application layer:\nvoid ble_evt_handler(ble_evt_t const *p_evt) {\n    // Validate L2CAP length\n    if (p_evt->evt.gatts_evt.params.write.len > MAX_WRITE_LEN) {\n        return; // Drop malformed packet\n    }\n    // Validate ATT opcode\n    if (p_evt->header.evt_id > BLE_GATTS_EVT_LAST) {\n        return; // Invalid opcode\n    }\n}\n',
                "severity": "HIGH",
                "title": "SweynTooth-style Malformed Packets",
                "description": "Malformed BLE packets that may trigger crashes or undefined behavior",
                "cve": ["CVE-2019-16336", "CVE-2019-17060", "CVE-2019-17061"],
                "evidence": f"{len(malformed_packets)} malformed packets, {len(crash_triggers)} potential crash triggers",
                "attack_vector": "Send crafted packets to crash BLE stack (DoS)",
                "affected_chips": "Texas Instruments, NXP, Dialog, Telink, Cypress BLE chips",
                "remediation": "Update BLE firmware to patched versions"
            })
        
        return vulns
    
    def _check_information_leakage(self, packets: List) -> List[Dict]:
        """Sensitive information in advertisements"""
        vulns = []
        
        leaked_data = {
            "device_names": set(),
            "manufacturer_data": [],
            "service_uuids": set(),
            "tx_power": []
        }
        
        for pkt in packets:
            if BTLE_ADV in pkt:
                # Extract advertising data
                if hasattr(pkt, 'data'):
                    raw_data = bytes(pkt.data) if hasattr(pkt.data, '__bytes__') else b''
                    
                    # Look for complete local name (0x09) or shortened (0x08)
                    if b'\x09' in raw_data or b'\x08' in raw_data:
                        leaked_data["device_names"].add(str(raw_data))
                    
                    # Manufacturer data (0xFF)
                    if b'\xFF' in raw_data:
                        leaked_data["manufacturer_data"].append(raw_data)
        
        if leaked_data["device_names"] or len(leaked_data["manufacturer_data"]) > 10:
            vulns.append({
                "id": "BLE-010",
                "fix_code": '\n// Fix: Minimize Advertisement Data + Enable Privacy\n\n// Nordic nRF5 SDK — reduce advertisement payload\nble_advdata_t advdata;\nmemset(&advdata, 0, sizeof(advdata));\n\n// Only advertise service UUID — no device name, no manufacturer data\nadvdata.name_type      = BLE_ADVDATA_NO_NAME; // Remove device name\nadvdata.include_appearance = false;            // Remove appearance\n\n// Move sensitive info to Scan Response (only sent on request)\nble_advdata_t scanrsp;\nscanrsp.name_type = BLE_ADVDATA_FULL_NAME;     // Name in scan response only\n\n// Enable privacy (RPA) to prevent tracking:\nble_gap_privacy_params_t privacy = {\n    .privacy_mode         = BLE_GAP_PRIVACY_MODE_DEVICE_PRIVACY,\n    .private_addr_type    = BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_RESOLVABLE,\n    .private_addr_cycle_s = 900,\n};\nsd_ble_gap_privacy_set(&privacy);\n',
                "severity": "MEDIUM",
                "title": "Information Leakage in BLE Advertisements",
                "description": "Device broadcasts identifying information that enables tracking",
                "evidence": f"{len(leaked_data['device_names'])} unique device names, "
                           f"{len(leaked_data['manufacturer_data'])} manufacturer data packets",
                "attack_vector": "Passive tracking of users via BLE advertisements",
                "remediation": "Minimize advertisement data, rotate addresses frequently, use privacy features",
                "leaked_info_types": list(leaked_data.keys())
            })
        
        return vulns
    
    def _check_dos_patterns(self, packets: List) -> List[Dict]:
        """CVE-2024-3077: DoS attack patterns"""
        vulns = []
        
        # Check for connection request flooding
        connection_reqs = []
        scan_reqs = []
        
        for i, pkt in enumerate(packets):
            if BTLE_ADV_IND in pkt or BTLE_ADV_NONCONN_IND in pkt:
                pass
                
            if BTLE_CONNECT_REQ in pkt:
                connection_reqs.append(i)
                
            if BTLE_SCAN_REQ in pkt:
                scan_reqs.append(i)
        
        # Detect flooding
        if len(connection_reqs) > 100:
            vulns.append({
                "id": "BLE-011",
                "fix_code": '\n// Fix: Implement Connection Rate Limiting (CVE-2024-3077)\n// Nordic nRF5 SDK — limit connection requests\n\n#define MAX_CONNECTIONS_PER_MINUTE 10\nstatic uint8_t conn_count = 0;\nstatic uint32_t window_start = 0;\n\n// In BLE_GAP_EVT_CONNECTED handler:\nvoid on_connected(ble_gap_evt_connected_t const *p_evt) {\n    uint32_t now = app_timer_cnt_get();\n    if ((now - window_start) > APP_TIMER_TICKS(60000)) {\n        window_start = now;\n        conn_count = 0;\n    }\n    if (++conn_count > MAX_CONNECTIONS_PER_MINUTE) {\n        // Too many connections — disconnect immediately\n        sd_ble_gap_disconnect(p_evt->conn_handle,\n            BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);\n        // Optionally start whitelist-only mode\n        sd_ble_gap_adv_start(&adv_params_whitelist, APP_BLE_CONN_CFG_TAG);\n        return;\n    }\n}\n',
                "severity": "MEDIUM",
                "title": "BLE Connection Request Flooding",
                "description": "Excessive connection requests detected (potential DoS)",
                "cve": ["CVE-2024-3077"],
                "evidence": f"{len(connection_reqs)} connection requests",
                "attack_vector": "Exhaust device resources through connection flooding",
                "remediation": "Implement connection rate limiting and whitelist filtering"
            })
        
        return vulns
    
    def _is_encrypted_link(self, pkt) -> bool:
        """Check if BLE link is encrypted"""
        # Simplified check - in real implementation, track connection encryption state
        if BTLE in pkt:
            if hasattr(pkt[BTLE], 'access_addr'):
                # Check for LL_START_ENC_RSP or encrypted payload indicators
                if BTLE_CTRL in pkt:
                    if hasattr(pkt[BTLE_CTRL], 'opcode'):
                        if pkt[BTLE_CTRL].opcode == 0x06:  # LL_START_ENC_RSP
                            return True
        return False
    
    def _count_unique_devices(self, packets: List) -> int:
        """Count unique BLE devices in capture"""
        devices = set()
        
        for pkt in packets:
            if BTLE in pkt:
                if hasattr(pkt[BTLE], 'AdvA'):
                    devices.add(pkt[BTLE].AdvA)
        
        return len(devices)
    
    def _calculate_risk_score(self, vulns: List[Dict]) -> int:
        """Calculate overall risk score (0-100)"""
        if not vulns:
            return 0
        
        severity_scores = {"CRITICAL": 35, "HIGH": 15, "MEDIUM": 10, "LOW": 5}
        total = sum(severity_scores.get(v["severity"], 0) for v in vulns)
        return min(total, 100)
