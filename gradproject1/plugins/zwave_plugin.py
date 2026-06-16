#!/usr/bin/env python3
"""
Z-Wave Protocol Vulnerability Scanner Plugin
Based on documented CVEs and peer-reviewed security research:
- CERT VU#142629 (CVE-2020-9057 to CVE-2020-10137)
- VFuzz research (IEEE Access 2022)
- Fouladi & Ghanoun S0 downgrade research
- "Crushing the Wave" (arXiv:2001.08497)
"""
import os
from typing import Dict, Any, List
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, Raw, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Z-Wave frame type constants ───────────────────────────────────────────────
ZWAVE_HOME_ID_LEN   = 4
ZWAVE_MIN_FRAME_LEN = 10

# Command Classes
CMD_CLASS_SECURITY          = 0x98  # S0
CMD_CLASS_SECURITY_2        = 0x9F  # S2
CMD_CLASS_NO_OPERATION      = 0x00
CMD_CLASS_NETWORK_MANAGEMENT= 0x34
CMD_CLASS_INCLUSION         = 0x52
CMD_CLASS_CRC16             = 0x56

# Security Commands
SEC_SCHEME_GET              = 0x04
SEC_SCHEME_REPORT           = 0x05
SEC_NETWORK_KEY_SET         = 0x06
SEC_NETWORK_KEY_VERIFY      = 0x07
SEC_COMMANDS_SUPPORTED_GET  = 0x02
NONCE_GET                   = 0x40
NONCE_REPORT                = 0x80

# S2 Commands
S2_NONCE_GET                = 0x01
S2_NONCE_REPORT             = 0x02
S2_MSG_ENCAPSULATION        = 0x03
KEX_GET                     = 0x04
KEX_REPORT                  = 0x05
KEX_SET                     = 0x06
KEX_FAIL                    = 0x07

# Known weak/default Home IDs used in test environments
KNOWN_TEST_HOME_IDS = {
    bytes([0xDE, 0xAD, 0xBE, 0xEF]),
    bytes([0x00, 0x00, 0x00, 0x00]),
    bytes([0xFF, 0xFF, 0xFF, 0xFF]),
    bytes([0x01, 0x02, 0x03, 0x04]),
}


class ZWavePlugin:
    name = "Z-Wave"

    def supports(self, pcap_path: str) -> bool:
        """Only process pcaps that contain Z-Wave frames (link type 147)."""
        if not os.path.exists(pcap_path):
            return False
        if not pcap_path.lower().endswith(('.pcap', '.pcapng')):
            return False
        # Check pcap link type: 147 (0x93) = USER0 used for Z-Wave
        # If link type is different (e.g. 195=IEEE802.15.4, 251=BT LE),
        # still attempt scan — Z-Wave can be encapsulated in various link types
        try:
            import struct
            with open(pcap_path, "rb") as f:
                header = f.read(24)
            if len(header) < 24:
                return True  # too short to check, try anyway
            magic = struct.unpack("<I", header[:4])[0]
            if magic in (0xa1b2c3d4, 0xd4c3b2a1):
                link_type = struct.unpack("<I", header[20:24])[0]
            elif magic in (0xa1b23c4d, 0x4d3cb2a1):
                link_type = struct.unpack("<I", header[20:24])[0]
            else:
                return True  # unknown format, try anyway

            # Known non-Z-Wave link types — skip to avoid false positives
            NON_ZWAVE_TYPES = {
                195,   # IEEE 802.15.4 (Zigbee)
                251,   # Bluetooth LE
                187,   # Bluetooth
                1,     # Ethernet
                105,   # IEEE 802.11 WiFi
                127,   # IEEE 802.11 Radiotap
            }
            if link_type in NON_ZWAVE_TYPES:
                return False
        except Exception:
            pass
        return True

    def scan(self, pcap_path: str) -> Dict[str, Any]:
        if not SCAPY_AVAILABLE:
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "error": "Scapy required: pip install scapy",
                "vulns": []
            }

        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "error": f"Cannot read pcap: {e}",
                "vulns": []
            }

        # Extract raw Z-Wave frames from packet payloads
        zwave_frames = self._extract_zwave_frames(packets, pcap_path)

        stats = {
            "total_packets": len(zwave_frames),
            "zwave_frames":  len(zwave_frames),
            "s0_frames":     sum(1 for f in zwave_frames if self._is_s0(f)),
            "s2_frames":     sum(1 for f in zwave_frames if self._is_s2(f)),
            "unencrypted":   sum(1 for f in zwave_frames if not self._is_s0(f) and not self._is_s2(f)),
        }

        if not zwave_frames:
            return {
                "protocol": self.name,
                "pcap": pcap_path,
                "statistics": stats,
                "vulns": []
            }

        vulns = []
        vulns.extend(self._check_no_encryption(zwave_frames, stats))        # ZWAVE-001 CVE-2020-9057
        vulns.extend(self._check_s0_downgrade(zwave_frames))                # ZWAVE-002 CVE-2020-9058
        vulns.extend(self._check_battery_exhaustion(zwave_frames))          # ZWAVE-003 CVE-2020-9059
        vulns.extend(self._check_s2_dos(zwave_frames))                      # ZWAVE-004 CVE-2020-9060
        vulns.extend(self._check_malformed_routing(zwave_frames))           # ZWAVE-005 CVE-2020-9061
        vulns.extend(self._check_find_node_auth(zwave_frames))              # ZWAVE-006 CVE-2020-10137
        vulns.extend(self._check_key_reset_attack(zwave_frames))            # ZWAVE-007 Fouladi & Ghanoun
        vulns.extend(self._check_replay_attack(zwave_frames))               # ZWAVE-008 General replay
        vulns.extend(self._check_home_id_exposure(zwave_frames))            # ZWAVE-009 Info leakage
        vulns.extend(self._check_network_key_in_clear(zwave_frames))        # ZWAVE-010 S0 key exchange

        return {
            "protocol":   self.name,
            "pcap":       pcap_path,
            "statistics": stats,
            "vulns":      vulns,
            "risk_score": self._calculate_risk_score(vulns),
            "topology":   self._build_topology(zwave_frames),
        }

    # ── Frame extraction ───────────────────────────────────────────────────────

    def _get_pcap_link_type(self, pcap_path: str) -> int:
        """Read link type from pcap global header."""
        import struct
        try:
            with open(pcap_path, "rb") as f:
                header = f.read(24)
            if len(header) < 24:
                return -1
            magic = struct.unpack("<I", header[:4])[0]
            if magic in (0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1):
                return struct.unpack("<I", header[20:24])[0]
        except Exception:
            pass
        return -1

    def _extract_zwave_frames(self, packets, pcap_path: str = "") -> List[bytes]:
        """
        Extract Z-Wave frames from packets.
        Uses link type to decide parsing strategy:
        - link type 147 (USER0): raw Z-Wave frames directly
        - other: try heuristic detection with strict validation
        """
        link_type = self._get_pcap_link_type(pcap_path) if pcap_path else -1

        # Known non-Z-Wave link types — return empty immediately
        NON_ZWAVE = {
            195,  # IEEE 802.15.4 = Zigbee
            251,  # Bluetooth LE
            187,  # Bluetooth Classic
            1,    # Ethernet
            105,  # IEEE 802.11 WiFi
            127,  # IEEE 802.11 Radiotap
        }
        if link_type in NON_ZWAVE:
            return []

        frames = []
        for pkt in packets:
            raw = bytes(pkt)

            if link_type == 147:
                # Raw Z-Wave — validate strictly
                if self._is_valid_zwave_frame(raw):
                    frames.append(raw)
            else:
                # Unknown link type — use strict heuristic
                for offset in range(min(len(raw) - ZWAVE_MIN_FRAME_LEN, 16)):
                    candidate = raw[offset:]
                    if self._is_valid_zwave_frame(candidate):
                        frames.append(candidate)
                        break

        return frames

    def _is_valid_zwave_frame(self, data: bytes) -> bool:
        """
        Strict Z-Wave frame validation:
        1. Minimum length check
        2. Length field matches actual data
        3. Checksum validation (XOR)
        4. Source/Dest node IDs in valid range (1-232)
        5. Frame control byte sanity
        """
        if len(data) < ZWAVE_MIN_FRAME_LEN:
            return False

        # Length field at offset 6
        declared_len = data[6]
        if not (10 <= declared_len <= 64):
            return False

        # Frame must have at least declared_len bytes
        if len(data) < declared_len:
            return False

        # Trim to declared length
        frame = data[:declared_len]

        # Node IDs must be 1-232 (valid Z-Wave node range)
        src_id  = frame[4] if len(frame) > 4 else 0
        dest_id = frame[7] if len(frame) > 7 else 0
        if not (1 <= src_id <= 232) or not (0 <= dest_id <= 255):
            return False
        # dest 0 = broadcast is valid, but src 0 is not
        if src_id == 0:
            return False

        # XOR checksum validation
        # checksum = XOR of all bytes except last
        calculated = 0xFF
        for b in frame[:-1]:
            calculated ^= b
        actual = frame[-1]
        if calculated != actual:
            return False

        return True

    def _get_home_id(self, frame: bytes) -> bytes:
        return frame[:4] if len(frame) >= 4 else b''

    def _get_src_id(self, frame: bytes) -> int:
        return frame[4] if len(frame) > 4 else 0

    def _get_dest_id(self, frame: bytes) -> int:
        return frame[7] if len(frame) > 7 else 0

    def _get_cmd_class(self, frame: bytes) -> int:
        return frame[8] if len(frame) > 8 else 0

    def _get_cmd(self, frame: bytes) -> int:
        return frame[9] if len(frame) > 9 else 0

    def _is_s0(self, frame: bytes) -> bool:
        return self._get_cmd_class(frame) == CMD_CLASS_SECURITY

    def _is_s2(self, frame: bytes) -> bool:
        return self._get_cmd_class(frame) == CMD_CLASS_SECURITY_2

    def _is_crc16(self, frame: bytes) -> bool:
        return self._get_cmd_class(frame) == CMD_CLASS_CRC16

    # ── Vulnerability checks ───────────────────────────────────────────────────

    def _check_no_encryption(self, frames: List[bytes], stats: Dict) -> List[Dict]:
        """
        CVE-2020-9057: Silicon Labs 100/200/300 series do not support encryption.
        يكتشف الأجهزة اللي ترسل بدون S0 أو S2 بغض النظر عن الـ command class.
        """
        # الـ frames اللي ليست S0 ولا S2
        unencrypted_frames = [
            f for f in frames
            if not self._is_s0(f) and not self._is_s2(f)
        ]

        # استثن الـ frames اللي هي بطبيعتها unencrypted في كل الشبكات
        ALWAYS_UNENCRYPTED = {
            CMD_CLASS_NO_OPERATION,      # 0x00
            CMD_CLASS_NETWORK_MANAGEMENT # 0x34
        }

        app_unencrypted = [
            f for f in unencrypted_frames
            if self._get_cmd_class(f) not in ALWAYS_UNENCRYPTED
        ]

        if not app_unencrypted:
            return []

        total_app = len([
            f for f in frames
            if self._get_cmd_class(f) not in ALWAYS_UNENCRYPTED
        ])

        pct = len(app_unencrypted) / max(total_app, 1) * 100

        # اكتشف الأجهزة المخالفة
        offending_nodes = set()
        for f in app_unencrypted:
            src = f[4] if len(f) > 4 else 0
            if 1 <= src <= 232:
                offending_nodes.add(src)

        node_list = ", ".join(f"Node {n}" for n in sorted(offending_nodes))
        severity  = "CRITICAL" if pct >= 70 else "HIGH" if pct >= 30 else "MEDIUM"

        return [{
            "id":           "ZWAVE-001",
                "fix_code":     '\n// Fix: Enable S2 Security on All Application Frames\n// Z-Wave SDK (Silicon Labs ZWave SDK)\n\n// In device configuration — request S2 security classes:\nBYTE requestedSecurityKeys = SECURITY_2_ACCESS_CLASS      // Locks, alarms\n                           | SECURITY_2_AUTHENTICATED_CLASS // Sensors\n                           | SECURITY_2_UNAUTHENTICATED_CLASS; // Basic devices\n\n// In ZAF_config.h:\n// #define APP_SECURITY_AUTHENTICATION SECURITY_2_AUTHENTICATED\n// #define REQUESTED_SECURITY_KEYS (SECURITY_2_ACCESS | SECURITY_2_AUTHENTICATED)\n\n// Never include SECURITY_KEY_S0 unless legacy device compatibility required\n// Never set requestedSecurityKeys = 0x00\n\n// Verify S2 bootstrap:\nvoid ZCB_CompleteSecureAdd(BYTE bStatus) {\n    if (bStatus != ADD_NODE_STATUS_DONE) {\n        // S2 bootstrapping failed — remove device\n        ZW_RemoveNodeFromNetwork(REMOVE_NODE_ANY, NULL);\n    }\n}\n',
            "severity":     severity,
            "title":        "Unencrypted Application Traffic Detected",
            "description":  "Z-Wave application frames transmitted without S0 or S2 encryption. "
                            "Silicon Labs 100/200/300 series chipsets do not support encryption, "
                            "exposing device commands to passive eavesdropping.",
            "cve":          ["CVE-2020-9057"],
            "evidence":     f"{len(app_unencrypted)} unencrypted app frames ({pct:.1f}%) "
                            f"from: {node_list}",
            "attack_vector":"Passive eavesdropping within 100m radio range",
            "remediation":  "Replace legacy chipsets with 500/700/800 series. "
                            "Enable S2 Authenticated or S2 Access Control.",
            "references":   ["CERT VU#142629"],
        }]

    def _check_s0_downgrade(self, frames: List[bytes]) -> List[Dict]:
        """
        CVE-2020-9058: S0 downgrade attack via CRC-16 encapsulation.
        500-series devices using CRC-16 can be forced to skip encryption.
        Detects S0 key exchange followed by CRC-16 unencrypted frames.
        """
        s0_exchange = False
        crc16_after_s0 = []

        for i, frame in enumerate(frames):
            cmd_class = self._get_cmd_class(frame)
            cmd       = self._get_cmd(frame)

            # Detect S0 key exchange
            if cmd_class == CMD_CLASS_SECURITY and cmd == SEC_SCHEME_GET:
                s0_exchange = True

            # CRC-16 frames after S0 exchange = potential downgrade
            if s0_exchange and cmd_class == CMD_CLASS_CRC16:
                crc16_after_s0.append(i)

        if not crc16_after_s0:
            return []

        return [{
            "id":           "ZWAVE-002",
                "fix_code":     '\n// Fix: Validate Message Authentication Code (S2 Integrity)\n// Z-Wave S2 automatically provides AEAD encryption\n\n// Ensure S2 is used for all application messages:\n// In ZW_transport_api.h set security level:\n#define ZWAVE_PLUS_INFO_SECURITY_LEVEL SECURITY_2_AUTHENTICATED\n\n// In application message handler — reject unsecured messages:\nvoid ApplicationCommandHandler(ZW_APPLICATION_TX_BUFFER *pCmd,\n                                BYTE cmdLength,\n                                RECEIVE_OPTIONS_TYPE_EX *rxOpt) {\n    // Check security level of received frame\n    if (rxOpt->securityKey < SECURITY_2_UNAUTHENTICATED) {\n        // Reject — command arrived without S2 protection\n        return;\n    }\n    // Process command only if properly secured\n    processSecureCommand(pCmd, cmdLength);\n}\n',
            "severity":     "HIGH",
            "title":        "S0 Security Downgrade via CRC-16 (CVE-2020-9058)",
            "description":  "Z-Wave 500-series devices using CRC-16 encapsulation can be forced "
                            "to communicate without encryption after S0 key exchange, "
                            "enabling an attacker to intercept and inject commands.",
            "cve":          ["CVE-2020-9058"],
            "evidence":     f"S0 key exchange detected, followed by {len(crc16_after_s0)} CRC-16 unencrypted frames",
            "attack_vector":"Active MITM — attacker intercepts inclusion and strips S0 encryption",
            "remediation":  "Upgrade to S2 security. Reject non-S2 frames after secure inclusion.",
            "references":   ["CERT VU#142629"],
        }]

    def _check_battery_exhaustion(self, frames: List[bytes]) -> List[Dict]:
        """
        CVE-2020-9059: Battery exhaustion via S0 nonce flooding.
        Attacker sends excessive NONCE_GET requests forcing device to generate nonces.
        """
        nonce_gets = []
        src_nonce_count = Counter()

        for i, frame in enumerate(frames):
            cmd_class = self._get_cmd_class(frame)
            cmd       = self._get_cmd(frame)
            src       = self._get_src_id(frame)

            if cmd_class == CMD_CLASS_SECURITY and cmd == NONCE_GET:
                nonce_gets.append(i)
                src_nonce_count[src] += 1

        if not nonce_gets:
            return []

        # Suspicious: single source sending many nonce requests
        max_src = src_nonce_count.most_common(1)[0] if src_nonce_count else (0, 0)
        suspicious = max_src[1] > 20

        if not suspicious and len(nonce_gets) < 30:
            return []

        return [{
            "id":           "ZWAVE-003",
                "fix_code":     '\n// Fix: Enforce S2 During Inclusion (Prevent Downgrade)\n// Never fall back to S0 or unsecured inclusion\n\n// Z-Wave SDK — in inclusion handler:\nvoid ZCB_CompleteLearnMode(BYTE bStatus) {\n    if (bStatus == LEARN_MODE_INTERVIEW_COMPLETED) {\n        // Verify S2 was negotiated\n        if (currentSecurityKey < SECURITY_2_UNAUTHENTICATED) {\n            // S2 negotiation failed — abort inclusion\n            ZW_SetLearnMode(LEARN_MODE_DISABLE, NULL);\n            // Notify user that secure inclusion is required\n            showSecurityError();\n        }\n    }\n}\n\n// Controller side (Z/IP Gateway):\n// zwave_controller_storage_preferred_security_level_set(\n//     ZWAVE_CONTROLLER_ENCAPSULATION_SECURITY_2_AUTHENTICATED);\n',
            "severity":     "HIGH",
            "title":        "Battery Exhaustion via S0 Nonce Flooding (CVE-2020-9059)",
            "description":  "Excessive NONCE_GET requests detected. An attacker can flood battery-powered "
                            "devices with nonce requests, forcing constant nonce generation and "
                            "depleting battery within hours.",
            "cve":          ["CVE-2020-9059"],
            "evidence":     f"{len(nonce_gets)} NONCE_GET requests — source {max_src[0]:02x} sent {max_src[1]}",
            "attack_vector":"Radio-range attacker sends continuous nonce requests to battery device",
            "remediation":  "Implement rate limiting for nonce requests. Upgrade to S2 which uses ECDH.",
            "references":   ["CERT VU#142629"],
        }]

    def _check_s2_dos(self, frames: List[bytes]) -> List[Dict]:
        """
        CVE-2020-9060: DoS via malformed S2 security messages.
        Malformed NONCE_GET/NONCE_GET2/NO_OPERATION/NIF_REQUEST cause crashes.
        """
        malformed_s2 = []
        no_operation = []

        for i, frame in enumerate(frames):
            cmd_class = self._get_cmd_class(frame)
            cmd       = self._get_cmd(frame)

            # S2 nonce operations (potential DoS vectors per CVE-2020-9060)
            if cmd_class == CMD_CLASS_SECURITY_2 and cmd in [S2_NONCE_GET, S2_NONCE_REPORT]:
                # Check for malformed: frame too short for expected payload
                expected_min = 12
                if len(frame) < expected_min:
                    malformed_s2.append(i)

            # Excessive NO_OPERATION frames
            if cmd_class == CMD_CLASS_NO_OPERATION:
                no_operation.append(i)

        if not malformed_s2 and len(no_operation) < 20:
            return []

        evidence_parts = []
        if malformed_s2:
            evidence_parts.append(f"{len(malformed_s2)} malformed S2 nonce frames")
        if len(no_operation) >= 20:
            evidence_parts.append(f"{len(no_operation)} NO_OPERATION frames (potential NIF flood)")

        return [{
            "id":           "ZWAVE-004",
                "fix_code":     '\n// Fix: Implement Sequence Number Validation (Prevent Replay)\n// Z-Wave S2 includes replay protection via SPAN (Singlecast PAN)\n\n// Verify S2 SPAN counter is strictly increasing:\n// This is handled automatically by Z-Wave S2 stack\n\n// For S0 devices (legacy) — add manual sequence tracking:\n#define MAX_SEQUENCE_TABLE 20\nstatic uint8_t lastSeqNum[MAX_SEQUENCE_TABLE];\nstatic uint16_t seqNodeIds[MAX_SEQUENCE_TABLE];\n\nbool isReplay(uint16_t nodeId, uint8_t seqNum) {\n    for (int i = 0; i < MAX_SEQUENCE_TABLE; i++) {\n        if (seqNodeIds[i] == nodeId) {\n            if (seqNum <= lastSeqNum[i]) return true; // replay!\n            lastSeqNum[i] = seqNum;\n            return false;\n        }\n    }\n    // New node — add to table\n    addToSequenceTable(nodeId, seqNum);\n    return false;\n}\n',
            "severity":     "HIGH",
            "title":        "S2 Denial of Service via Malformed Messages (CVE-2020-9060)",
            "description":  "Malformed S2 security messages or excessive NO_OPERATION frames detected. "
                            "Silicon Labs 500/700-series devices crash or become unresponsive "
                            "when receiving malformed NONCE_GET or NO_OPERATION floods.",
            "cve":          ["CVE-2020-9060"],
            "evidence":     " | ".join(evidence_parts),
            "attack_vector":"Radio-range attacker sends crafted S2 frames to crash target device",
            "remediation":  "Apply Silicon Labs firmware patches. Implement frame validation and rate limiting.",
            "references":   ["CERT VU#142629"],
        }]

    def _check_malformed_routing(self, frames: List[bytes]) -> List[Dict]:
        """
        CVE-2020-9061: DoS via malformed routing messages.
        500/700-series vulnerable to crash via crafted routing frames.
        """
        suspect_routing = []

        for i, frame in enumerate(frames):
            if len(frame) < 8:
                continue

            # Frame control byte at offset 5
            frame_ctrl = frame[5] if len(frame) > 5 else 0

            # Routed frame bit set (bit 7) but routing info inconsistent
            is_routed = (frame_ctrl & 0x80) != 0

            if is_routed:
                # Check routing fields: repeater count at offset after dest
                if len(frame) > 9:
                    repeater_count = (frame[8] >> 4) & 0x0F
                    # More than 4 repeaters is invalid in Z-Wave
                    if repeater_count > 4:
                        suspect_routing.append(i)
                    # Routing length exceeds frame length
                    expected_len = 9 + repeater_count
                    if expected_len >= len(frame):
                        suspect_routing.append(i)

        if not suspect_routing:
            return []

        return [{
            "id":           "ZWAVE-005",
                "fix_code":     '\n// Fix: Prevent Network-Wide Inclusion Attacks\n// Restrict inclusion to authenticated methods only\n\n// Disable SmartStart automatic inclusion in production:\n// In ZAF_config.h:\n// #define ZAF_CONFIG_SMARTSTART_ENABLED 0  // Disable if not needed\n\n// If SmartStart required, validate DSK before confirming:\nvoid ZCB_SmartStartIncludePrimary(uint8_t *dsk) {\n    // Verify DSK matches printed label on device\n    if (!verifyDSKWithDatabase(dsk)) {\n        // Reject — DSK not in approved list\n        ZW_SmartStartInclusionAccept(false);\n        return;\n    }\n    ZW_SmartStartInclusionAccept(true);\n}\n\n// Limit inclusion window to 60 seconds max:\nZW_ExploreRequestInclusion();\n// After 60 seconds:\nZW_SetLearnMode(LEARN_MODE_DISABLE, NULL);\n',
            "severity":     "MEDIUM",
            "title":        "Malformed Routing Messages - DoS Risk (CVE-2020-9061)",
            "description":  "Invalid routing frames detected with illegal repeater counts or "
                            "inconsistent routing fields. Silicon Labs 500/700-series chipsets "
                            "are vulnerable to crashes from malformed routing messages.",
            "cve":          ["CVE-2020-9061"],
            "evidence":     f"{len(suspect_routing)} frames with invalid routing fields",
            "attack_vector":"Attacker injects crafted routing frames to crash routers or the controller",
            "remediation":  "Update firmware to latest Silicon Labs release. "
                            "Validate repeater count and routing length before processing.",
            "references":   ["CERT VU#142629"],
        }]

    def _check_find_node_auth(self, frames: List[bytes]) -> List[Dict]:
        """
        CVE-2020-10137: FIND_NODE_IN_RANGE frames not authenticated in S2.
        700-series chipsets allow unauthenticated node discovery.
        """
        network_mgmt_frames = []
        unauthenticated_discovery = []

        for i, frame in enumerate(frames):
            cmd_class = self._get_cmd_class(frame)

            if cmd_class == CMD_CLASS_NETWORK_MANAGEMENT:
                network_mgmt_frames.append(i)
                # If not wrapped in S2 encapsulation → unauthenticated
                if not self._is_s2(frame):
                    unauthenticated_discovery.append(i)

        if not unauthenticated_discovery:
            return []

        return [{
            "id":           "ZWAVE-006",
                "fix_code":     '\n// Fix: Encrypt All Sensitive Command Classes\n// Map command classes to required security levels\n\n// In ZAF_CommandClassList.c — define required security per CC:\nconst cc_handler_map_t CC_handler_map[] = {\n    // Door Lock — requires S2 Access class\n    {COMMAND_CLASS_DOOR_LOCK, SECURITY_2_ACCESS_CLASS,\n     CC_DoorLock_handler},\n\n    // Thermostat — requires S2 Authenticated\n    {COMMAND_CLASS_THERMOSTAT_MODE, SECURITY_2_AUTHENTICATED_CLASS,\n     CC_Thermostat_handler},\n\n    // Battery — requires at least S2 Unauthenticated\n    {COMMAND_CLASS_BATTERY, SECURITY_2_UNAUTHENTICATED_CLASS,\n     CC_Battery_handler},\n\n    // Basic — can be unsecured (non-sensitive)\n    {COMMAND_CLASS_BASIC, SECURITY_NONE,\n     CC_Basic_handler},\n};\n\n// Reject commands below required security level:\nif (rxSecurityKey < CC_handler_map[cc].requiredSecurity) {\n    return; // Silently drop\n}\n',
            "severity":     "MEDIUM",
            "title":        "Unauthenticated Node Discovery (CVE-2020-10137)",
            "description":  "FIND_NODE_IN_RANGE frames transmitted without S2 authentication. "
                            "Z-Wave 700-series chipsets do not adequately authenticate these frames, "
                            "enabling attackers to map the network topology without credentials.",
            "cve":          ["CVE-2020-10137"],
            "evidence":     f"{len(unauthenticated_discovery)} unauthenticated network management frames",
            "attack_vector":"Passive attacker maps full Z-Wave mesh topology without joining network",
            "remediation":  "Apply Silicon Labs SDK patch. Require S2 Authenticated for all management frames.",
            "references":   ["CERT VU#142629"],
        }]

    def _check_key_reset_attack(self, frames: List[bytes]) -> List[Dict]:
        """
        Key Reset Attack (Fouladi & Ghanoun, 2013 — affects millions of devices).
        Attacker re-runs inclusion protocol using intercepted Home ID
        to establish new key with already-paired device (e.g. smart lock).
        Detects multiple S0 key exchanges for same device.
        """
        key_exchanges_per_device = defaultdict(list)

        for i, frame in enumerate(frames):
            cmd_class = self._get_cmd_class(frame)
            cmd       = self._get_cmd(frame)
            src       = self._get_src_id(frame)

            if cmd_class == CMD_CLASS_SECURITY and cmd in [SEC_SCHEME_GET, SEC_NETWORK_KEY_SET]:
                key_exchanges_per_device[src].append(i)

        # Flag devices with more than one key exchange
        vulnerable = {
            src: indices
            for src, indices in key_exchanges_per_device.items()
            if len(indices) > 1
        }

        if not vulnerable:
            return []

        affected = list(vulnerable.keys())

        return [{
            "id":           "ZWAVE-007",
                "fix_code":     '\n// Fix: Prevent Key Reset / Re-Interview Attacks\n// Validate Security Scheme Get commands\n\n// In S0 security handler — limit key negotiation attempts:\nstatic uint8_t keyNegotiationCount = 0;\n#define MAX_KEY_NEGOTIATIONS 1\n\nvoid CC_Security_SchemeGet_handler(ZW_APPLICATION_TX_BUFFER *rxBuf,\n                                    RECEIVE_OPTIONS_TYPE_EX *rxOpt) {\n    if (++keyNegotiationCount > MAX_KEY_NEGOTIATIONS) {\n        // Already negotiated — reject re-negotiation attempt\n        // This prevents key reset attacks\n        sendSecurityAlert(KEY_RESET_ATTEMPT, rxOpt->sourceNode);\n        return;\n    }\n    // Process legitimate first-time negotiation only\n    processKeyNegotiation(rxBuf, rxOpt);\n}\n\n// Reset counter only after successful factory reset:\nvoid factoryReset() {\n    keyNegotiationCount = 0;\n    ZW_SetDefault();\n}\n',
            "severity":     "CRITICAL",
            "title":        "Key Reset Attack — Re-pairing Without Authentication",
            "description":  "Multiple S0 key exchange sequences detected for the same device. "
                            "An attacker who intercepts the Home ID (present in every frame) "
                            "can impersonate the controller and re-run key establishment, "
                            "replacing the network key on smart locks and other devices.",
            "cve":          [],
            "evidence":     f"{len(vulnerable)} device(s) with multiple key exchanges: "
                            f"{[f'0x{s:02x}' for s in affected[:5]]}",
            "attack_vector":"Attacker intercepts Home ID then sends SEC_SCHEME_GET impersonating controller",
            "real_world":   "Demonstrated on commercial Z-Wave door locks — attacker unlocks door "
                            "without knowing original network key",
            "remediation":  "Devices must verify existing key before accepting re-pairing. "
                            "Use S2 which requires out-of-band DSK verification.",
            "references":   [
                "Fouladi & Ghanoun: Security Evaluation of Z-Wave (2013)",
                "https://www.securityindustry.org/2019/04/23/mitigating-risks-from-a-to-z-wave/",
            ],
        }]

    def _check_replay_attack(self, frames: List[bytes]) -> List[Dict]:
        """
        Replay attack: Z-Wave S0 uses nonces but older devices
        have weak or no sequence number validation.
        Uses FULL frame payload as fingerprint to avoid false positives
        from structurally similar but distinct frames.
        """
        seen = {}   # full_frame_bytes → first_seen_index
        replay_candidates = []

        for i, frame in enumerate(frames):
            if len(frame) < 12:
                continue

            # Skip S2-encrypted frames — they have built-in replay protection
            if self._is_s2(frame):
                continue

            src = self._get_src_id(frame)

            # Full frame fingerprint (minus checksum byte which may vary)
            fingerprint = (src, frame[:-1])

            if fingerprint in seen:
                replay_candidates.append({
                    "frame_idx":   i,
                    "first_seen":  seen[fingerprint],
                    "src":         f"0x{src:02x}",
                    "cmd_class":   f"0x{self._get_cmd_class(frame):02x}",
                })
            else:
                seen[fingerprint] = i

        # Require at least 2 confirmed replays to reduce false positives
        if len(replay_candidates) < 2:
            return []

        return [{
            "id":           "ZWAVE-008",
                "fix_code":     '\n// Fix: Prevent Frame Injection via Sequence Validation\n// Detect and reject duplicate Z-Wave frames\n\n#define DUPLICATE_WINDOW_SIZE 16\nstatic struct {\n    uint16_t nodeId;\n    uint8_t  seqNo;\n    uint32_t timestamp;\n} duplicateTable[DUPLICATE_WINDOW_SIZE];\nstatic uint8_t dupIdx = 0;\n\nbool isDuplicate(uint16_t nodeId, uint8_t seqNo) {\n    uint32_t now = ZW_GetTickTime();\n    for (int i = 0; i < DUPLICATE_WINDOW_SIZE; i++) {\n        if (duplicateTable[i].nodeId == nodeId &&\n            duplicateTable[i].seqNo  == seqNo  &&\n            (now - duplicateTable[i].timestamp) < 5000) {\n            return true; // Duplicate within 5 seconds\n        }\n    }\n    // Add to table\n    duplicateTable[dupIdx % DUPLICATE_WINDOW_SIZE] = {nodeId, seqNo, now};\n    dupIdx++;\n    return false;\n}\n',
            "severity":     "MEDIUM",
            "title":        "Replay Attack — Confirmed Duplicate Frame Injection",
            "description":  "Confirmed identical Z-Wave frames from the same source detected. "
                            "Devices without proper nonce validation or sequence counters "
                            "accept replayed commands, allowing attackers to re-trigger actions "
                            "(e.g. unlock door, turn off alarm).",
            "cve":          ["CVE-2020-9058"],
            "evidence":     f"{len(replay_candidates)} confirmed duplicate frames "
                            f"(first replay at frame #{replay_candidates[0]['frame_idx']})",
            "attack_vector":"Attacker captures and replays valid unencrypted command frames",
            "remediation":  "Use S2 security which enforces ECDH + AES-128-CCM with sequence counters. "
                            "Reject frames with seen nonces.",
            "references":   ["Z-Wave S2 Security Specification"],
            "technical_details": replay_candidates[:5],
        }]

    def _check_home_id_exposure(self, frames: List[bytes]) -> List[Dict]:
        """
        Information leakage: Home ID transmitted in plaintext in every frame.
        Enables targeted attacks (Key Reset, network mapping).
        Detects known weak/test Home IDs or consistent Home ID broadcasting.
        """
        home_ids = Counter()
        weak_home_ids = []

        for frame in frames:
            if len(frame) < 4:
                continue
            home_id = self._get_home_id(frame)
            home_ids[home_id] += 1
            if home_id in KNOWN_TEST_HOME_IDS:
                weak_home_ids.append(home_id)

        if not home_ids:
            return []

        vulns = []

        # All frames expose Home ID (always a finding for awareness)
        most_common_id = home_ids.most_common(1)[0]
        vulns.append({
            "id":           "ZWAVE-009",
                "fix_code":     '\n// Fix: Protect Home ID from Information Leakage\n// Use Z-Wave Long Range (ZWLR) with encrypted beacon\n\n// Z-Wave 700/800 series — enable Home ID encryption:\n// The Home ID is always in plaintext in classic Z-Wave\n// Mitigation: Use Z-Wave Long Range (800 series) which\n// has improved privacy features\n\n// Immediate mitigations:\n// 1. Change Home ID periodically (requires re-pairing all devices)\n// 2. Use Z-Wave S2 which encrypts the payload (Home ID still visible)\n// 3. Upgrade to Z-Wave 800 series (ZGM230) with ZWLR\n\n// In Z/IP Gateway — enable network-level security:\n// Set unique strong network key (not default):\nuint8_t networkKey[16] = {\n    // Use cryptographically random 128-bit key\n    // NEVER use all-zeros or default keys\n};\nZW_SetNetworkKey(networkKey);\n',
            "severity":     "LOW",
            "title":        "Home ID Exposed in Plaintext (Information Leakage)",
            "description":  "Z-Wave transmits the 4-byte Home ID unencrypted in every single frame. "
                            "This enables attackers to identify the network, target specific controllers, "
                            "and is a prerequisite for the Key Reset attack (ZWAVE-007).",
            "cve":          [],
            "evidence":     f"{sum(home_ids.values())} frames expose Home ID. "
                            f"Most frequent: {most_common_id[0].hex()} ({most_common_id[1]} times)",
            "attack_vector":"Passive sniffing — no association required",
            "remediation":  "No fix available at protocol level. "
                            "Mitigate by using S2 to prevent key reset attacks that exploit Home ID.",
            "references":   [
                "Fouladi & Ghanoun: Security Evaluation of Z-Wave (2013)",
                "arXiv:2001.08497 — Crushing the Wave",
            ],
        })

        # Weak/test Home ID is more severe
        if weak_home_ids:
            vulns.append({
                "id":           "ZWAVE-009B",
                "severity":     "HIGH",
                "title":        "Weak/Default Home ID Detected",
                "description":  "Network using a known weak or default Home ID. "
                                "Attackers can predict or brute-force the controller identity.",
                "cve":          [],
                "evidence":     f"Weak Home IDs: {list(set(h.hex() for h in weak_home_ids[:3]))}",
                "remediation":  "Reset controller to generate a cryptographically random Home ID.",
                "references":   [],
            })

        return vulns

    def _check_network_key_in_clear(self, frames: List[bytes]) -> List[Dict]:
        """
        ZWAVE-010: S0 Network Key Exchange in cleartext.
        S0 transmits the 16-byte network key encrypted with a well-known
        all-zeros temporary key — effectively in the clear.
        Detects SEC_NETWORK_KEY_SET commands.
        """
        key_set_frames = []

        for i, frame in enumerate(frames):
            cmd_class = self._get_cmd_class(frame)
            cmd       = self._get_cmd(frame)

            if cmd_class == CMD_CLASS_SECURITY and cmd == SEC_NETWORK_KEY_SET:
                key_set_frames.append(i)

        if not key_set_frames:
            return []

        return [{
            "id":           "ZWAVE-010",
                "fix_code":     '\n// Fix: Secure Network Key Exchange (Prevent Zero-Key Attack)\n// Z-Wave S2 uses ECDH key exchange — never transmits key in plaintext\n\n// CRITICAL: Never use S0 for new devices — S0 sends key in plaintext!\n// Always use S2 which uses ECDH:\n\n// In inclusion handler — reject S0 key exchange:\nvoid ZCB_CompleteSecureAdd(BYTE bStatus) {\n    if (currentSecurityClass == SECURITY_KEY_S0) {\n        // S0 uses temporary key transmitted in plaintext\n        // Remove device and require S2 re-inclusion\n        ZW_RemoveNodeFromNetwork(REMOVE_NODE_ANY, NULL);\n        showError("S0 not allowed — please re-include with S2");\n        return;\n    }\n}\n\n// Verify S2 ECDH key exchange completed:\n// S2 uses Curve25519 ECDH — key never transmitted over air\n// DSK (Device Specific Key) used to authenticate the exchange\n\n// For Z/IP Gateway:\n// zwave_controller_storage_preferred_security_level_set(\n//     ZWAVE_CONTROLLER_ENCAPSULATION_SECURITY_2_ACCESS);\n',
            "severity":     "CRITICAL",
            "title":        "S0 Network Key Transmitted with Temporary Zero Key",
            "description":  "S0 NETWORK_KEY_SET command detected. The S0 security scheme "
                            "encrypts the 16-byte network key using a temporary all-zeros key "
                            "(0x00 * 16), which is publicly known. Any passive observer "
                            "within radio range during device inclusion can recover the network key "
                            "and decrypt all past and future S0-encrypted traffic.",
            "cve":          [],
            "evidence":     f"{len(key_set_frames)} NETWORK_KEY_SET frame(s) captured during inclusion",
            "attack_vector":"Passive sniffing during device pairing/inclusion",
            "real_world":   "Demonstrated against Schlage, Yale, and Kwikset Z-Wave smart locks",
            "remediation":  "Migrate entirely to S2 security which uses ECDH key agreement — "
                            "network key never transmitted over the air.",
            "references":   [
                "Fouladi & Ghanoun: Security Evaluation of Z-Wave (2013)",
                "Z-Wave S2 Security White Paper",
                "arXiv:2001.08497",
            ],
        }]

    # ── Risk score ─────────────────────────────────────────────────────────────

    def _calculate_risk_score(self, vulns: List[Dict]) -> int:
        if not vulns:
            return 0
        weights = {"CRITICAL": 35, "HIGH": 15, "MEDIUM": 10, "LOW": 5}
        return min(sum(weights.get(v["severity"], 0) for v in vulns), 100)

    # ── Device fingerprinting ──────────────────────────────────────────────────

    # Command Class → device type mapping (based on Z-Wave spec)
    CMD_CLASS_DEVICE_TYPES = {
        0x62: "Door Lock",
        0x40: "Thermostat",
        0x31: "Sensor",
        0x30: "Motion Sensor",
        0x25: "Switch",
        0x26: "Dimmer",
        0x50: "Basic Device",
        0x60: "Multi-Channel",
        0x70: "Config",
        0x72: "Manufacturer Info",
        0x80: "Battery",
        0x84: "Wake Up",
        0x86: "Version",
        0x98: "S0 Device",
        0x9F: "S2 Device",
        0x34: "Network Mgmt",
        0x56: "CRC-16",
        0x20: "Basic",
        0x21: "Controller Replication",
    }

    def _fingerprint_device(self, cmd_classes: set, role: str) -> str:
        """يحاول يعرف نوع الجهاز من الـ command classes اللي استخدمها."""
        if role == "controller":
            return "Controller / Hub"
        # Priority order — أهم الأجهزة أولاً
        priority = [0x62, 0x40, 0x30, 0x31, 0x25, 0x26, 0x60, 0x80, 0x84]
        for cc in priority:
            if cc in cmd_classes:
                return self.CMD_CLASS_DEVICE_TYPES[cc]
        if 0x9F in cmd_classes:
            return "S2 Device"
        if 0x98 in cmd_classes:
            return "S0 Device"
        return "Z-Wave Device"

    # ── Topology builder ───────────────────────────────────────────────────────

    def _build_topology(self, frames: List[bytes]) -> dict:
        """
        يبني topology حقيقية من Z-Wave frames.
        يستخرج Node IDs، أنواع الأجهزة، والاتصالات.
        """
        node_info = {}   # node_id → info dict
        edge_info = defaultdict(lambda: {"count":0,"s0":0,"s2":0,"unencrypted":0})
        home_ids  = set()

        for frame in frames:
            if len(frame) < 10:
                continue

            home_id = frame[:4].hex().upper()
            src     = frame[4]
            dst     = frame[7]
            cmd_cls = frame[8] if len(frame) > 8 else 0

            home_ids.add(home_id)

            is_s0 = cmd_cls == CMD_CLASS_SECURITY
            is_s2 = cmd_cls == CMD_CLASS_SECURITY_2

            # Register source node
            if src not in node_info:
                node_info[src] = {
                    "count": 0, "s0": 0, "s2": 0, "unencrypted": 0,
                    "role": "controller" if src == 1 else "device",
                    "cmd_classes": set(),
                }
            node_info[src]["count"] += 1
            node_info[src]["cmd_classes"].add(cmd_cls)

            if is_s0:
                node_info[src]["s0"] += 1
            elif is_s2:
                node_info[src]["s2"] += 1
            else:
                node_info[src]["unencrypted"] += 1

            # Register destination node
            if dst not in node_info:
                node_info[dst] = {
                    "count": 0, "s0": 0, "s2": 0, "unencrypted": 0,
                    "role": "controller" if dst == 1 else "device",
                    "cmd_classes": set(),
                }
            node_info[dst]["count"] += 1

            # Edge
            key = (src, dst)
            edge_info[key]["count"] += 1
            if is_s0:
                edge_info[key]["s0"]   += 1
            elif is_s2:
                edge_info[key]["s2"]   += 1
            else:
                edge_info[key]["unencrypted"] += 1

        # Build nodes list with fingerprinting
        nodes = []
        for nid, info in node_info.items():
            device_type = self._fingerprint_device(info["cmd_classes"], info["role"])
            encrypted   = info["s0"] + info["s2"]
            unencrypted = info["unencrypted"]
            nodes.append({
                "id":           f"Node {nid}",
                "label":        f"Node {nid}\n{device_type}",
                "device_type":  device_type,
                "role":         info["role"],
                "packet_count": info["count"],
                "encrypted":    encrypted,
                "unencrypted":  unencrypted,
                "s0":           info["s0"],
                "s2":           info["s2"],
                "secure":       encrypted >= unencrypted and unencrypted == 0,
                "protocol":     "Z-Wave",
            })

        edges = [
            {
                "from":        f"Node {src}",
                "to":          f"Node {dst}",
                "count":       info["count"],
                "encrypted":   info["s0"] + info["s2"],
                "unencrypted": info["unencrypted"],
                "secure":      info["unencrypted"] == 0,
            }
            for (src, dst), info in edge_info.items()
        ]

        return {
            "nodes":    nodes,
            "edges":    edges,
            "home_ids": list(home_ids),
        }
