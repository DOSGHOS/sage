#!/usr/bin/env python3
"""
Test PCAP Generator for IoT Vulnerability Scanner Demo
Generates realistic test captures with known vulnerabilities
"""
import sys

try:
    from scapy.all import *
    from scapy.layers.dot15d4 import *
    from scapy.layers.zigbee import *
    from scapy.layers.bluetooth import *
    from scapy.layers.bluetooth4LE import *
except ImportError:
    print("Error: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

def generate_vulnerable_zigbee():
    """Generate Zigbee capture with multiple vulnerabilities"""
    print("[*] Generating vulnerable Zigbee capture...")
    packets = []
    
    # Scenario: Unencrypted traffic (ZIGBEE-001)
    print("  - Adding unencrypted traffic...")
    for i in range(50):
        pkt = Dot15d4(fcf_frametype=1, seqnum=i) / \
              Dot15d4Data() / \
              ZigbeeNWK(flags=0x00, seqnum=i, source=0x1234, destination=0x0000)
        packets.append(pkt)
    
    # Scenario: Insecure joining (ZIGBEE-003)
    print("  - Adding insecure join attempts...")
    for i in range(15):
        pkt = Dot15d4(fcf_frametype=3, seqnum=100+i) / \
              Dot15d4Cmd(cmd_id=0x01)  # Association request
        packets.append(pkt)
    
    # Scenario: Replay attack pattern (ZIGBEE-004)
    print("  - Adding replay attack pattern...")
    duplicate_pkt = Dot15d4(fcf_frametype=1, seqnum=50) / \
                    Dot15d4Data() / \
                    ZigbeeNWK(seqnum=50, source=0x1234)
    for _ in range(5):
        packets.append(duplicate_pkt)
    
    # Scenario: Key transport (ZIGBEE-005)
    print("  - Adding key transport...")
    key_pkt = Dot15d4(fcf_frametype=1) / \
              Dot15d4Data() / \
              ZigbeeNWK() / \
              ZigbeeAppDataPayload(cluster=0x0000)
    packets.append(key_pkt)
    
    # Scenario: Routing manipulation (ZIGBEE-010)
    print("  - Adding excessive route requests...")
    for i in range(30):
        pkt = Dot15d4(fcf_frametype=1) / \
              Dot15d4Data() / \
              ZigbeeNWK(frametype=1, seqnum=200+i)  # Route request
        packets.append(pkt)
    
    # Scenario: DoS pattern (ZIGBEE-007)
    print("  - Adding DoS flooding from single source...")
    for i in range(100):
        pkt = Dot15d4(fcf_frametype=1) / \
              Dot15d4Data(src_addr=0xBAD1)
        packets.append(pkt)
    
    # Add some beacons
    for i in range(20):
        beacon = Dot15d4(fcf_frametype=0) / Dot15d4Beacon()
        packets.append(beacon)
    
    filename = "test_vulnerable_zigbee.pcap"
    wrpcap(filename, packets)
    print(f"[✓] Generated {filename} with {len(packets)} packets")
    print(f"    Expected vulnerabilities: ZIGBEE-001, 003, 004, 005, 007, 010")
    return filename

def generate_vulnerable_ble():
    """Generate BLE capture with multiple vulnerabilities"""
    print("\n[*] Generating vulnerable BLE capture...")
    packets = []
    
    # Scenario: Just Works pairing (BLE-003)
    print("  - Adding Just Works pairing...")
    try:
        pairing_req = BTLE() / BTLE_DATA() / L2CAP_Hdr() / \
                      SM_Hdr() / SM_Pairing_Request(
                          authentication=0x00,  # No MITM, no bonding
                          oob=0x00
                      )
        packets.append(pairing_req)
        
        pairing_resp = BTLE() / BTLE_DATA() / L2CAP_Hdr() / \
                       SM_Hdr() / SM_Pairing_Response(
                           authentication=0x00
                       )
        packets.append(pairing_resp)
    except Exception as e:
        print(f"    Warning: SM layers not fully available: {e}")
    
    # Scenario: Legacy pairing (BLE-004)
    print("  - Adding legacy pairing...")
    try:
        legacy_pair = BTLE() / BTLE_DATA() / L2CAP_Hdr() / \
                      SM_Hdr() / SM_Pairing_Request(
                          authentication=0x04  # MITM but no SC
                      )
        packets.append(legacy_pair)
    except:
        pass
    
    # Scenario: Unencrypted GATT operations (BLE-006)
    print("  - Adding unencrypted GATT reads/writes...")
    try:
        for i in range(30):
            read_pkt = BTLE(access_addr=0x8e89bed6) / \
                       BTLE_DATA() / L2CAP_Hdr() / \
                       ATT_Hdr() / ATT_Read_Request(gatt_handle=i+1)
            packets.append(read_pkt)
        
        for i in range(20):
            write_pkt = BTLE(access_addr=0x8e89bed6) / \
                        BTLE_DATA() / L2CAP_Hdr() / \
                        ATT_Hdr() / ATT_Write_Request(
                            gatt_handle=i+1,
                            data=b'\x01\x02\x03'
                        )
            packets.append(write_pkt)
    except Exception as e:
        print(f"    Warning: GATT layers limited: {e}")
    
    # Scenario: Static address (privacy issue) (BLE-005)
    print("  - Adding static addresses...")
    try:
        for i in range(100):
            adv = BTLE(access_addr=0x8e89bed6) / \
                  BTLE_ADV() / \
                  BTLE_ADV_IND()
            packets.append(adv)
    except:
        # Fallback to simple BLE packets
        for i in range(100):
            pkt = BTLE(access_addr=0x8e89bed6) / BTLE_DATA()
            packets.append(pkt)
    
    # Scenario: Connection request flooding (BLE-011)
    print("  - Adding connection flooding...")
    for i in range(120):
        try:
            conn_req = BTLE() / BTLE_ADV() / BTLE_CONNECT_REQ()
            packets.append(conn_req)
        except:
            # Fallback
            pkt = BTLE() / BTLE_DATA()
            packets.append(pkt)
    
    # Scenario: Rapid reconnection (relay attack indicator) (BLE-008)
    print("  - Adding rapid reconnection pattern...")
    try:
        for i in range(10):
            ctrl = BTLE() / BTLE_DATA() / BTLE_CTRL(opcode=0x00)
            packets.append(ctrl)
            ctrl2 = BTLE() / BTLE_DATA() / BTLE_CTRL(opcode=0x01)
            packets.append(ctrl2)
    except:
        for i in range(20):
            pkt = BTLE() / BTLE_DATA()
            packets.append(pkt)
    
    # Scenario: Weak key negotiation (BLE-002 - KNOB)
    print("  - Adding weak key negotiation...")
    try:
        enc_req = BTLE() / BTLE_DATA() / BTLE_CTRL(opcode=0x03)
        packets.append(enc_req)
    except:
        pass
    
    # Scenario: Suspicious pairing attempts (BLE-007)
    print("  - Adding suspicious re-pairing...")
    try:
        for i in range(5):
            pair = BTLE() / BTLE_DATA() / L2CAP_Hdr() / \
                   SM_Hdr() / SM_Pairing_Request(authentication=0x00)
            packets.append(pair)
    except:
        pass
    
    # Scenario: Malformed packets (BLE-009 - SweynTooth)
    print("  - Adding malformed L2CAP packets...")
    try:
        malformed = BTLE() / BTLE_DATA() / L2CAP_Hdr(len=0x0000)
        packets.append(malformed)
        
        malformed2 = BTLE() / BTLE_DATA() / L2CAP_Hdr() / \
                     ATT_Hdr(opcode=0xFF)  # Invalid opcode
        packets.append(malformed2)
    except:
        pass
    
    # Add some normal scan requests
    print("  - Adding scan requests...")
    for i in range(50):
        try:
            scan = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ()
            packets.append(scan)
        except:
            pkt = BTLE() / BTLE_DATA()
            packets.append(pkt)
    
    if not packets:
        print("    Warning: Generating minimal BLE packets due to layer limitations")
        for i in range(200):
            pkt = BTLE(access_addr=0x8e89bed6) / BTLE_DATA()
            packets.append(pkt)
    
    filename = "test_vulnerable_ble.pcap"
    wrpcap(filename, packets)
    print(f"[✓] Generated {filename} with {len(packets)} packets")
    print(f"    Expected vulnerabilities: BLE-002, 003, 004, 005, 006, 007, 008, 009, 011")
    return filename

def generate_secure_zigbee():
    """Generate secure Zigbee capture (minimal vulnerabilities)"""
    print("\n[*] Generating secure Zigbee capture...")
    packets = []
    
    # Encrypted traffic with proper security
    for i in range(100):
        pkt = Dot15d4(fcf_frametype=1, seqnum=i) / \
              Dot15d4Data() / \
              ZigbeeNWK(flags=0x08, seqnum=i) / \
              ZigbeeSecurityHeader(key_type=1)
        packets.append(pkt)
    
    # Normal beacons
    for i in range(10):
        beacon = Dot15d4(fcf_frametype=0) / Dot15d4Beacon()
        packets.append(beacon)
    
    filename = "test_secure_zigbee.pcap"
    wrpcap(filename, packets)
    print(f"[✓] Generated {filename} with {len(packets)} packets")
    print(f"    Expected: LOW risk score (properly encrypted)")
    return filename

def generate_secure_ble():
    """Generate secure BLE capture (minimal vulnerabilities)"""
    print("\n[*] Generating secure BLE capture...")
    packets = []
    
    # Secure Connections pairing
    try:
        secure_pair = BTLE() / BTLE_DATA() / L2CAP_Hdr() / \
                      SM_Hdr() / SM_Pairing_Request(
                          authentication=0x0C,  # MITM + SC
                          oob=0x00
                      )
        packets.append(secure_pair)
    except:
        pass
    
    # Encryption start
    try:
        enc_start = BTLE() / BTLE_DATA() / BTLE_CTRL(opcode=0x06)
        packets.append(enc_start)
    except:
        pass
    
    # Encrypted GATT operations (simulated)
    for i in range(50):
        # In real scenario, payload would be encrypted
        encrypted_data = BTLE(access_addr=0x8e89bed6) / BTLE_DATA()
        packets.append(encrypted_data)
    
    # Address randomization (changing addresses) - simplified
    print("  - Adding address randomization patterns...")
    for i in range(30):
        # Multiple advertisements with different access addresses
        adv = BTLE(access_addr=0x8e89bed6 + i) / BTLE_DATA()
        packets.append(adv)
    
    # Add some encrypted-looking control packets
    for i in range(20):
        try:
            ctrl = BTLE() / BTLE_DATA() / BTLE_CTRL(opcode=0x06)  # LL_START_ENC_RSP
            packets.append(ctrl)
        except:
            pkt = BTLE() / BTLE_DATA()
            packets.append(pkt)
    
    filename = "test_secure_ble.pcap"
    wrpcap(filename, packets)
    print(f"[✓] Generated {filename} with {len(packets)} packets")
    print(f"    Expected: LOW risk score (secure connections)")
    return filename

def generate_mixed_scenario():
    """Generate realistic mixed scenario"""
    print("\n[*] Generating realistic mixed scenario...")
    packets = []
    
    # Zigbee smart home: mostly encrypted, some issues
    print("  - Simulating Zigbee smart home...")
    
    # 80% encrypted traffic
    for i in range(80):
        pkt = Dot15d4(fcf_frametype=1, seqnum=i) / \
              Dot15d4Data() / \
              ZigbeeNWK(flags=0x08, seqnum=i)
        packets.append(pkt)
    
    # 20% unencrypted (configuration/pairing)
    for i in range(20):
        pkt = Dot15d4(fcf_frametype=1, seqnum=100+i) / \
              Dot15d4Data() / \
              ZigbeeNWK(flags=0x00, seqnum=100+i)
        packets.append(pkt)
    
    filename = "test_realistic_zigbee.pcap"
    wrpcap(filename, packets)
    print(f"[✓] Generated {filename} with {len(packets)} packets")
    print(f"    Expected: MEDIUM risk (mixed security)")
    return filename

def main():
    print("="*60)
    print("IoT Vulnerability Scanner - Test Data Generator")
    print("="*60)
    
    try:
        # Generate all test files
        vuln_zigbee = generate_vulnerable_zigbee()
        vuln_ble = generate_vulnerable_ble()
        secure_zigbee = generate_secure_zigbee()
        secure_ble = generate_secure_ble()
        mixed = generate_mixed_scenario()
        
        print("\n" + "="*60)
        print("✓ All test files generated successfully!")
        print("="*60)
        print("\nTest Files Created:")
        print(f"  1. {vuln_zigbee} - Vulnerable Zigbee (HIGH/CRITICAL)")
        print(f"  2. {vuln_ble} - Vulnerable BLE (HIGH/CRITICAL)")
        print(f"  3. {secure_zigbee} - Secure Zigbee (LOW)")
        print(f"  4. {secure_ble} - Secure BLE (LOW)")
        print(f"  5. {mixed} - Realistic Mixed (MEDIUM)")
        
        print("\nQuick Test:")
        print(f"  python scanner.py {vuln_zigbee}")
        print(f"  python scanner.py {vuln_ble}")
        print(f"  python scanner.py *.pcap --json")
        
        print("\nValidation:")
        print("  - Vulnerable files should show HIGH/CRITICAL risks")
        print("  - Secure files should show LOW risks")
        print("  - Mixed file should show MEDIUM risks")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
