#!/usr/bin/env python3
"""
Z-Wave Test PCAP Generator
يولّد ملفات pcap تجريبية لاختبار Z-Wave plugin
"""
import struct, random
from pathlib import Path

OUTPUT_DIR = Path("/tmp/zwave_test_pcaps")
OUTPUT_DIR.mkdir(exist_ok=True)


def write_pcap(path: str, frames: list):
    """كتابة pcap بـ link type 147 (USER0) لـ Z-Wave"""
    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack("<IHHiIII",
            0xa1b2c3d4,  # magic
            2, 4,         # version
            0,            # timezone
            0,            # accuracy
            65535,        # snaplen
            147           # link type USER0 — Z-Wave raw frames
        ))
        for frame in frames:
            data = bytes(frame)
            ts_sec  = 1700000000
            ts_usec = random.randint(0, 999999)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
            f.write(data)


def make_zwave_frame(home_id: bytes, src: int, dst: int,
                     cmd_class: int, cmd: int,
                     payload: bytes = b'',
                     routed: bool = False,
                     repeaters: int = 0) -> bytes:
    """
    بناء Z-Wave frame بسيط:
    HomeID(4) + SrcID(1) + FrameCtrl(1) + Length(1) + DestID(1)
    + CmdClass(1) + Cmd(1) + Payload + Checksum(1)
    """
    frame_ctrl = 0x41  # single-cast data frame
    if routed:
        frame_ctrl |= 0x80
        frame_ctrl |= (repeaters & 0x0F) << 4

    body = (bytes(home_id) +
            bytes([src, frame_ctrl]) +
            bytes([0]) +           # length placeholder
            bytes([dst, cmd_class, cmd]) +
            bytes(payload))

    # Fill length
    length = len(body) + 1  # +1 for checksum
    body = body[:6] + bytes([length]) + body[7:]

    # Simple XOR checksum
    checksum = 0xFF
    for b in body:
        checksum ^= b
    return body + bytes([checksum & 0xFF])


# ── Constants ──────────────────────────────────────────────────────────────────
HOME_ID       = bytes([0xAB, 0xCD, 0x12, 0x34])
WEAK_HOME_ID  = bytes([0xDE, 0xAD, 0xBE, 0xEF])  # known test ID

CMD_CLASS_SECURITY   = 0x98
CMD_CLASS_SECURITY_2 = 0x9F
CMD_CLASS_NO_OP      = 0x00
CMD_CLASS_NETWORK    = 0x34
CMD_CLASS_CRC16      = 0x56

NONCE_GET            = 0x40
SEC_SCHEME_GET       = 0x04
SEC_NETWORK_KEY_SET  = 0x06
S2_NONCE_GET         = 0x01
S2_NONCE_REPORT      = 0x02


# ── Test pcap generators ──────────────────────────────────────────────────────

def gen_no_encryption(path: str):
    """ZWAVE-001: كل الـ frames بدون S0 أو S2"""
    frames = []
    for i in range(40):
        frame = make_zwave_frame(
            home_id=HOME_ID, src=0x01, dst=0x02,
            cmd_class=0x25,  # BINARY_SWITCH — no security
            cmd=0x01,
            payload=bytes([i % 2])
        )
        frames.append(frame)
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_s0_downgrade(path: str):
    """ZWAVE-002: S0 key exchange ثم CRC-16 frames"""
    frames = []
    # S0 scheme get (key exchange start)
    frames.append(make_zwave_frame(HOME_ID, 0x01, 0xFF,
        CMD_CLASS_SECURITY, SEC_SCHEME_GET))
    # بعدها CRC-16 frames بدون تشفير = downgrade
    for i in range(10):
        frames.append(make_zwave_frame(HOME_ID, 0x01, 0x02,
            CMD_CLASS_CRC16, 0x01, payload=bytes([i])))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_battery_exhaustion(path: str):
    """ZWAVE-003: نفيضة من NONCE_GET"""
    frames = []
    for i in range(35):
        frames.append(make_zwave_frame(HOME_ID, 0xEE, 0x01,
            CMD_CLASS_SECURITY, NONCE_GET))
    # بعض الـ frames العادية
    for i in range(10):
        frames.append(make_zwave_frame(HOME_ID, 0x01, 0x02,
            0x25, 0x01))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_s2_dos(path: str):
    """ZWAVE-004: S2 malformed + NO_OPERATION flood"""
    frames = []
    # Malformed S2 (too short)
    for i in range(5):
        frame = make_zwave_frame(HOME_ID, 0xAA, 0x01,
            CMD_CLASS_SECURITY_2, S2_NONCE_GET,
            payload=b'\x01')  # too short
        frames.append(frame[:8])  # truncate intentionally
    # NO_OPERATION flood
    for i in range(25):
        frames.append(make_zwave_frame(HOME_ID, 0xBB, 0x01,
            CMD_CLASS_NO_OP, 0x00))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_malformed_routing(path: str):
    """ZWAVE-005: routing frames مع repeater count خاطئ"""
    frames = []
    for i in range(8):
        frame = make_zwave_frame(HOME_ID, 0x01, 0x05,
            0x25, 0x01,
            routed=True,
            repeaters=7)  # > 4 = invalid
        frames.append(frame)
    # بعض الـ frames العادية
    for i in range(5):
        frames.append(make_zwave_frame(HOME_ID, 0x01, 0x02, 0x25, 0x01))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_find_node_unauth(path: str):
    """ZWAVE-006: network management frames بدون S2"""
    frames = []
    for i in range(6):
        frames.append(make_zwave_frame(HOME_ID, 0x01, 0xFF,
            CMD_CLASS_NETWORK, 0x01,  # unauthenticated
            payload=bytes([i])))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_key_reset(path: str):
    """ZWAVE-007: نفس الجهاز يسوي key exchange أكثر من مرة"""
    frames = []
    # First inclusion
    frames.append(make_zwave_frame(HOME_ID, 0x01, 0x05,
        CMD_CLASS_SECURITY, SEC_SCHEME_GET))
    frames.append(make_zwave_frame(HOME_ID, 0x01, 0x05,
        CMD_CLASS_SECURITY, SEC_NETWORK_KEY_SET,
        payload=bytes(16)))
    # Some normal traffic
    for i in range(5):
        frames.append(make_zwave_frame(HOME_ID, 0x05, 0x01, 0x25, 0x01))
    # Second inclusion = Key Reset Attack!
    frames.append(make_zwave_frame(HOME_ID, 0x01, 0x05,
        CMD_CLASS_SECURITY, SEC_SCHEME_GET))
    frames.append(make_zwave_frame(HOME_ID, 0x01, 0x05,
        CMD_CLASS_SECURITY, SEC_NETWORK_KEY_SET,
        payload=bytes(16)))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_replay(path: str):
    """ZWAVE-008: نفس الـ frame يتكرر"""
    frames = []
    # Normal sequence
    for i in range(10):
        frames.append(make_zwave_frame(HOME_ID, 0x01, 0x02, 0x25, 0x01, bytes([i])))
    # Replay: نفس الـ frame مرتين
    replay_frame = make_zwave_frame(HOME_ID, 0x03, 0x01, 0x25, 0x01, bytes([0xAB]))
    frames.append(replay_frame)
    frames.append(replay_frame)  # duplicate
    frames.append(replay_frame)  # duplicate again
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_home_id_exposure(path: str):
    """ZWAVE-009: weak Home ID في كل frame"""
    frames = []
    for i in range(30):
        frames.append(make_zwave_frame(WEAK_HOME_ID, 0x01, 0x02,
            0x25, 0x01, bytes([i % 2])))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_network_key_clear(path: str):
    """ZWAVE-010: NETWORK_KEY_SET مكشوف"""
    frames = []
    frames.append(make_zwave_frame(HOME_ID, 0x01, 0xFF,
        CMD_CLASS_SECURITY, SEC_SCHEME_GET))
    # Network key set — key transmitted with zero temporary key
    frames.append(make_zwave_frame(HOME_ID, 0xFF, 0x01,
        CMD_CLASS_SECURITY, SEC_NETWORK_KEY_SET,
        payload=bytes(16)))  # 16-byte network key
    write_pcap(path, frames)
    print(f"  ✓ {path}")


def gen_clean(path: str):
    """شبكة نظيفة — S2 فقط، بدون مشاكل"""
    frames = []
    for i in range(20):
        frames.append(make_zwave_frame(HOME_ID, 0x01, 0x02,
            CMD_CLASS_SECURITY_2, S2_MSG_ENCAPSULATION := 0x03,
            payload=bytes([i, i+1, i+2])))
    write_pcap(path, frames)
    print(f"  ✓ {path}")


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Z-Wave Test PCAP Generator")
    print("  " + "─" * 35)

    tests = [
        ("zwave_no_encryption.pcap",  gen_no_encryption),
        ("zwave_s0_downgrade.pcap",   gen_s0_downgrade),
        ("zwave_battery_exhaust.pcap",gen_battery_exhaustion),
        ("zwave_s2_dos.pcap",         gen_s2_dos),
        ("zwave_routing.pcap",        gen_malformed_routing),
        ("zwave_find_node.pcap",      gen_find_node_unauth),
        ("zwave_key_reset.pcap",      gen_key_reset),
        ("zwave_replay.pcap",         gen_replay),
        ("zwave_home_id.pcap",        gen_home_id_exposure),
        ("zwave_key_clear.pcap",      gen_network_key_clear),
        ("zwave_clean.pcap",          gen_clean),
    ]

    for filename, func in tests:
        path = str(OUTPUT_DIR / filename)
        func(path)

    print(f"\n  Generated {len(tests)} pcap files in {OUTPUT_DIR}")
    print("\n  Test with:")
    print(f"    python scanner.py {OUTPUT_DIR}/*.pcap")
    print(f"    python scanner.py {OUTPUT_DIR}/zwave_key_reset.pcap\n")
