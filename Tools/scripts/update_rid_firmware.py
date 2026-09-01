#!/usr/bin/env python3
"""
update_rid_firmware.py
OTA firmware update for the ArduRemoteID module via MAVLink SECURE_COMMAND.

Flow:
  1. Get session key from FC (op=0)
  2. Send OTA_BEGIN (op=11) signed with firmware signing key
  3. Split firmware into CHUNK_SIZE chunks
  4. For each chunk send OTA_CHUNK (op=12) — no signature required
     Retry on TEMPORARILY_REJECTED (FC waiting for DroneCAN ACK)
  5. FC waits for ESP32 validation result and forwards it as SECURE_COMMAND_REPLY

Usage:
  python3 update_rid_firmware.py --signing-key private_key \
      --firmware rid_firmware.bin --port /dev/ttyACM0
"""

import sys
import struct
import random
import base64
import time
from argparse import ArgumentParser

try:
    import monocypher
except ImportError:
    print("Install monocypher: python3 -m pip install pymonocypher")
    sys.exit(1)

try:
    from pymavlink import mavutil
except ImportError:
    print("Install pymavlink: python3 -m pip install pymavlink")
    sys.exit(1)

SECURE_COMMAND_GET_SESSION_KEY = 0
SECURE_COMMAND_OTA_BEGIN       = 11
SECURE_COMMAND_OTA_CHUNK       = 12

CHUNK_SIZE = 215  # max firmware bytes per DroneCAN transfer (DroneCAN data[<=220] minus 5-byte header)

FLAG_FIRST = 0x01
FLAG_LAST  = 0x02

RESULTS = {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED", 3: "UNSUPPORTED", 4: "FAILED"}

parser = ArgumentParser(description='OTA firmware update for ArduRemoteID module')
parser.add_argument("--signing-key", required=True,
                    help="Firmware signing private key (PRIVATE_KEYV1: format)")
parser.add_argument("--firmware", required=True,
                    help="Firmware binary (.bin)")
parser.add_argument("--port", required=True,
                    help="MAVLink connection (e.g. /dev/ttyACM0, udp:127.0.0.1:14550)")
parser.add_argument("--baudrate", default=115200, type=int)
parser.add_argument("--timeout", default=15, type=float,
                    help="Timeout per command in seconds (default: 15)")
parser.add_argument("--first-chunk-timeout", default=60.0, type=float,
                    help="Timeout for first chunk in seconds — longer to allow ESP32 OTA partition pre-erase (default: 60)")
parser.add_argument("--retry-delay", default=0.0, type=float,
                    help="Delay between retries on TEMPORARILY_REJECTED (default: 0.0s — proactive ACK eliminates most retries)")
parser.add_argument("--chunk-reply-timeout", default=5.0, type=float,
                    help="Timeout waiting for reply per chunk attempt (default: 5.0s)")
parser.add_argument("--max-size", default=2*1024*1024, type=int,
                    help="Maximum firmware size in bytes — must fit in one OTA partition (default: 2097152 = 2MB)")
args = parser.parse_args()


def load_private_key(path):
    data = open(path).read().strip()
    prefix = 'PRIVATE_KEYV1:'
    if not data.startswith(prefix):
        print(f"ERROR: {path!r} must start with {prefix!r}")
        sys.exit(1)
    key = base64.b64decode(data[len(prefix):])
    if len(key) != 32:
        print(f"ERROR: expected 32-byte key, got {len(key)}")
        sys.exit(1)
    return key


def sign(private_key, sequence, operation, data, session_key):
    payload = struct.pack("<II", sequence, operation) + bytes(data) + bytes(session_key)
    return monocypher.signature_sign(private_key, payload)


def send_secure(mav, signing_key, sequence, operation, data, session_key):
    sig = sign(signing_key, sequence, operation, data, session_key)
    payload = bytearray(data) + bytearray(sig)
    mav.mav.secure_command_send(
        mav.target_system, mav.target_component,
        sequence, operation,
        len(data), len(sig),
        payload + bytearray(220 - len(payload))
    )


def send_chunk(mav, sequence, data):
    """Send an OTA_CHUNK with no signature."""
    mav.mav.secure_command_send(
        mav.target_system, mav.target_component,
        sequence, SECURE_COMMAND_OTA_CHUNK,
        len(data), 0,
        bytearray(data) + bytearray(220 - len(data))
    )


def recv_reply(mav, sequence, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = mav.recv_match(type='SECURE_COMMAND_REPLY', blocking=True, timeout=0.5)
        if msg and msg.sequence == sequence:  
            return msg
    return None


def send_with_retry(mav, sequence, data_bytes, timeout, retry_delay, label, reply_timeout=5.0):
    """Send a chunk and retry on TEMPORARILY_REJECTED."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        send_chunk(mav, sequence, data_bytes)
        reply = recv_reply(mav, sequence, timeout=reply_timeout)
        if reply is None:
            print(f"  {label}: timeout waiting for reply, retrying...")
            time.sleep(0.2)
            continue
        if reply.result == 0:  # ACCEPTED
            return True
        if reply.result == 1:  # TEMPORARILY_REJECTED
            time.sleep(retry_delay)
            continue
        print(f"  {label}: {RESULTS.get(reply.result, f'unknown({reply.result})')}")
        return False
    print(f"  {label}: overall timeout exceeded")
    return False


def main():
    signing_key = load_private_key(args.signing_key)

    firmware = open(args.firmware, 'rb').read()
    fw_size = len(firmware)
    print(f"Firmware: {args.firmware} ({fw_size} bytes)")

    if fw_size > args.max_size:
        print(f"ERROR: firmware ({fw_size} bytes) exceeds OTA partition size ({args.max_size} bytes)")
        sys.exit(1)

    chunks = [firmware[i:i+CHUNK_SIZE] for i in range(0, fw_size, CHUNK_SIZE)]
    n_chunks = len(chunks)
    print(f"Chunks: {n_chunks} x {CHUNK_SIZE} bytes")

    sequence = random.randint(0, 0xFFFFFFFF)

    print(f"Connecting to {args.port}...")
    mav = mavutil.mavlink_connection(args.port, baud=args.baudrate)
    mav.wait_heartbeat()
    print(f"Connected: system {mav.target_system} component {mav.target_component}")

    # Step 1: get session key
    send_secure(mav, signing_key, sequence, SECURE_COMMAND_GET_SESSION_KEY, b'', b'')
    print("Requesting session key...")
    reply = recv_reply(mav, sequence, args.timeout)
    if reply is None:
        print("Timed out waiting for session key"); sys.exit(1)
    if reply.result != 0:
        print(f"Session key denied: {RESULTS.get(reply.result)}"); sys.exit(1)
    session_key = bytes(reply.data[:8])
    print(f"Session key: {session_key.hex()}")
    sequence = (sequence + 1) % (1 << 32)

    # Step 2: OTA_BEGIN with firmware size (4 bytes LE)
    fw_size_bytes = struct.pack("<I", fw_size)
    send_secure(mav, signing_key, sequence, SECURE_COMMAND_OTA_BEGIN, fw_size_bytes, session_key)
    print("Sending OTA_BEGIN...")
    reply = recv_reply(mav, sequence, args.timeout)
    if reply is None:
        print("Timed out waiting for OTA_BEGIN reply"); sys.exit(1)
    if reply.result != 0:
        print(f"OTA_BEGIN rejected: {RESULTS.get(reply.result, f'unknown({reply.result})')}"); sys.exit(1)
    print("OTA session started")
    sequence = (sequence + 1) % (1 << 32)

    # Step 3: send firmware chunks
    start_time = time.time()
    for i, chunk in enumerate(chunks):
        flags = 0
        if i == 0:
            flags |= FLAG_FIRST
        if i == n_chunks - 1:
            flags |= FLAG_LAST
        offset = i * CHUNK_SIZE

        chunk_data = bytearray([flags]) + struct.pack("<I", offset) + bytearray(chunk)
        label = f"chunk {i+1}/{n_chunks} offset={offset}"

        chunk_timeout = args.first_chunk_timeout if i == 0 else args.timeout
        reply_timeout = args.timeout if (flags & FLAG_LAST) else args.chunk_reply_timeout
        ok = send_with_retry(mav, sequence, chunk_data, chunk_timeout, args.retry_delay, label, reply_timeout)
        if not ok:
            print(f"OTA failed at {label}"); sys.exit(1)

        sequence = (sequence + 1) % (1 << 32)

        # progress
        pct = (i + 1) * 100 // n_chunks
        elapsed = time.time() - start_time
        rate = (offset + len(chunk)) / elapsed if elapsed > 0 else 0
        print(f"\r  {pct}% ({i+1}/{n_chunks}) {rate/1024:.1f} KB/s  ", end='', flush=True)

    elapsed = time.time() - start_time
    print(f"\nFirmware validated — module rebooting ({elapsed:.1f}s)")


if __name__ == '__main__':
    main()
