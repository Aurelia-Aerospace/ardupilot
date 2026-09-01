#!/usr/bin/env python3
"""
generate_rid_key.py
Trigger the ArduRemoteID module to generate its own Ed25519 keypair internally,
then retrieve and save the public key from the flight controller.

Flow:
  1. Get session key from FC (op=0)
  2. Send SECURE_COMMAND_GENERATE_RID_KEY (op=9) signed with AureliaKeys
     FC forwards this to the RID module over DroneCAN
  3. Poll SECURE_COMMAND_GET_RID_PUBLIC_KEY (op=10) until the FC has it
  4. Print and optionally save the public key

Usage:
  python3 generate_rid_key.py --signing-key private_key --port /dev/ttyACM0
  python3 generate_rid_key.py --signing-key private_key --port /dev/ttyACM0 --out rid_pubkey.dat
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

SECURE_COMMAND_GET_SESSION_KEY    = 0
SECURE_COMMAND_GENERATE_RID_KEY   = 9
SECURE_COMMAND_GET_RID_PUBLIC_KEY = 10

parser = ArgumentParser(description='Generate RID Ed25519 keypair on the RemoteID module')
parser.add_argument("--signing-key", required=True,
                    help="Firmware signing private key (PRIVATE_KEYV1: format)")
parser.add_argument("--port", required=True,
                    help="MAVLink connection (e.g. /dev/ttyACM0, udp:127.0.0.1:14550)")
parser.add_argument("--baudrate", default=115200, type=int)
parser.add_argument("--timeout", default=10, type=float,
                    help="Timeout per command in seconds (default: 10)")
parser.add_argument("--out", help="Save public key to file (PUBLIC_KEYV1: format)")
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
    payload = struct.pack("<II", sequence, operation) + data + session_key
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


def recv_reply(mav, sequence, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = mav.recv_match(type='SECURE_COMMAND_REPLY', blocking=True, timeout=0.5)
        if msg and msg.sequence == sequence:
            return msg
    return None


RESULTS = {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED", 3: "UNSUPPORTED", 4: "FAILED"}


def main():
    signing_key = load_private_key(args.signing_key)
    sequence = random.randint(0, 0xFFFFFFFF)

    print(f"Connecting to {args.port}...")
    mav = mavutil.mavlink_connection(args.port, baud=args.baudrate)
    mav.wait_heartbeat()
    print(f"Heartbeat from system {mav.target_system} component {mav.target_component}")

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

    # Step 2: trigger keypair generation on the RID module
    send_secure(mav, signing_key, sequence, SECURE_COMMAND_GENERATE_RID_KEY, b'', session_key)
    print("Sending GENERATE_RID_KEY...")
    reply = recv_reply(mav, sequence, args.timeout)
    if reply is None:
        print("Timed out waiting for GENERATE_RID_KEY reply"); sys.exit(1)
    print(f"GENERATE_RID_KEY: {RESULTS.get(reply.result, f'unknown({reply.result})')}")
    if reply.result != 0:
        sys.exit(reply.result)
    sequence = (sequence + 1) % (1 << 32)

    # Step 3: poll FC until it has the public key (RID module responds async over DroneCAN)
    # Wait for DroneCAN round-trip to complete before first poll
    time.sleep(2)
    print("Polling for public key...")
    pubkey = None
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        send_secure(mav, signing_key, sequence, SECURE_COMMAND_GET_RID_PUBLIC_KEY, b'', session_key)
        reply = recv_reply(mav, sequence, 2.0)
        sequence = (sequence + 1) % (1 << 32)
        if reply and reply.result == 0 and reply.data_length >= 32:
            candidate = bytes(reply.data[:32])
            if any(b != 0xFF for b in candidate):
                pubkey = candidate
                break
        time.sleep(1)

    if pubkey is None:
        print("Timed out waiting for public key from RID module")
        sys.exit(1)

    print(f"Public key ({len(pubkey)} bytes): {pubkey.hex()}")

    if args.out:
        with open(args.out, 'w') as f:
            f.write(f"PUBLIC_KEYV1:{base64.b64encode(pubkey).decode()}\n")
        print(f"Saved: {args.out}")


if __name__ == '__main__':
    main()
