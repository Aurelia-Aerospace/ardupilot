#!/usr/bin/env python3
'''
Set a @SECURE parameter on an ArduPilot flight controller via MAVLink SECURE_COMMAND.
The parameter must be marked @SECURE in firmware (e.g. CPS_LOCK).

Usage:
  python3 secure_param.py --port /dev/ttyACM0 --private-key private_key {PARAM_NAME} {VALUE}
  python3 secure_param.py --port udp:127.0.0.1:14550 --private-key private_key {PARAM_NAME} {VALUE}
'''

import sys, struct, random, base64
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
SECURE_COMMAND_SET_PARAM       = 8

parser = ArgumentParser(description='Set a @SECURE ArduPilot parameter')
parser.add_argument("--port",        required=True,  help="MAVLink connection string (e.g. /dev/ttyACM0, udp:127.0.0.1:14550)")
parser.add_argument("--baudrate",    default=115200,  type=int)
parser.add_argument("--private-key", required=True,  help="Private key file (PRIVATE_KEYV1: format)")
parser.add_argument("--timeout",     default=5,       type=float, help="Reply timeout in seconds")
parser.add_argument("param_name",    help="Parameter name (e.g. CPS_LOCK)")
parser.add_argument("param_value",   type=float,      help="Value to set")
args = parser.parse_args()


def load_private_key(path):
    data = open(path, 'r').read().strip()
    prefix = "PRIVATE_KEYV1:"
    if not data.startswith(prefix):
        print(f"Invalid key format, expected {prefix}...")
        sys.exit(1)
    return base64.b64decode(data[len(prefix):])


def sign(private_key, sequence, operation, data, session_key):
    payload = struct.pack("<II", sequence, operation) + data + session_key
    return monocypher.signature_sign(private_key, payload)


def recv_secure_reply(mav, sequence, timeout):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = mav.recv_match(type='SECURE_COMMAND_REPLY', blocking=True, timeout=0.5)
        if msg and msg.sequence == sequence:
            return msg
    return None


def main():
    private_key = load_private_key(args.private_key)
    sequence = random.randint(0, 0xFFFFFFFF)

    print(f"Connecting to {args.port}...")
    mav = mavutil.mavlink_connection(args.port, baud=args.baudrate)
    mav.wait_heartbeat()
    print(f"Heartbeat from system {mav.target_system} component {mav.target_component}")

    # Step 1: get session key
    sig = sign(private_key, sequence, SECURE_COMMAND_GET_SESSION_KEY, b'', b'')
    mav.mav.secure_command_send(
        mav.target_system,
        mav.target_component,
        sequence,
        SECURE_COMMAND_GET_SESSION_KEY,
        0,               # data_length
        len(sig),        # sig_length
        bytearray(sig) + bytearray(220 - len(sig))
    )
    print("Requested session key...")
    reply = recv_secure_reply(mav, sequence, args.timeout)
    if reply is None:
        print("Timed out waiting for session key")
        sys.exit(1)
    if reply.result != 0:  # MAV_RESULT_ACCEPTED
        print(f"Session key request denied (result={reply.result})")
        sys.exit(1)
    session_key = bytes(reply.data[:8])
    print(f"Got session key: {session_key.hex()}")
    sequence = (sequence + 1) % (1 << 32)

    # Step 2: build data = name(16 bytes) + value(4 bytes float LE)
    name_bytes = args.param_name.encode('utf-8')[:16].ljust(16, b'\x00')
    value_bytes = struct.pack('<f', args.param_value)
    data = name_bytes + value_bytes  # 20 bytes

    sig = sign(private_key, sequence, SECURE_COMMAND_SET_PARAM, data, session_key)
    payload = bytearray(data) + bytearray(sig)  # 20 + 64 = 84 bytes
    mav.mav.secure_command_send(
        mav.target_system,
        mav.target_component,
        sequence,
        SECURE_COMMAND_SET_PARAM,
        len(data),       # data_length = 20
        len(sig),        # sig_length = 64
        payload + bytearray(220 - len(payload))
    )
    print(f"Sent SET_PARAM {args.param_name} = {args.param_value}")
    reply = recv_secure_reply(mav, sequence, args.timeout)
    if reply is None:
        print("Timed out waiting for reply")
        sys.exit(1)

    results = {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED", 3: "UNSUPPORTED", 4: "FAILED"}
    print(f"Result: {results.get(reply.result, f'unknown({reply.result})')}")
    sys.exit(reply.result)


if __name__ == '__main__':
    main()
