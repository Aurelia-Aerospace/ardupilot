#!/usr/bin/env python3
'''
Set a @SECURE parameter on an ArduPilot flight controller via MAVLink SECURE_COMMAND.
The parameter must be marked @SECURE in firmware (e.g. CPS_LOCK).

Usage:
  python3 secure_param.py --port /dev/ttyACM0 --private-key private_key {PARAM_NAME} {VALUE}
  python3 secure_param.py --port udp:127.0.0.1:14550 --private-key private_key {PARAM_NAME} {VALUE}
  python3 secure_param.py --port udpout:support.ardupilot.org:PORT2 --passphrase PASS --private-key private_key {PARAM_NAME} {VALUE}
'''

import sys, struct, random, base64, hashlib, time
from argparse import ArgumentParser

try:
    import monocypher as _monocypher
    import ctypes as _ctypes
    _mono_lib = _ctypes.CDLL(_monocypher.__file__)
except ImportError:
    print("Install monocypher: python3 -m pip install pymonocypher")
    sys.exit(1)
_Buf32 = _ctypes.c_char * 32
_Buf64 = _ctypes.c_char * 64
try:
    _mono_lib.crypto_eddsa_key_pair
    _mono_lib.crypto_eddsa_sign
    _SIGN_API = 'eddsa'
except AttributeError:
    _SIGN_API = 'sign'

import os
os.environ['MAVLINK20'] = '1'  # before pymavlink import: SECURE_COMMAND and signing are MAVLink2-only
try:
    from pymavlink import mavutil
except ImportError:
    print("Install pymavlink: python3 -m pip install pymavlink")
    sys.exit(1)

SECURE_COMMAND_GET_SESSION_KEY = 0
SECURE_COMMAND_SET_PARAM       = 8

parser = ArgumentParser(description='Set a @SECURE ArduPilot parameter')
parser.add_argument("--port",        required=True,  help="MAVLink connection string (e.g. /dev/ttyACM0, udp:127.0.0.1:14550)")
parser.add_argument("--passphrase", help="MAVLink2 signing passphrase (required by support.ardupilot.org engineer port)")
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
    payload = struct.pack("<II", sequence, operation) + bytes(data) + bytes(session_key)
    sig = _Buf64()
    msg_buf = (_ctypes.c_char * len(payload))(*payload)
    if _SIGN_API == 'eddsa':
        sk = _Buf64()
        _mono_lib.crypto_eddsa_key_pair(sk, _Buf32(), _Buf32(*private_key))
        _mono_lib.crypto_eddsa_sign(sig, sk, msg_buf, _ctypes.c_size_t(len(payload)))
    else:
        pk = _Buf32()
        _mono_lib.crypto_sign_public_key(pk, _Buf32(*private_key))
        _mono_lib.crypto_sign(sig, _Buf32(*private_key), pk, msg_buf, _ctypes.c_size_t(len(payload)))
    return bytes(sig)


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
    if args.passphrase:
        # support.ardupilot.org (UDPProxy) discards unsigned packets from the engineer side; key = sha256(passphrase)
        mav.setup_signing(hashlib.sha256(args.passphrase.encode('utf-8')).digest())
    # send first so udpout peers (e.g. support.ardupilot.org) learn our address and start forwarding
    deadline = time.time() + args.timeout
    while not mav.wait_heartbeat(timeout=1):
        if time.time() > deadline:
            print("No heartbeat (wrong/missing --passphrase?)"); sys.exit(1)
        mav.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
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
