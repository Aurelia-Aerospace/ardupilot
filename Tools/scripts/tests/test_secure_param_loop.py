#!/usr/bin/env python3
"""
test_secure_param_loop.py
Run secure_param.py N times and report stats.

Usage:
  python3 test_secure_param_loop.py [--runs 100] [--port ...] [--private-key ...] PARAM_NAME VALUE
  Any extra args after --runs are forwarded to secure_param.py.
"""

import sys
import time
import subprocess
import statistics
from argparse import ArgumentParser
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "secure_param.py"

parser = ArgumentParser(description="Secure param loop tester")
parser.add_argument("--runs", type=int, default=100, help="Number of attempts (default: 100)")
args, forward = parser.parse_known_args()

results = []
times = []

for i in range(1, args.runs + 1):
    cmd = [sys.executable, str(SCRIPT)] + forward
    print(f"\n{'='*60}\nRun {i}/{args.runs}\n{'='*60}", flush=True)

    lines = []
    t0 = time.monotonic()
    # ponytail: stream line-by-line so output appears in real time
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
        for line in proc.stdout:
            line = line.replace('\r', '\n').rstrip('\n') + '\n'
            print(line, end="", flush=True)
            lines.append(line)
        proc.wait()
        elapsed = time.monotonic() - t0
        success = proc.returncode == 0

    results.append(success)
    times.append(elapsed)

    status = "OK" if success else "FAIL"
    print(f"[{status}] run {i}: {elapsed:.1f}s", flush=True)

    if i < args.runs:
        print("Waiting 10s before next run...", flush=True)
        time.sleep(10)

ok   = sum(results)
fail = len(results) - ok

print(f"""
{'='*60}
RESULTS  ({args.runs} runs)
  Success : {ok}
  Failure : {fail}
  Rate    : {ok/len(results)*100:.1f}%
  Time (s)
    mean  : {statistics.mean(times):.1f}
    min   : {min(times):.1f}
    max   : {max(times):.1f}
{'='*60}""")
