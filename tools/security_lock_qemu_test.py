#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

"""Integration test for the security lock, driven against QEMU.

Stands in for Gadgetbridge: speaks the QEMU comm channel directly, so the
firmware sees real Pebble Protocol frames on the security endpoint rather than
a mocked-out call. Assumes the phone side sends well-formed messages -- what is
under test here is the watch.

Usage:
    ./pbl qemu &                              # in another shell
    python3 tools/security_lock_qemu_test.py
"""

import argparse
import socket
import struct
import subprocess
import sys
import time

QEMU_HEADER_SIGNATURE = 0xFEED
QEMU_FOOTER_SIGNATURE = 0xBEEF
QEMU_PROTOCOL_SPP = 1
QEMU_PROTOCOL_BLUETOOTH_CONNECTION = 3

SECURITY_ENDPOINT = 11300

CMD_CONFIGURE = 0x01
CMD_LOCK = 0x02
CMD_STATUS_REQUEST = 0x03
CMD_LOCK_ACK = 0x82
CMD_STATUS_RESPONSE = 0x83
CMD_SHRED_COMPLETE = 0x84
CMD_STATE_CHANGED = 0x85

REASON_PHONE_LOCKDOWN = 0x01

STATE_NAMES = {0: "disabled", 1: "armed", 2: "locked"}

CMD_NAMES = {
    CMD_LOCK_ACK: "LOCK_ACK",
    CMD_STATUS_RESPONSE: "STATUS_RESPONSE",
    CMD_SHRED_COMPLETE: "SHRED_COMPLETE",
    CMD_STATE_CHANGED: "STATE_CHANGED",
}


class Watch:
    """The QEMU comm channel, from the phone's point of view."""

    def __init__(self, host="localhost", port=12344, timeout=30.0):
        self.sock = socket.create_connection((host, port), timeout=5.0)
        self.sock.settimeout(timeout)
        self.buf = b""

    def close(self):
        self.sock.close()

    def _send_qemu(self, protocol, data):
        header = struct.pack(">HHH", QEMU_HEADER_SIGNATURE, protocol, len(data))
        footer = struct.pack(">H", QEMU_FOOTER_SIGNATURE)
        self.sock.sendall(header + data + footer)

    def set_connected(self, connected):
        """Simulate the phone connecting or dropping."""
        self._send_qemu(QEMU_PROTOCOL_BLUETOOTH_CONNECTION,
                        struct.pack(">B", 1 if connected else 0))

    def send_endpoint(self, endpoint, payload):
        """Send one Pebble Protocol frame."""
        frame = struct.pack(">HH", len(payload), endpoint) + payload
        self._send_qemu(QEMU_PROTOCOL_SPP, frame)

    def _read_qemu_packet(self, deadline):
        """Pull one framed QEMU packet, resyncing on the header signature."""
        while True:
            # Resync: the firmware also emits log traffic on this channel.
            idx = self.buf.find(struct.pack(">H", QEMU_HEADER_SIGNATURE))
            if idx >= 0 and len(self.buf) >= idx + 6:
                _, protocol, length = struct.unpack(">HHH", self.buf[idx:idx + 6])
                total = idx + 6 + length + 2
                if len(self.buf) >= total:
                    data = self.buf[idx + 6:idx + 6 + length]
                    self.buf = self.buf[total:]
                    return protocol, data

            if time.time() > deadline:
                return None, None
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None, None
            if not chunk:
                return None, None
            self.buf += chunk

    def expect(self, command, timeout=30.0):
        """Wait for one security-endpoint message with the given command."""
        deadline = time.time() + timeout
        while True:
            protocol, data = self._read_qemu_packet(deadline)
            if protocol is None:
                return None
            if protocol != QEMU_PROTOCOL_SPP or len(data) < 5:
                continue
            length, endpoint = struct.unpack(">HH", data[:4])
            if endpoint != SECURITY_ENDPOINT:
                continue
            payload = data[4:4 + length]
            if not payload:
                continue
            name = CMD_NAMES.get(payload[0], hex(payload[0]))
            print(f"    <- {name} {payload.hex()}")
            if payload[0] == command:
                return payload

    # Messages Gadgetbridge would send.

    def configure(self, enabled=True, timeout_s=1800, lock_on_disconnect=False):
        self.send_endpoint(SECURITY_ENDPOINT, struct.pack(
            ">BBHB", CMD_CONFIGURE, 1 if enabled else 0, timeout_s,
            1 if lock_on_disconnect else 0))

    def lock(self, reason=REASON_PHONE_LOCKDOWN):
        self.send_endpoint(SECURITY_ENDPOINT, struct.pack(">BB", CMD_LOCK, reason))

    def status_request(self):
        self.send_endpoint(SECURITY_ENDPOINT, struct.pack(">B", CMD_STATUS_REQUEST))


def monitor(command, sock_path="build/qemu-mon.sock"):
    """Send a command to the QEMU socket monitor."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.settimeout(2.0)
        time.sleep(0.2)
        s.sendall((command + "\n").encode())
        time.sleep(0.3)
        try:
            return s.recv(65536).decode(errors="replace")
        except socket.timeout:
            return ""


def press(button):
    """Press a watch button. left=back right=select up=up down=down."""
    monitor(f"sendkey {button}")
    time.sleep(0.4)


def screenshot(path):
    subprocess.run([sys.executable, "./pbl", "screenshot",
                    "--screenshot-output", path], check=True,
                   capture_output=True)
    print(f"    screenshot -> {path}")


PASSED = []
FAILED = []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", default="/tmp/seclock", help="screenshot prefix")
    args = ap.parse_args()

    print("Connecting to QEMU...")
    watch = Watch()
    watch.set_connected(True)
    time.sleep(2.0)

    print("\n1. STATUS_REQUEST before anything is configured")
    watch.status_request()
    status = watch.expect(CMD_STATUS_RESPONSE, timeout=15)
    if check("status responds", status is not None):
        _, state, pin_configured, remaining = struct.unpack(">BBBI", status[:7])
        print(f"      state={STATE_NAMES.get(state, state)} "
              f"pin_configured={pin_configured} deadline_remaining={remaining}s")
        check("starts disabled with no PIN", state == 0 and pin_configured == 0)

    print("\n2. CONFIGURE from the phone")
    watch.configure(enabled=True, timeout_s=1800, lock_on_disconnect=False)
    time.sleep(1.0)
    watch.status_request()
    check("survives CONFIGURE", watch.expect(CMD_STATUS_RESPONSE, timeout=15) is not None)

    print("\n3. LOCK with no PIN set: must shred but not lock")
    screenshot(f"{args.shots}-before-lock.png")
    watch.lock()
    shred = watch.expect(CMD_SHRED_COMPLETE, timeout=90)
    if check("shred runs and is reported", shred is not None):
        _, reason, wiped = struct.unpack(">BBI", shred[:6])
        print(f"      reason={reason} wiped_bitmap=0x{wiped:08x}")
        check("wiped bitmap is non-empty", wiped != 0, f"0x{wiped:08x}")
        # Bit 4 = BlobDBIdNotifs, bit 1 = Pins.
        check("notifications wiped", bool(wiped & (1 << 4)))
        check("calendar pins wiped", bool(wiped & (1 << 1)))

    time.sleep(2.0)
    watch.status_request()
    status = watch.expect(CMD_STATUS_RESPONSE, timeout=15)
    if status:
        _, state, pin_configured, _ = struct.unpack(">BBBI", status[:7])
        check("did not lock without a PIN", state != 2,
              f"state={STATE_NAMES.get(state, state)}")
    screenshot(f"{args.shots}-after-lock.png")

    print("\n4. Buttons still work when unlocked")
    press("right")
    screenshot(f"{args.shots}-menu.png")
    press("left")

    watch.close()

    print(f"\n{'=' * 60}")
    print(f"passed {len(PASSED)}  failed {len(FAILED)}")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
