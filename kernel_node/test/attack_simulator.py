import os
import sys
import time
import socket
import struct
import subprocess
import fcntl
from enum import IntEnum

if not hasattr(socket, "SOL_NETLINK"):
    socket.SOL_NETLINK = 270
if not hasattr(socket, "NETLINK_ADD_MEMBERSHIP"):
    socket.NETLINK_ADD_MEMBERSHIP = 1

NETLINK_ATTEST = 31
NETLINK_GROUP = 1

MSG_TYPE_HASH_REQUEST = 1
MSG_TYPE_HASH_RESPONSE = 2
MSG_TYPE_ALERT = 5

DUMMY_KEY_DIR = "/root/signing"
SIGN_FILE = f"/usr/src/linux-headers-{os.uname().release}/scripts/sign-file"


class AttestMonitor:

    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK,
                                  socket.SOCK_RAW,
                                  NETLINK_ATTEST)

        self.sock.bind((os.getpid(), NETLINK_GROUP))
        self.sock.setsockopt(socket.SOL_NETLINK,
                             socket.NETLINK_ADD_MEMBERSHIP,
                             struct.pack("I", NETLINK_GROUP))

        flags = fcntl.fcntl(self.sock, fcntl.F_GETFL)
        fcntl.fcntl(self.sock, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self.sock.settimeout(0.2)

        print(f"[+] Monitor ready (PID={os.getpid()}, group={NETLINK_GROUP})")

    def _recv_msg(self):
        try:
            data = self.sock.recv(4096)
        except (socket.timeout, BlockingIOError):
            return None, None
        if len(data) < 24:
            return None, None
        payload = data[16:]
        mtype, dlen = struct.unpack("II", payload[:8])
        txt = payload[8:8+dlen].decode("utf-8", errors="ignore").rstrip("\0")
        return mtype, txt

    def flush_buffer(self):
        flushed = 0
        while True:
            mtype, txt = self._recv_msg()
            if mtype is None:
                break
            flushed += 1
        if flushed > 0:
            print(f"[i] Flushed {flushed} buffered message(s)")

    def _send_hash_req(self):
        payload = struct.pack("II512s",
                              MSG_TYPE_HASH_REQUEST,
                              len(b"REQUEST_HASH"),
                              b"REQUEST_HASH")
        nlhdr = struct.pack("IHHII",
                            16 + len(payload), 0, 0, 1, os.getpid())
        self.sock.send(nlhdr + payload)

    def get_kernel_hash(self):
        self._send_hash_req()
        deadline = time.time() + 2
        while time.time() < deadline:
            mtype, txt = self._recv_msg()
            if mtype == MSG_TYPE_HASH_RESPONSE:
                return txt
        return None

    def wait_for_alert(self, max_sec=3, verbose=True):
        deadline = time.time() + max_sec
        alerts = []
        if verbose:
            print(f"[i] Waiting for alerts ({max_sec}s)...")

        while time.time() < deadline:
            mtype, txt = self._recv_msg()
            if mtype == MSG_TYPE_ALERT:
                if verbose:
                    print(f"    [!] ALERT: {txt}")
                alerts.append(txt)

        if verbose:
            print(f"    [i] Collected {len(alerts)} alert(s)")

        return alerts[0] if alerts else None

    def wait_for_alerts_multiple(self, max_sec=3, verbose=True):
        deadline = time.time() + max_sec
        alerts = []
        if verbose:
            print(f"[i] Waiting for alerts ({max_sec}s)...")

        while time.time() < deadline:
            mtype, txt = self._recv_msg()
            if mtype == MSG_TYPE_ALERT:
                if verbose:
                    print(f"    [!] ALERT: {txt}")
                alerts.append(txt)

        if verbose:
            print(f"    [i] Collected {len(alerts)} alert(s)")

        return alerts

    def listen_for_alerts(self, duration=5):
        end = time.time() + duration
        alerts = []
        print(f"[*] Listening for alerts ({duration}s)...")
        while time.time() < end:
            mtype, txt = self._recv_msg()
            if mtype == MSG_TYPE_ALERT:
                print(f"[!] ALERT: {txt}")
                alerts.append(txt)
        return alerts

    def close(self):
        self.sock.close()


def sign_module(path):
    key = os.path.join(DUMMY_KEY_DIR, "MOK.priv")
    crt = os.path.join(DUMMY_KEY_DIR, "MOK.pem")

    if not all(os.path.exists(p) for p in (key, crt)):
        print(f"[!] Signing keys not found in {DUMMY_KEY_DIR}")
        print(f"    Looking for: {key} and {crt}")
        return False

    if not os.path.exists(SIGN_FILE):
        print(f"[!] sign-file script not found at {SIGN_FILE}")
        return False

    try:
        subprocess.run([SIGN_FILE, "sha256", key, crt, path],
                      check=True, capture_output=True)
        print("[+] Module signed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Signing failed: {e.stderr.decode()}")
        return False


def check_secure_boot():
    try:
        with open("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", "rb") as f:
            data = f.read()
            return len(data) >= 5 and data[4] == 1
    except:
        return False


class AttackSimulator:

    @staticmethod
    def test_hash_consistency(mon: AttestMonitor):
        print("\n" + "="*60)
        print("TEST 1: Hash Integrity Verification")
        print("="*60)

        mon.flush_buffer()

        h1 = mon.get_kernel_hash()
        if not h1:
            print("[!] could not obtain baseline hash")
            return False, []
        print(f"[i] Hash 1: {h1[:64]}...")

        time.sleep(2)

        h2 = mon.get_kernel_hash()
        if not h2:
            print("[!] could not obtain second hash")
            return False, []
        print(f"[i] Hash 2: {h2[:64]}...")

        ok = h2 == h1
        print("[+] hashes match" if ok else "[!] HASH MISMATCH")
        return ok, []

    @staticmethod
    def test_module_load(mon: AttestMonitor):
        print("\n" + "="*60)
        print("TEST 2: Module Load Detection")
        print("="*60)

        ko = "/home/devadvancer/temp/attest_test/dummy_test.ko"

        if not os.path.exists(ko):
            print(f"[!] Module not found at {ko}")
            return False, []

        mon.flush_buffer()

        print(f"[>] Loading module from {ko}")

        modinfo_result = subprocess.run(["modinfo", ko],
                                       capture_output=True, text=True)
        if "sig_id" in modinfo_result.stdout:
            print("[+] Module is signed")
        else:
            print("[!] Module is NOT signed")
            if check_secure_boot():
                print("[!] Secure Boot is enabled - signing required")
                sign_module(ko)

        print(f"[>] insmod {ko}")
        result = subprocess.run(["insmod", ko], capture_output=True, text=True)

        if result.returncode != 0:
            stderr = result.stderr
            print(f"[!] insmod failed: {stderr}")
            return False, []

        print("[+] Module loaded successfully")

        time.sleep(0.5)
        alerts = mon.wait_for_alerts_multiple(max_sec=5, verbose=True)

        alerted = len(alerts) > 0
        print("    > alert received ✓" if alerted else "    > NO alert ✗")

        if alerts:
            for i, alert in enumerate(alerts):
                print(f"    Alert {i+1}: {alert}")

        print("[>] Unloading module...")
        subprocess.run(["rmmod", "dummy_test"], capture_output=True)

        time.sleep(1)

        return alerted, alerts

    @staticmethod
    def test_module_unload(mon: AttestMonitor):
        print("\n" + "="*60)
        print("TEST 3: Module Unload Detection")
        print("="*60)

        mon.flush_buffer()

        ko = "/home/devadvancer/temp/attest_test/dummy_test.ko"

        print("[>] Loading dummy module first...")
        result = subprocess.run(["insmod", ko], capture_output=True)
        if result.returncode != 0:
            print("[!] Could not load module for unload test")
            return False, []

        time.sleep(1)
        mon.flush_buffer()

        print("[>] Now unloading module...")
        subprocess.run(["rmmod", "dummy_test"], capture_output=True)

        time.sleep(0.5)
        alerts = mon.wait_for_alerts_multiple(max_sec=5, verbose=True)
        alerted = len(alerts) > 0

        print("    > alert received ✓" if alerted else "    > NO alert ✗")

        if alerts:
            for i, alert in enumerate(alerts):
                print(f"    Alert {i+1}: {alert}")

        return alerted, alerts

    @staticmethod
    def test_rapid_ops(mon: AttestMonitor):
        print("\n" + "="*60)
        print("TEST 4: Rapid Module Load / Unload")
        print("="*60)

        mon.flush_buffer()

        ko = "/home/devadvancer/temp/attest_test/dummy_test.ko"
        if not os.path.exists(ko):
            print("[!] dummy_test.ko missing")
            return False, []

        print("[>] Performing 3 rapid load/unload cycles...")
        for i in range(3):
            print(f"    Cycle {i+1}/3...")
            result = subprocess.run(["insmod", ko], capture_output=True)
            if result.returncode != 0:
                print(f"[!] insmod failed on cycle {i+1}")
                break
            time.sleep(0.3)
            subprocess.run(["rmmod", "dummy_test"], capture_output=True)
            time.sleep(0.3)

        time.sleep(0.5)
        alerts = mon.wait_for_alerts_multiple(max_sec=6, verbose=True)
        alerted = len(alerts) > 0

        print("    > alert received ✓" if alerted else "    > NO alert ✗")
        print(f"    > Total alerts: {len(alerts)}")

        return alerted, alerts


def run_attack_suite():
    print(r"""
╔═══════════════════════════════════════════════════════════╗
║  Kernel Attestation Module – Attack-Simulation Suite      ║
╚═══════════════════════════════════════════════════════════╝
""")
    if os.geteuid() != 0:
        sys.exit("[!] Run as root (sudo)")

    if "attest_lkm" not in subprocess.check_output(["lsmod"], text=True):
        sys.exit("[!] attest_lkm not loaded")

    print("[+] attest_lkm loaded\n")

    mon = AttestMonitor()
    results = {}
    all_alerts = []

    try:
        passed, alerts = AttackSimulator.test_hash_consistency(mon)
        results["hash_consistency"] = passed
        all_alerts.extend(alerts)
        time.sleep(2)

        passed, alerts = AttackSimulator.test_module_load(mon)
        results["module_load"] = passed
        all_alerts.extend(alerts)
        time.sleep(2)

        passed, alerts = AttackSimulator.test_module_unload(mon)
        results["module_unload"] = passed
        all_alerts.extend(alerts)
        time.sleep(2)

        passed, alerts = AttackSimulator.test_rapid_ops(mon)
        results["rapid_ops"] = passed
        all_alerts.extend(alerts)
        time.sleep(1)

        print("\n[>] Final 5-second alert sweep...")
        final_alerts = mon.listen_for_alerts(5)
        all_alerts.extend(final_alerts)

    finally:
        mon.close()

    print("\n" + "="*60)
    print("ATTACK-SIMULATION SUMMARY")
    print("="*60)
    for k, v in results.items():
        print(f"{'✓ PASS' if v else '✗ FAIL'} - {k}")

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n[*] Tests Passed: {passed}/{total}")
    print(f"[*] Total alerts seen: {len(all_alerts)}")
    print("============================================================")
    print("View kernel log with:  sudo dmesg | grep ATTEST")
    print("============================================================")


if __name__ == "__main__":
    try:
        run_attack_suite()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
    except Exception as exc:
        import traceback
        traceback.print_exc()
        sys.exit(f"[!] Fatal: {exc}")
