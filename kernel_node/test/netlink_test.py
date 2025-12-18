import socket
import struct
import os
import sys
import subprocess

NETLINK_ATTEST = 31

def check_root():
    if os.geteuid() != 0:
        print("[!] Not running as root")
        print("    Run with: sudo python3 netlink_diagnostic.py")
        return False
    print("[+] Running as root")
    return True

def check_module_loaded():
    result = subprocess.run(
        ["lsmod"],
        capture_output=True,
        text=True
    )

    if "attest_lkm" in result.stdout:
        print("[+] attest_lkm module is loaded")
        return True
    else:
        print("[!] attest_lkm module NOT loaded")
        print("    Load it with: sudo insmod attest_lkm.ko")
        return False

def check_dmesg():
    print("\n[*] Recent kernel logs from attest_lkm:")
    print("-" * 60)

    result = subprocess.run(
        ["dmesg", "-T"],
        capture_output=True,
        text=True
    )

    lines = [line for line in result.stdout.split('\n') if 'ATTEST' in line]

    if lines:
        for line in lines[-10:]:
            print(line)
    else:
        print("[!] No ATTEST logs found")

    print("-" * 60)

def test_netlink_socket():
    print("\n[*] Testing netlink socket creation...")

    try:
        print(f"    Protocol number: {NETLINK_ATTEST}")
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ATTEST)
        print("[+] Socket created successfully")

        pid = os.getpid()
        print(f"    Binding to PID: {pid}")
        sock.bind((pid, 0))
        print("[+] Socket bound successfully")

        sockname = sock.getsockname()
        print(f"[+] Socket name: {sockname}")

        sock.close()
        print("[+] Socket closed successfully")

        return True

    except PermissionError as e:
        print(f"[!] Permission denied: {e}")
        print("    Make sure you're running as root")
        return False
    except OSError as e:
        print(f"[!] OS Error: {e}")
        if e.errno == 93:
            print("    Protocol not supported - module may not have created netlink socket")
            print("    Check: sudo dmesg | grep 'Netlink socket created'")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {type(e).__name__}: {e}")
        return False

def test_send_receive():
    print("\n[*] Testing message exchange...")

    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ATTEST)
        sock.bind((os.getpid(), 0))
        sock.settimeout(5.0)

        print("[>] Sending hash request...")
        msg_type = 1
        data = b"REQUEST_HASH"
        data_len = len(data)

        msg = struct.pack("II512s", msg_type, data_len, data)
        nlmsg_len = 16 + len(msg)
        nlhdr = struct.pack("IHHII", nlmsg_len, 0, 0, 1, os.getpid())

        sock.send(nlhdr + msg)
        print("[+] Message sent")

        print("[>] Waiting for response (5s timeout)...")
        try:
            data = sock.recv(4096)
            print(f"[+] Received {len(data)} bytes")

            if len(data) >= 16:
                nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = \
                    struct.unpack("IHHII", data[:16])
                print(f"    Netlink header: len={nlmsg_len}, type={nlmsg_type}, pid={nlmsg_pid}")

                if len(data) >= 24:
                    payload = data[16:]
                    msg_type, data_len = struct.unpack("II", payload[:8])
                    msg_data = payload[8:8+data_len].decode('utf-8', errors='ignore').rstrip('\x00')

                    print(f"    Message type: {msg_type}")
                    print(f"    Data length: {data_len}")
                    print(f"    Data: {msg_data[:64]}{'...' if len(msg_data) > 64 else ''}")

                    if msg_type == 2:
                        print("[+] Received hash response successfully!")
                        sock.close()
                        return True

        except socket.timeout:
            print("[!] Timeout - no response from kernel module")
            print("    Possible issues:")
            print("    1. Module's netlink_recv_msg() not being called")
            print("    2. Module not processing MSG_TYPE_HASH_REQUEST")
            print("    3. Module not sending response")

        sock.close()
        return False

    except Exception as e:
        print(f"[!] Error during test: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_netlink_protocols():
    print("\n[*] Checking netlink protocol support...")

    protocols_to_test = [
        (0, "NETLINK_ROUTE"),
        (3, "NETLINK_FIREWALL"),
        (4, "NETLINK_SOCK_DIAG"),
        (9, "NETLINK_AUDIT"),
        (15, "NETLINK_NETFILTER"),
        (16, "NETLINK_GENERIC"),
        (31, "NETLINK_ATTEST (our module)"),
    ]

    for proto_num, proto_name in protocols_to_test:
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, proto_num)
            sock.close()
            status = "+"
        except:
            status = "!"

        print(f"  [{status}] {proto_num:2d}: {proto_name}")

def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║         Netlink Diagnostic Tool - attest_lkm             ║
╚═══════════════════════════════════════════════════════════╝
""")

    all_ok = True

    print("[1/6] Checking root privileges...")
    if not check_root():
        all_ok = False
        sys.exit(1)

    print("\n[2/6] Checking module status...")
    if not check_module_loaded():
        all_ok = False

    print("\n[3/6] Checking kernel logs...")
    check_dmesg()

    print("\n[4/6] Checking netlink protocols...")
    check_netlink_protocols()

    print("\n[5/6] Testing socket creation...")
    if not test_netlink_socket():
        all_ok = False

    print("\n[6/6] Testing message exchange...")
    if not test_send_receive():
        all_ok = False

    print("\n" + "="*60)
    print("DIAGNOSTIC SUMMARY")
    print("="*60)

    if all_ok:
        print("[+] All tests passed! Netlink communication is working.")
        print("    You can now run the attack simulator.")
    else:
        print("[!] Some tests failed. Common fixes:")
        print()
        print("1. Module not loaded:")
        print("   sudo insmod attest_lkm.ko")
        print()
        print("2. Netlink socket not created:")
        print("   Check: sudo dmesg | grep 'Netlink socket created'")
        print("   The module's netlink_init() might have failed")
        print()
        print("3. No response from module:")
        print("   Check: sudo dmesg | tail -30")
        print("   The netlink_recv_msg() callback might not be triggered")
        print()
        print("4. Permission issues:")
        print("   Always run with sudo")

    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
