import socket
import struct
import os
import sys

NETLINK_ATTEST = 31
MSG_TYPE_HASH_REQUEST = 1
MSG_TYPE_HASH_RESPONSE = 2

class AttestClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ATTEST)
        self.sock.bind((os.getpid(), 0))
        print(f"[+] Netlink socket bound (PID: {os.getpid()})")

    def send_hash_request(self):
        msg_type = MSG_TYPE_HASH_REQUEST
        data = b"REQUEST_HASH"
        data_len = len(data)

        msg = struct.pack("II512s", msg_type, data_len, data)

        nlmsg_len = 16 + len(msg)
        nlmsg_type = 0
        nlmsg_flags = 0
        nlmsg_seq = 1
        nlmsg_pid = os.getpid()

        nlhdr = struct.pack("IHHII", nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)
        packet = nlhdr + msg

        self.sock.send(packet)
        print("[>] Hash request sent to kernel module")

    def receive_response(self):
        data = self.sock.recv(4096)

        if len(data) < 16:
            print("[!] Invalid response")
            return None

        nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack("IHHII", data[:16])

        payload = data[16:]
        if len(payload) < 8:
            print("[!] Payload too short")
            return None

        msg_type, data_len = struct.unpack("II", payload[:8])
        msg_data = payload[8:8+data_len]

        if msg_type == MSG_TYPE_HASH_RESPONSE:
            hash_value = msg_data.decode('utf-8', errors='ignore').rstrip('\x00')
            print(f"[+] Received kernel hash: {hash_value}")
            return hash_value

        return None

    def close(self):
        self.sock.close()

def main():
    print("=" * 60)
    print("Kernel Attestation Monitor - Test Client")
    print("=" * 60)

    try:
        client = AttestClient()

        client.send_hash_request()

        print("[*] Waiting for kernel response...")
        hash_result = client.receive_response()

        if hash_result:
            print(f"\n[+] SUCCESS: Kernel measurement received")
            print(f"[*] Hash: {hash_result}")
        else:
            print("\n[!] FAILED: No valid response received")

        client.close()

    except PermissionError:
        print("[!] Error: This script requires root privileges")
        print("    Run with: sudo python3 monitor_test.py")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
