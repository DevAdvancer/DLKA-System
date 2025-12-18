# Kernel Runtime Attestation Module (Attest LKM)

A Linux Kernel Module for distributed runtime attestation that monitors kernel integrity through cryptographic hashing and real-time event detection.

## Overview

Attest LKM provides runtime integrity monitoring for Linux kernels by:
- Computing SHA256 hashes of kernel memory regions
- Detecting module load/unload events via kprobes and notifiers
- Communicating with userspace via Netlink sockets
- Broadcasting security alerts in real-time

## Architecture

### Components

**Core Module** (`src/attest_lkm.c`)
- Module initialization and lifecycle management
- Global state coordination
- Component orchestration

**Measurement Engine** (`src/measure.c`)
- SHA256 cryptographic hashing
- Kernel text section measurement
- Dynamic symbol resolution via kprobes

**Integrity Hooks** (`src/hooks.c`)
- Module load/unload detection using kernel notifiers
- Kprobe-based monitoring of `do_init_module` and `free_module`
- Real-time event broadcasting

**Netlink Communication** (`src/netlink_comm.c`)
- Kernel-userspace message passing
- Unicast responses for hash requests
- Multicast alerts for security events

### Communication Protocol

**Message Types:**
- `MSG_TYPE_HASH_REQUEST (1)` - Request kernel hash computation
- `MSG_TYPE_HASH_RESPONSE (2)` - Return computed hash
- `MSG_TYPE_BASELINE_UPDATE (4)` - Update baseline hash
- `MSG_TYPE_ALERT (5)` - Security event notification
- `MSG_TYPE_ACK (6)` - Acknowledgment

**Netlink Protocol:** `NETLINK_ATTEST (31)`

## System Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    Attest LKM Workflow                      │
└─────────────────────────────────────────────────────────────┘

1. Key Generation          2. Build & Sign         3. Load Module
   ┌──────────┐              ┌──────────┐            ┌──────────┐
   │MOK_Gen.sh│─────────────▶│  make    │───────────▶│ insmod   │
   │          │              │make sign │            │          │
   └──────────┘              └──────────┘            └──────────┘
        │                                                  │
        ▼                                                  ▼
   ┌──────────┐                                      ┌──────────┐
   │ mokutil  │                                      │  Kernel  │
   │ --import │                                      │  Space   │
   └──────────┘                                      └──────────┘
        │                                                  │
        ▼                                                  ▼
   ┌──────────┐                                      ┌──────────┐
   │  Reboot  │                                      │ Netlink  │
   │   UEFI   │                                      │  Socket  │
   └──────────┘                                      └──────────┘
                                                           │
4. Test & Monitor                                          │
   ┌──────────┐                                            │
   │ Python   │◀───────────────────────────────────────────┘
   │ Monitor  │  (Hash requests, Real-time alerts)
   └──────────┘
```

## Workflow

### 1. Key Generation and Secure Boot Setup

Generate signing keys for module verification:

```bash
./MOK_Gen.sh
```

This creates RSA-2048 keys in `keys/` directory.

Enroll the Machine Owner Key (MOK) in Secure Boot:

```bash
sudo mokutil --import keys/MOK.der
```

Reboot and complete enrollment via UEFI prompt.

Verify enrollment:

```bash
mokutil --list-enrolled | grep "Attest LKM"
```

### 2. Build and Sign Module

Build the kernel module:

```bash
make clean && make
```

Sign the module with your MOK:

```bash
make sign
```

### 3. Load Module

Load the signed module:

```bash
sudo insmod attest_lkm.ko
```

Or use the convenience script:

```bash
./build_load.sh
```

### 4. Verify Module Status

Check if module is loaded:

```bash
lsmod | grep attest_lkm
```

View kernel logs:

```bash
sudo dmesg | grep ATTEST
```

Expected output:
```
[ATTEST] Initializing v1.0.0
[ATTEST-MEASURE] kallsyms_lookup_name acquired successfully
[ATTEST-MEASURE] Measurement engine initialized (SHA256)
[ATTEST-HOOKS] Integrity hooks ready
[ATTEST] Module loaded successfully
```

### 5. Test Communication

Test Netlink communication with userspace:

```bash
sudo python3 test/monitor_test.py
```

This script:
- Establishes Netlink connection
- Requests kernel hash computation
- Receives real-time security alerts

### 6. Auto-Start on Boot (Optional)

Install module to load automatically:

```bash
sudo ./install.sh
```

This configures systemd service and module loading.

Verify auto-start:

```bash
sudo reboot
# After reboot
lsmod | grep attest_lkm
systemctl status attest-lkm
```

### 7. Unload Module

Remove the module:

```bash
sudo rmmod attest_lkm
```

## Development

### Project Structure

```
.
├── include/
│   ├── attest_lkm.h      # Main header with state definitions
│   ├── hooks.h           # Integrity monitoring hooks
│   ├── measure.h         # Cryptographic measurement
│   └── netlink_comm.h    # Userspace communication
├── src/
│   ├── attest_lkm.c      # Module entry point
│   ├── hooks.c           # Event detection implementation
│   ├── measure.c         # Hash computation
│   └── netlink_comm.c    # Netlink protocol handler
├── test/
│   ├── monitor_test.py   # Userspace monitor client
│   └── netlink_test.py   # Protocol testing
├── Makefile              # Build configuration
├── MOK_Gen.sh            # Key generation script
├── build_load.sh         # Build and load helper
├── install.sh            # Auto-start installer
└── cleanup_attest.sh     # Cleanup and key removal
```

### Build Targets

```bash
make              # Build module
make clean        # Remove build artifacts
make sign         # Sign module with MOK
make install      # Load module
make uninstall    # Unload module
make reload       # Unload and reload
```

### Cleanup

Remove module and enrolled keys:

```bash
./cleanup_attest.sh
```

This schedules MOK deletion. Reboot and confirm in MokManager.

## Security Considerations

- Module must be signed for Secure Boot systems
- Requires root privileges for loading and Netlink communication
- Kprobes may fail on hardened kernels with symbol restrictions
- Hash computation samples 4KB of kernel text section

## Requirements

- Linux kernel 5.x or higher
- Kernel headers matching running kernel
- OpenSSL for key generation
- Python 3 for testing scripts
- Root access for module operations

## Troubleshooting

**Module fails to load:**
- Check kernel version compatibility
- Verify module signature: `modinfo attest_lkm.ko`
- Review dmesg for specific errors

**Netlink communication fails:**
- Ensure module is loaded
- Run userspace tools with sudo
- Check protocol number matches (31)

**Kprobe registration fails:**
- Some symbols may be unavailable on stripped kernels
- Module notifier still functions for basic monitoring

## License

GPL v2

## Authors

Abhirup Kumar & Sujal Kr Sil & Ayushman Bilas Thakur
