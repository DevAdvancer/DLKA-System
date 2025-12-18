# Quick Start Guide

## Prerequisites

```bash
# Install required packages (Fedora/RHEL)
sudo dnf install kernel-devel kernel-headers openssl python3

# Install required packages (Debian/Ubuntu)
sudo apt install linux-headers-$(uname -r) build-essential openssl python3
```

## Setup Steps

### 1. Generate and Enroll Keys (First Time Only)

```bash
# Generate signing keys
./MOK_Gen.sh

# Enroll in Secure Boot
sudo mokutil --import keys/MOK.der

# Reboot and complete enrollment in UEFI
sudo reboot
```

After reboot, verify:
```bash
mokutil --list-enrolled | grep "Attest LKM"
```

### 2. Build and Load Module

```bash
# Quick build and load
./build_load.sh
```

Or manually:
```bash
# Build
make clean && make

# Sign
make sign

# Load
sudo insmod attest_lkm.ko
```

### 3. Verify Operation

```bash
# Check module is loaded
lsmod | grep attest_lkm

# View logs
sudo dmesg | tail -20 | grep ATTEST
```

Expected output:
```
[ATTEST] Initializing v1.0.0
[ATTEST-MEASURE] Measurement engine initialized (SHA256)
[ATTEST-HOOKS] Integrity hooks ready
[ATTEST] Module loaded successfully
```

### 4. Test Communication

```bash
# Run test monitor
sudo python3 test/monitor_test.py
```

You should see:
- Connection established
- Kernel hash received
- Real-time alerts for module events

### 5. Unload Module

```bash
sudo rmmod attest_lkm
```

## Common Commands

```bash
# View module info
modinfo attest_lkm.ko

# Check signature
modinfo attest_lkm.ko | grep sig

# Monitor kernel logs in real-time
sudo dmesg -w | grep ATTEST

# Reload module
make reload

# Clean build
make clean
```

## Troubleshooting

**"Operation not permitted" when loading:**
- Module not signed or signature invalid
- Run `make sign` before loading

**"Invalid module format":**
- Kernel version mismatch
- Update `KERNEL_VERSION` in Makefile
- Rebuild with correct kernel headers

**No output from test script:**
- Module not loaded: `lsmod | grep attest_lkm`
- Run with sudo: `sudo python3 test/monitor_test.py`
- Check Netlink protocol number matches (31)

**Kprobe warnings in dmesg:**
- Non-critical, module notifier still works
- Some kernels restrict kprobe symbols
- Basic functionality unaffected

## Auto-Start Setup

To load module automatically on boot:

```bash
sudo ./install.sh
```

Verify:
```bash
systemctl status attest-lkm
```

Disable auto-start:
```bash
sudo systemctl disable attest-lkm
sudo systemctl stop attest-lkm
```

## Complete Cleanup

Remove module and keys:

```bash
# Unload module
sudo rmmod attest_lkm

# Schedule key deletion
./cleanup_attest.sh

# Reboot and confirm in MokManager
sudo reboot
```

## Next Steps

- Read `README.md` for detailed workflow
- Read `ARCHITECTURE.md` for technical details
- Explore `test/` directory for example clients
- Modify `src/` files to extend functionality
