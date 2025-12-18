
## DLKA System

Distributed Linux Kernel Attestation (DLKA) is a two-part system for runtime kernel integrity monitoring:
- **`kernel_node/`**: a Linux Kernel Module (Attest LKM) that measures kernel memory and emits integrity events.
- **`control_node/`**: a Python-based control service that collects attestation reports, runs consensus, manages baselines, and drives operator response.

This repository combines both components into a single deployable project.

---

## Repository structure

- `control_node/`
  User-space control plane for attestation:
  - HTTP API for monitors to submit attestation reports
  - Consensus engine for multi-monitor decisions
  - Baseline management and persistence
  - Structured audit logging and operator prompts

- `kernel_node/`
  Kernel-space Attest LKM:
  - Computes SHA256 measurements of kernel memory
  - Hooks into module load/unload events
  - Sends hash responses and real-time alerts via Netlink

- `LICENSE`
  Project license (GPL v2 for kernel module; see file for details).

---

## High-level architecture

1. The **kernel node** (Attest LKM) runs inside the Linux kernel:
   - Periodically measures a section of kernel memory and computes a SHA256 hash.
   - Monitors module load/unload and other integrity-related events.
   - Communicates with user space over a Netlink protocol (`NETLINK_ATTEST`).

2. One or more **monitor processes** subscribe to Netlink messages:
   - Request hashes from the kernel module.
   - Forward attestation reports to the control node (typically over HTTP).

3. The **control node** exposes a small HTTP API:
   - Receives signed attestation reports from monitors.
   - Applies a configurable quorum-based consensus algorithm.
   - Compares results against a trusted baseline hash.
   - Prompts an operator or triggers a security response when integrity is violated.

For a more detailed view, see:
- `ARCHITECTURE.md` (root) — end-to-end system view
- `kernel_node/ARCHITECTURE.md` — kernel module internals
- `control_node/documentation/documentation/doceumentation.md` — control node internals

---

## Requirements

- Linux system with:
  - Kernel headers installed and matching the running kernel (for `kernel_node/`)
  - Secure Boot-aware toolchain if you plan to sign the module (optional but recommended)
- Python 3.8+ for `control_node/`
- Root privileges to:
  - Build and load kernel modules
  - Use Netlink protocol number reserved for Attest LKM

See:
- `kernel_node/README.md` — detailed kernel node requirements
- `control_node/requirements.txt` — Python dependencies for the control node

---

## Quick start

### 1. Build and load the kernel node

```bash
cd kernel_node
./build_load.sh
```

This script:
- Builds the Attest LKM for your current kernel
- Optionally signs it (if configured)
- Loads the module into the running kernel

You can verify the module status with:

```bash
lsmod | grep attest_lkm
sudo dmesg | grep ATTEST
```

For Secure Boot setups and manual steps, see `kernel_node/README.md`.

### 2. Install and run the control node

```bash
cd control_node
./install.sh
python3 control_node.py
```

`install.sh` will:
- Create a Python virtual environment
- Install required Python packages
- Create default directories (`keys/`, `logs/`, `data/`)
- Generate monitor keypairs (for signed reports)

Then, `control_node.py` starts the HTTP API on the host/port specified in `config.yaml`.

### 3. Connect monitors and test

- Use the testing clients under `kernel_node/test/` to validate Netlink communication.
- Implement or configure monitor agents that:
  - Subscribe to kernel Netlink alerts
  - Periodically request kernel hashes
  - Forward signed reports to the control node `POST /attest` endpoint.

The control node will:
- Accumulate reports until quorum is met
- Compute a consensus decision (TRUSTED / COMPROMISED / UNCERTAIN)
- Compare to the configured baseline
- Log audit events and optionally prompt an operator to update the baseline or escalate

---

## Documentation

- **End-to-end architecture**: `ARCHITECTURE.md`
- **Kernel node internals and workflows**: `kernel_node/ARCHITECTURE.md` and `kernel_node/README.md`
- **Control node internals and per-file docs**: `control_node/documentation/documentation/doceumentation.md`

If you extend the project (new hooks, new consensus rules, additional monitor types), add a short section under `ARCHITECTURE.md` and update the relevant component README.
