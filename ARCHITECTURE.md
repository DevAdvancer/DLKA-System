## DLKA System Architecture

This document describes the end-to-end architecture of the Distributed Linux Kernel Attestation (DLKA) system across both the kernel-space and user-space components.

---

## Components

### Kernel node (`kernel_node/`)

- Linux Kernel Module (Attest LKM) that:
  - Measures selected kernel memory (typically a 4KB window of kernel text) and computes SHA256 hashes.
  - Hooks module load/unload and other integrity-relevant events.
  - Maintains global attestation state (baseline hash, counts, timestamps).
  - Communicates with user-space monitors through a custom Netlink protocol (`NETLINK_ATTEST`).

Key internal modules (see `kernel_node/ARCHITECTURE.md` for details):
- `src/attest_lkm.c` — module entry point, global state, initialization/teardown.
- `src/measure.c` — measurement engine, hash computation, symbol resolution.
- `src/hooks.c` — integrity hooks, module notifier and kprobes.
- `src/netlink_comm.c` — Netlink message handling for requests and alerts.

### Monitors (user-space)

- Processes that:
  - Subscribe to the Attest LKM Netlink socket.
  - Trigger hash requests.
  - Receive hash responses and security alerts.
  - Optionally sign measurements and forward structured attestation reports to the control node.
- Example/testing clients live under `kernel_node/test/`.

### Control node (`control_node/`)

- Python-based control plane that:
  - Exposes an HTTP API (Flask) for incoming attestation reports.
  - Implements a quorum-based consensus engine on top of multiple monitors.
  - Persists and manages a trusted baseline hash.
  - Produces structured audit logs and operator prompts.

Key internal modules (see `control_node/documentation/documentation/doceumentation.md` for per-file details):
- `control_node.py` — HTTP API, global state, main orchestration.
- `models.py` — domain models (`AttestationReport`, `ConsensusDecision`, `Baseline`, `SystemStatistics`).
- `consensus.py` — `ConsensusEngine`, quorum and vote-counting logic.
- `crypto_utils.py` — key generation and signature verification.
- `config.py` — YAML-backed configuration.
- `audit_logger.py` — structured audit logging.
- `user_interaction.py` — console-based operator prompts.

---

## Data flows

### 1. Measurement and alert flow (kernel ↔ monitor)

1. Attest LKM initializes (`attest_init`):
   - Allocates global state, Netlink socket, measurement engine, and hooks.
2. A monitor process:
   - Connects to `NETLINK_ATTEST`.
   - Sends a `MSG_TYPE_HASH_REQUEST` message.
3. The kernel module:
   - Computes a SHA256 hash over the selected kernel region.
   - Sends back `MSG_TYPE_HASH_RESPONSE` with the hex-encoded hash.
4. On module events or integrity triggers, Attest LKM:
   - Formats an alert message (`MSG_TYPE_ALERT`) and multicasts it to all subscribers.

For exact message types and protocol details, see `kernel_node/README.md`.

### 2. Attestation and consensus flow (monitor ↔ control node)

1. After receiving a kernel hash, the monitor:
   - Builds an attestation report containing:
     - `monitor_id`, `timestamp`, `kernel_hash`, `result` (`OK`/`ALERT`/`ERROR`).
     - Optional `baseline_hash`, human-readable `message`.
   - Optionally signs the canonical string using its private key.
   - Sends the report to the control node `POST /attest` endpoint.
2. The control node:
   - Parses JSON into an `AttestationReport`.
   - Verifies the signature (if `require_signatures` is enabled in `config.yaml`).
   - Appends the report to in-memory `current_reports`.
3. Once `current_reports` length ≥ configured `quorum`:
   - `ConsensusEngine.apply_consensus()` computes a `ConsensusDecision`.
   - Decision, vote counts, and outliers are logged via `AuditLogger`.
   - The decision is persisted in `recent_decisions` and statistics are updated.

### 3. Baseline and operator interaction

1. If no baseline exists:
   - On a `TRUSTED` decision, the control node may prompt the operator to accept the measured hash as the initial baseline.
2. If a baseline exists:
   - On `TRUSTED`, hashes are compared to the stored baseline.
   - On `COMPROMISED`, the operator may:
     - Approve updating the baseline (if the change is expected).
     - Reject and trigger a security response (e.g., incident handling checklist).
     - Ignore (log only).
3. Baseline updates:
   - Are saved atomically to disk (JSON) via `Baseline.save`.
   - Are recorded as audit events including `approved_by` and a version/previous hash.

---

## Deployment topology

- **Single host (development/lab)**:
  - Attest LKM and control node run on the same machine.
  - Monitors connect via local Netlink and localhost HTTP.
- **Distributed (production-style)**:
  - Attest LKM runs on protected hosts.
  - Lightweight monitor agents run locally on each host, communicating with:
    - Local kernel via Netlink.
    - Central control node over a secure network channel (e.g., HTTPS).
  - A single control node instance (or a small HA cluster) aggregates reports and decisions.

Network and security considerations:
- Protect control node HTTP endpoints with TLS and authentication when used across networks.
- Carefully manage monitor key distribution and private key storage.
- Ensure logs and baseline files are stored on protected, backed-up storage.

---

## Extensibility

Ideas for extending the DLKA system:

- **Kernel node**:
  - Add more measurement strategies (e.g., multiple regions, dynamic targets).
  - Hook additional security-relevant events and broadcast new alert types.
  - Extend the Netlink protocol with richer message payloads.

- **Control node**:
  - Implement alternative consensus mechanisms (weighted votes, reputation, larger clusters).
  - Add persistent storage for reports and decisions (database-backed).
  - Integrate with external incident response tooling (ticketing systems, SIEM, alert managers).
  - Expose metrics endpoints for observability platforms.

Keep this document updated when you introduce new components or data flows so it remains the single high-level reference for the entire codebase.
