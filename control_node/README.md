## Control Node

The control node is the user-space control plane for the DLKA System. It receives attestation reports from one or more monitors, runs a consensus algorithm, manages a trusted baseline hash, and drives operator-visible responses.

This file provides a high-level overview. For per-file, in-depth documentation, see `documentation/documentation/doceumentation.md`.

---

## Features

- HTTP API (Flask) for:
  - Health and status checks.
  - Submitting attestation reports.
  - Managing and querying the baseline.
  - Inspecting pending reports and recent decisions.
- Quorum-based consensus across multiple monitors.
- Optional ECDSA-based signature verification for incoming reports.
- Structured audit logging with rotation.
- Human-in-the-loop workflows for establishing and updating baselines.

---

## Key files

- `control_node.py` — main entry point and HTTP API implementation.
- `models.py` — core data structures (reports, decisions, baseline, statistics).
- `consensus.py` — consensus rules and vote counting.
- `crypto_utils.py` — key generation and signature verification helpers.
- `config.py` — YAML-based configuration loader and accessors.
- `audit_logger.py` — structured audit logging utilities.
- `user_interaction.py` — terminal-based operator prompts and status views.
- `install.sh` — helper script to bootstrap the environment and keys.
- `requirements.txt` — Python dependencies.
- `config.yaml` — runtime configuration (example/expected structure described in documentation).

For detailed behavior of each module and function, refer to `documentation/documentation/doceumentation.md`.

---

## Running the control node

From the repository root:

```bash
cd control_node
./install.sh
python3 control_node.py
```

Then call the HTTP API from your monitors (or tools such as `curl` or Postman). Endpoints and payload shapes are documented in the control node documentation file.
