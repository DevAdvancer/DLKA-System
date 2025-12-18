# Control Node API — Reference

This document describes the HTTP API exposed by the Control Node application (the Distributed Kernel Attestation system). It covers endpoints, request/response formats, models, configuration notes relevant to API behavior, and example usage.

Files of interest in the codebase:

- `control_node/control_node.py` — main Flask application and endpoint implementations.
- `control_node/models.py` — dataclasses for `AttestationReport`, `ConsensusDecision`, `Baseline`, and `SystemStatistics`.
- `control_node/consensus.py` — consensus engine logic and voting rules.
- `control_node/crypto_utils.py` — signature and key utilities.
- `control_node/config.py` — configuration values that affect the API behavior.

Read the implementation for details:

```control_node/control_node.py#L1-400
# See control_node/control_node.py for endpoint implementation and flow.
```

---

## Base URL

By default the server runs on:

- Host: configured via `config.server_host` (defaults to `0.0.0.0`)
- Port: configured via `config.server_port` (defaults to `5000`)

Example base URL:

- `http://<host>:<port>/` (e.g., `http://localhost:5000/`)

---

## Authentication & Security

- The current implementation does not enforce HTTP authentication on the API endpoints.
- Report authenticity may be validated by verifying ECDSA signatures when `config.require_signatures` is `true`.
- Public keys for monitors are loaded from file paths declared in `config.monitors`. See `control_node/crypto_utils.py` and `control_node/config.py` for details.

```control_node/crypto_utils.py#L1-400
# Signature verification and key loading implementation
```

---

## Endpoints Summary

The table below provides a concise, machine-readable summary of the public HTTP endpoints exposed by the Control Node. Use the detailed sections that follow for examples, request shapes, and special behaviour.

# API Documentation

| Endpoint | Method | Request Body (Summary) | Success Response (Summary) | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `/health` | GET | n/a | `{ status, timestamp, baseline_established, monitors_configured, uptime_seconds }` | Lightweight probe for monitoring systems |
| `/attest` | POST | `{ monitor_id*, timestamp*, kernel_hash*, result*, signature* }` | **No Quorum:** `{ status, consensus_reached: false, ... }`<br>**Consensus:** `{ status, consensus_reached: true, decision, ... }` | Signature verification enforced if `require_signatures` is true |
| `/baseline` | GET | n/a | `{ hash_value, timestamp, approved_by, previous_hash, version }` | Returns 404 if no baseline is established |
| `/baseline` | PUT | `{ hash*, approved_by? }` | `{ status: success, message, baseline: { ... } }` | Sensitive operation; saved atomically and logged |
| `/status` | GET | n/a | `{ baseline, pending_reports, recent_decisions, statistics, config }` | Full system state for dashboards/admin UIs |
| `/reports` | GET | n/a | `{ pending_reports: [...], count, quorum_required }` | Lists in-flight reports since last consensus |

Notes:

- Fields marked `*` are required.
- The "Request body (summary)" column is a compact guide — see the detailed endpoint sections below for full shapes and examples.
- The table summarizes API behaviours but not all error responses. Refer to detailed endpoint docs for error cases.

---

## Endpoints (Detailed)

### 1) GET /health

Health check endpoint — a lightweight status response.

- Method: `GET`
- Path: `/health`
- Description: Returns service health, uptime, whether a baseline exists, and monitor configuration summary.

Response (200):

```control_node/control_node.py#L1-200
{
  "status": "healthy",
  "timestamp": "2025-01-01T12:34:56.789123",
  "baseline_established": true,
  "monitors_configured": 3,
  "uptime_seconds": 123.45
}
```

---

### 2) POST /attest

Submit an attestation report from a monitor node. The Control Node will collect reports and run the consensus algorithm once the configured quorum of reports has been received.

- Method: `POST`
- Path: `/attest`
- Content-Type: `application/json`
- Description: Accepts a single monitor attestation report. When enough reports are collected (>= `config.quorum`) the system executes consensus and, if consensus is reached, returns the decision.

Request body (required fields):

- `monitor_id` (int) — monitor identifier (e.g., `1`, `2`, `3`)
- `timestamp` (string) — ISO-8601 timestamp when measurement was taken
- `kernel_hash` (string) — SHA256 hash hex string of the measured kernel
- `result` (string) — one of `"OK"`, `"ALERT"`, or `"ERROR"`
- `signature` (string) — base64-encoded ECDSA signature of the canonical signed string (format: `monitor_id|timestamp|kernel_hash|result`)

Optional fields:

- `baseline_hash` (string) — hash the monitor compared to (if it reported one)
- `message` (string) — optional human-readable message

Example request:

```control_node/control_node.py#L1-300
{
  "monitor_id": 1,
  "timestamp": "2025-01-15T10:30:00Z",
  "kernel_hash": "a3f5... (64 hex chars)",
  "result": "OK",
  "signature": "MEUCIQDx7+9kZX..."
}
```

Possible responses:

- 200 when report accepted but quorum not yet reached:

```control_node/control_node.py#L1-200
{
  "status": "success",
  "consensus_reached": false,
  "reports_received": 1,
  "quorum_required": 2
}
```

- 200 when quorum reached and consensus processed:

```control_node/control_node.py#L1-300
{
  "status": "success",
  "consensus_reached": true,
  "decision": "TRUSTED",          // "TRUSTED" | "COMPROMISED" | "UNCERTAIN"
  "timestamp": "2025-01-15T10:31:00.123456"
}
```

- 403 when signature verification fails (if `require_signatures` is true):

```control_node/control_node.py#L1-200
{
  "status": "error",
  "message": "Signature verification failed"
}
```

- 400 for missing fields:

```control_node/control_node.py#L1-200
{
  "status": "error",
  "message": "Missing required field: 'monitor_id'"
}
```

- 500 for internal errors.

Notes:

- Signature verification uses monitor public keys loaded by `SignatureVerifier`. If `config.require_signatures` is `true` and a report does not verify, it will be rejected.
- Reports are stored temporarily in `state.current_reports` until consensus is processed and then cleared.

---

### 3) GET /baseline

Retrieve the current baseline.

- Method: `GET`
- Path: `/baseline`
- Description: Returns the current baseline hash and metadata if established.

Success (200):

```control_node/models.py#L1-200
{
  "hash_value": "a3f5... (64 hex chars)",
  "timestamp": "2025-01-01T12:00:00.000000",
  "approved_by": "admin_user",
  "previous_hash": "b5c1...",
  "version": null
}
```

Error (404) if no baseline exists:

```control_node/control_node.py#L1-200
{
  "status": "error",
  "message": "No baseline established"
}
```

---

### 4) PUT /baseline

Update or set the baseline. This action updates the stored baseline JSON file and is logged in the audit trail.

- Method: `PUT`
- Path: `/baseline`
- Content-Type: `application/json`
- Description: Replace or establish a new baseline hash; expects the new hash and optional `approved_by` field.

Request body:

- `hash` (string) — new baseline hash (required)
- `approved_by` (string) — who approved the update (optional; default `"api_call"`)

Example:

```control_node/control_node.py#L1-300
{
  "hash": "b7d9... (64 hex chars)",
  "approved_by": "admin_user"
}
```

Response on success:

```control_node/control_node.py#L1-300
{
  "status": "success",
  "message": "Baseline updated",
  "baseline": {
    "hash_value": "b7d9...",
    "timestamp": "2025-01-15T10:45:00.000000",
    "approved_by": "admin_user",
    "previous_hash": "a3f5..."
  }
}
```

Errors:

- 500 on write/failure.

Notes:

- Baseline is saved atomically to the file configured by `config.baseline_file` (default `data/baseline.json`).
- Baseline updates are logged via `AuditLogger`.

---

### 5) GET /status

Retrieve overall system status and statistics.

- Method: `GET`
- Path: `/status`
- Description: Returns current baseline, number of pending reports, recent decisions, aggregated statistics, and important configuration values.

Response (200):

```control_node/control_node.py#L1-400
{
  "baseline": { /* baseline object or null */ },
  "pending_reports": 0,
  "recent_decisions": [
    /* up to the 10 most recent ConsensusDecision objects */
  ],
  "statistics": {
    "total_measurements": 42,
    "trusted_decisions": 30,
    "compromised_decisions": 5,
    "uncertain_decisions": 7,
    "total_alerts": 3,
    "baseline_updates": 2,
    "signature_failures": 0,
    "uptime_seconds": 12345,
    "start_time": "2025-01-01T00:00:00"
  },
  "config": {
    "quorum": 2,
    "total_monitors": 3,
    "require_signatures": true
  }
}
```

Notes:

- `recent_decisions` entries are objects produced by `ConsensusDecision.to_dict()`.

---

### 6) GET /reports

List pending (collected but not yet processed) attestation reports.

- Method: `GET`
- Path: `/reports`
- Description: Returns the list of reports currently waiting for quorum.

Response (200):

```control_node/control_node.py#L1-400
{
  "pending_reports": [
    /* AttestationReport objects as dicts */
  ],
  "count": 2,
  "quorum_required": 2
}
```

---

## Models

The primary data models are implemented as dataclasses in `control_node/models.py`. Below is a summary of each model and the JSON shape used by the API.

- `AttestationReport`
  - Fields:
    - `monitor_id` (int)
    - `timestamp` (str, ISO-8601)
    - `kernel_hash` (str)
    - `result` (str) — `"OK" | "ALERT" | "ERROR"`
    - `signature` (str) — base64 signature string
    - `baseline_hash` (optional str)
    - `message` (optional str)
  - Conversion: `to_dict()` returns JSON-serializable dict.

See definition:

```control_node/models.py#L1-200
# AttestationReport dataclass definition
```

- `ConsensusDecision`
  - Fields:
    - `decision` (str) — `"TRUSTED" | "COMPROMISED" | "UNCERTAIN"`
    - `timestamp` (str)
    - `reports` (list of `AttestationReport`)
    - `quorum_met` (bool)
    - `vote_counts` (dict)
    - `user_action` (optional str)
    - `notes` (optional str)
  - `to_dict()` creates a JSON-friendly representation that expands `reports`.

See definition:

```control_node/models.py#L1-300
# ConsensusDecision dataclass definition
```

- `Baseline`
  - Fields:
    - `hash_value` (str)
    - `timestamp` (str)
    - `approved_by` (str)
    - `previous_hash` (optional str)
    - `version` (optional str)
  - Methods:
    - `save(filepath)` — atomic write to `filepath`
    - `load(filepath)` — load baseline from file or return `None`

See definition:

```control_node/models.py#L1-400
# Baseline dataclass and persistence helpers
```

- `SystemStatistics`
  - Aggregated counters and runtime info such as `total_measurements`, `trusted_decisions`, `uptime_seconds`, etc.

See definition:

```control_node/models.py#L1-400
# SystemStatistics dataclass
```

---

## Consensus Rules

Consensus is implemented in `control_node/consensus.py`. The default rules are:

- Require `quorum` votes (configured via `config.consensus.quorum`, default `2` for a 2-of-3 scheme).
- Voting logic:
  - If at least `quorum` monitors report `"OK"` → `TRUSTED`.
  - If at least `quorum` monitors report `"ALERT"` → `COMPROMISED`.
  - Otherwise → `UNCERTAIN`.
- The engine also provides helper methods like `get_majority_hash`, `identify_outliers`, and `check_hash_consistency`.

Reference:

```control_node/consensus.py#L1-400
# ConsensusEngine implementation and rules
```

---

## Audit & Logging

- All major events are logged via `AuditLogger`:
  - Report receipts, consensus results, baseline updates, user actions, signature failures, and security alerts are written to the rotating log file specified by `config.logging.file` (default `logs/attest.log`).
- The logger also prints to the console (useful when running interactively).

---

## Example Usage (cURL)

Submit an attestation report (example):

```control_node/control_node.py#L1-300
curl -X POST http://localhost:5000/attest \
  -H "Content-Type: application/json" \
  -d '{
    "monitor_id": 1,
    "timestamp": "2025-01-15T10:30:00Z",
    "kernel_hash": "a3f5...64hexchars",
    "result": "OK",
    "signature": "MEUCIQDx7+9kZX..."
  }'
```

Fetch health:

```control_node/control_node.py#L1-200
curl http://localhost:5000/health
```

Get baseline:

```control_node/control_node.py#L1-300
curl http://localhost:5000/baseline
```

Update baseline:

```control_node/control_node.py#L1-300
curl -X PUT http://localhost:5000/baseline \
  -H "Content-Type: application/json" \
  -d '{"hash":"b7d9...64hexchars","approved_by":"admin_user"}'
```

---

## Configuration keys that affect API behavior

These keys live in the YAML config loaded by `control_node/config.py`:

- `server.host` — HTTP host interface
- `server.port` — HTTP port
- `consensus.quorum` — number of reports required to evaluate consensus
- `consensus.total_monitors` — total configured monitors
- `monitors` — list of monitor configs (each must include `id` and `public_key_path`)
- `security.require_signatures` — whether to verify ECDSA signatures on reports
- `storage.baseline_file` — path to baseline JSON file
- `logging.file` — path to the audit log file

See:

```control_node/config.py#L1-400
# Config loader and properties
```

---

## Notes & Best Practices

- Make sure monitor public keys are correctly declared in the `monitors` section of the config and accessible to the Control Node process; otherwise signature verification will fail.
- When running in production, consider adding authentication (API keys, mutual TLS, etc.) because the API does not currently enforce access controls.
- Baseline updates are sensitive operations: require human approval or automation control flows that you trust.
- Logs contain structured messages suitable for ingestion by SIEM systems. Rotate and protect logs appropriately.

---

If you want, I can:

- Generate a short OpenAPI (Swagger) spec for these endpoints.
- Produce sample client code (Python or Bash) to interact with the API.
- Add usage examples that show end-to-end flows (collecting reports, reaching consensus, and baseline update).
