# Control Node — Per-file Documentation

This document describes the purpose, behavior, interfaces, and important implementation details of each file and directory in the `control_node` module. Use this to understand runtime flow, extend functionality, or onboard new developers.

Repository root (relevant files & directories)
- `control_node/` (module root)
  - `autostart_login/` (helper directory for autostart utilities)
  - `documentation/` (documentation files — this file lives here)
  - `audit_logger.py`
  - `config.py`
  - `config.yaml`
  - `consensus.py`
  - `control_node.py`
  - `crypto_utils.py`
  - `install.sh`
  - `models.py`
  - `requirements.txt`
  - `user_interaction.py`

---

## High-level overview

The Control Node is the central decision-making component of a small distributed kernel attestation system. Monitors submit attestation reports (hash of kernel and a verdict). The Control Node collects these reports, verifies authenticity (optionally), runs a consensus algorithm (2-of-3 by default), logs audit information, possibly prompts a human operator, and persists/maintains a trusted kernel baseline.

Key responsibilities:
- Expose a small HTTP API for reports and state (`control_node.py` / Flask).
- Keep ephemeral state for reports while waiting for quorum.
- Apply a deterministic consensus algorithm (`consensus.py`).
- Verify signatures from monitor nodes (`crypto_utils.py`) when enabled.
- Persist the baseline to disk atomically (`models.py`).
- Structured audit logging (`audit_logger.py`).
- Simple interactive user prompts for human-in-the-loop decisions (`user_interaction.py`).
- Provide configuration via YAML (`config.py` + `config.yaml`).
- Provide an installation helper that creates keys and directories (`install.sh`).

---

## File-by-file documentation

### `control_node.py`
Primary runtime application.

Responsibilities:
- Creates and configures a Flask application exposing the public API endpoints (health, attest, baseline, status, reports).
- Initializes global runtime `state` via the `ControlNodeState` class defined in the module. The `state` holds:
  - `current_reports`: list of in-memory `AttestationReport` objects accumulated until quorum.
  - `baseline`: currently established `Baseline` or `None`.
  - `consensus_engine`: `ConsensusEngine` instance constructed from config values.
  - `signature_verifier`: `SignatureVerifier` constructed with monitor public key configuration.
  - `audit_logger`: `AuditLogger` used for structured logging.
  - `user_interface`: `UserInteraction` for interactive prompts.
  - `recent_decisions`, `statistics`, `start_time`.
- Loads baseline from disk at startup via `Baseline.load()` and logs the event.
- Implements the HTTP endpoints:
  - `GET /health` — returns basic status including uptime and whether baseline exists.
  - `POST /attest` — accepts an attestation report JSON, verifies signatures (if enabled), appends to `current_reports`, and triggers consensus processing once quorum is reached. Handles common HTTP error codes (400 for missing fields, 403 for failed signature verification, 500 for server errors).
  - `GET /baseline` — returns the baseline object if present (404 if none).
  - `PUT /baseline` — replaces/sets baseline after receiving JSON `{ hash, approved_by }`. Persists using `Baseline.save()` and logs audit events.
  - `GET /status` — returns aggregated system information: baseline, pending reports count, recent decisions, statistics, and a small view of config values relevant to API consumers.
  - `GET /reports` — returns pending reports waiting for quorum.
- Contains core control flow functions:
  - `process_consensus()` — orchestrates using `consensus_engine` to compute a `ConsensusDecision`, logs it, updates statistics, and delegates to handlers depending on decision.
  - `handle_trusted_state()`, `handle_compromised_state()`, `handle_uncertain_state()` — logic for post-decision behavior including prompting operator, updating baseline, or triggering the security response.
  - `trigger_security_response()` — logs and prints an escalation checklist.
  - `notify_systemd_ready()` — attempts to notify systemd using `NOTIFY_SOCKET` (no-op if not running under systemd).
- `main()` function: prints a startup banner, calls `notify_systemd_ready()`, and runs Flask (parameters pulled from config).

Design notes:
- `state.current_reports` is ephemeral and reset after consensus; the long-term audit trail lives in logs and `recent_decisions`.
- The HTTP API intentionally avoids implementing authentication; signature verification secures report authenticity only when enabled.
- The module favors clear logging of decisions and actions to support offline investigation and SIEM ingestion.

---

### `models.py`
Domain model dataclasses and baseline persistence.

Contains dataclasses:
- `AttestationReport`:
  - Attributes: `monitor_id`, `timestamp`, `kernel_hash`, `result`, `signature`, `baseline_hash`, `message`.
  - Methods: `to_dict()` and `from_dict()` for JSON-ready shapes.
  - Intended as the canonical in-memory representation of incoming reports.

- `ConsensusDecision`:
  - Attributes: `decision` (`TRUSTED` | `COMPROMISED` | `UNCERTAIN`), `timestamp`, `reports`, `quorum_met`, `vote_counts`, `user_action`, `notes`.
  - Method: `to_dict()` returns a JSON-serializable representation suitable for API responses (expanding reports).
  - Used to represent the outcome of applying the consensus algorithm to a set of reports.

- `Baseline`:
  - Attributes: `hash_value`, `timestamp`, `approved_by`, `previous_hash`, `version`.
  - Persistence methods:
    - `save(filepath)` — writes JSON atomically (via temporary file then `os.replace`), ensures parent directory exists.
    - `load(filepath)` — reads JSON if present and returns a `Baseline` instance or `None` on missing/corrupt file. Logs a warning to stdout if file cannot be parsed.
  - The baseline object is used as the trusted reference hash for kernel integrity comparisons and recorded with an approval identity/time for auditable changes.

- `SystemStatistics`:
  - Counters and runtime metrics (measurements processed, trust/compromised/uncertain counts, alerts, baseline updates, signature failures, uptime).
  - `to_dict()` for API serialization.

Design notes:
- Baseline persistence is atomic for safety on POSIX: write to `.tmp`, then rename. This reduces risk of corrupted baseline files on interruptions.
- Models are intentionally lightweight and JSON-friendly, making them easy to log and include in API responses.

---

### `consensus.py`
Consensus engine implementation.

Primary class:
- `ConsensusEngine`:
  - Initialized with `quorum` and `total_monitors`. Validates that `1 <= quorum <= total_monitors`.
  - `apply_consensus(reports)`:
    - Counts votes (`OK`, `ALERT`, `ERROR`) and determines final decision by the simple majority/quorum rules:
      - If `OK` count >= quorum → `TRUSTED`.
      - Else if `ALERT` count >= quorum → `COMPROMISED`.
      - Else → `UNCERTAIN`.
    - Returns a `ConsensusDecision` object populated with vote counts, quorum flag, and notes.
  - `check_hash_consistency(reports)`:
    - Returns `True` if all `OK` reports have identical `kernel_hash`, otherwise `False`.
  - `get_majority_hash(reports)`:
    - Returns the most common `kernel_hash` among non-`ERROR` reports (or `None` if none).
  - `identify_outliers(reports)`:
    - Computes the majority `result` and returns a list of `monitor_id` values that disagree — useful for identifying suspicious monitors.
  - `get_decision_summary(decision)`:
    - Returns a human-readable string summary useful for logs or console.

Design notes:
- The engine implements a straightforward deterministic rule (2-of-3 by default). It is intentionally simple to be auditable and predictable.
- Extensibility: the class can be replaced or extended to support weighted votes, tie-breaker rules, or quorum policies for larger deployments.

---

### `crypto_utils.py`
Cryptographic utilities and signature verification.

Contains:
- `CryptoUtils` static helpers:
  - `generate_keypair()` — generates an ECDSA (secp256r1) keypair and returns `(private_pem, public_pem)` bytes in PEM format.
  - `sign_data(private_key_pem, data)` — signs `data` (string) with provided private key using ECDSA+SHA256, returns base64-encoded signature.
  - `verify_signature(public_key_pem, data, signature_b64)` — verifies a base64-encoded signature against `data` using the given public key. Returns boolean; prints a message and returns `False` on errors.
  - `load_public_key(filepath)` — convenience to load a PEM pub key from a file path.
- `SignatureVerifier`:
  - Accepts `monitors_config` (list of monitor entries, each should include `id` and `public_key_path`).
  - Loads all public keys into a `public_keys` mapping keyed by `monitor_id`. If a key fails to load it logs to stdout.
  - `verify_report(report)` reconstructs the signed canonical string `"{monitor_id}|{timestamp}|{kernel_hash}|{result}"`, finds the `public_key` for the `report.monitor_id` and calls `CryptoUtils.verify_signature(...)`.
  - Returns `True` only if the signature is valid and a public key exists for that monitor.

Usage:
- `control_node.py` uses `SignatureVerifier` to validate incoming `AttestationReport` objects before accepting them (when `require_signatures` is enabled via config).

Security notes:
- The canonical signing format must match what monitors use. Any mismatch (ordering, separators, timezone formatting) will cause verification to fail.
- Monitor public keys should be distributed securely and file permissions should restrict write access to avoid key spoofing.

---

### `config.py`
Configuration loader & accessor.

Functionality:
- `Config` class loads YAML configuration from a file (default `'config.yaml'`).
- Implements a `.get(dot.notation, default)` helper that navigates nested dictionaries using dot notation (e.g., `server.host`).
- Exposes convenient properties for common configuration values:
  - `server_host`, `server_port`
  - `quorum`, `total_monitors`
  - `monitors` (list of monitor configs)
  - `require_signatures` (bool)
  - `baseline_file` (path)
  - `log_file`, `log_level`
- At module load time, a global `config = Config()` instance is created for use by other modules.

Recommended config keys (expected in `config.yaml`):
- `server`:
  - `host` (string)
  - `port` (int)
- `consensus`:
  - `quorum` (int)
  - `total_monitors` (int)
- `monitors`: list of `{ id: int, public_key_path: path/to/key.pub }`
- `security`:
  - `require_signatures`: bool
- `storage`:
  - `baseline_file` (path)
- `logging`:
  - `file` (path)
  - `level` (string)

Notes:
- If the config file is missing, `Config` raises `FileNotFoundError` at init time, which will interrupt startup. Ensure `config.yaml` exists and is readable.

---

### `audit_logger.py`
Structured audit logging.

Responsibilities:
- Provides `AuditLogger` class that:
  - Initializes a `logging.Logger` named (e.g., `attestation_audit`) with file rotation via `RotatingFileHandler`.
  - Ensures the log directory exists.
  - Formats log lines as `timestamp | level | message`.
  - Attaches a console handler for real-time visibility.
  - Exposes higher-level methods to log specific event types:
    - `log_report_received(report)`
    - `log_consensus(decision)`
    - `log_user_action(action, details)`
    - `log_baseline_update(old_hash, new_hash, approved_by)`
    - `log_alert(severity, message)`
    - `log_signature_failure(monitor_id)`
    - `log_system_event(event_type, details)`
    - `log_statistics(stats)`
- `control_node.py` uses `AuditLogger` throughout for traceability and auditing.

Operational notes:
- Log rotation prevents disk exhaustion. The default rotation parameters can be tuned via constructor arguments.
- Logs are intentionally textual to allow easy ingestion into log collection systems (SIEM/ELK/etc).

---

### `user_interaction.py`
Console-based human-in-the-loop interaction utilities.

Features:
- Uses `colorama` and `tabulate` to make terminal prompts readable and actionable.
- `UserInteraction` exposes:
  - `prompt_integrity_violation(decision, current_hash, baseline_hash)`:
    - Displays a formatted alert including vote breakdown, monitor reports (with colorization), and the expected vs measured hash.
    - Prompts operator for an action: `Approve` (update baseline), `Reject` (trigger security response), or `Ignore` (log and continue).
    - Returns the operator's choice: `'approve'`, `'reject'`, or `'ignore'`.
  - `prompt_baseline_establishment(kernel_hash)`:
    - Used when no baseline exists: prompts the operator to accept the first measured hash as baseline.
  - `display_status(baseline, recent_decisions)`:
    - Pretty-prints system status, baseline metadata and recent consensus decisions for CLI operators.
- This module is designed to be used in interactive deployments where a human operator is present. It is not intended for headless/service-only deployments (unless the CLI is wired into automated workflows).

Important:
- `prompt_*` methods block and expect stdin interaction. For headless environments, consider replacing `UserInteraction` with a non-blocking implementation (e.g., auto-approve policy or external ticketing integration).

---

### `install.sh`
Convenience installation script.

What it does:
- Creates a Python virtual environment (if one does not exist).
- Activates the virtual environment and installs dependencies from `requirements.txt`.
- Creates directories `keys`, `logs`, and `data` (defaults expected by other modules).
- Generates ECDSA keypairs for monitors (if not present) using `CryptoUtils.generate_keypair()` through an inlined Python script. It writes keys to `keys/monitor<N>.priv` and `keys/monitor<N>.pub`.
- Fixes file permissions for private keys and public keys.
- Prints next steps including how to start the control node or install a systemd unit.

Caveats / improvements:
- The script assumes `python3` and `pip` are available system-wide.
- Key generation occurs during install; in production you may want to manage keys with a secure KMS.
- Script manipulates file permissions without enforcing ownership or other security measures.

---

### `requirements.txt`
Lists Python dependencies used by the module:
- `Flask`, `Flask-CORS` — HTTP API
- `cryptography` — ECDSA signing & verification
- `PyYAML` — configuration loading
- `requests` — (not used in core code, useful for clients/tests)
- `python-dateutil` — date handling (if used)
- `colorama`, `tabulate` — pretty CLI output
- Lock versions here if reproducible deployments are required.

---

### `config.yaml`
Application configuration. It is loaded by `config.py`. Example structure (fields expected — adapt to your environment):

- `server`:
  - `host: 0.0.0.0`
  - `port: 5000`
- `consensus`:
  - `quorum: 2`
  - `total_monitors: 3`
- `monitors`:
  - `- id: 1`
    `  public_key_path: keys/monitor1.pub`
  - `- id: 2`
    `  public_key_path: keys/monitor2.pub`
  - `- id: 3`
    `  public_key_path: keys/monitor3.pub`
- `security`:
  - `require_signatures: true`
- `storage`:
  - `baseline_file: data/baseline.json`
- `logging`:
  - `file: logs/attest.log`
  - `level: INFO`

Notes:
- Ensure the `monitors` section matches the actual keys present on disk and that the `id` values match the `monitor_id` in reports.
- File paths are treated as relative to the working directory where the control node is started, unless absolute paths are provided.

---

## Runtime flow summary

1. Start-up
   - `control_node.py` initializes global `state`, loads baseline (if present), sets up `AuditLogger`, `ConsensusEngine`, and `SignatureVerifier`.
   - If running as a systemd service, `notify_systemd_ready()` tries to send readiness.

2. Receiving a report
   - `POST /attest` receives a JSON payload.
   - Payload is parsed into an `AttestationReport` and logged (`log_report_received`).
   - If `require_signatures` is enabled, `SignatureVerifier.verify_report()` is called. On failure, the report is rejected with a 403 and `signature_failures` increments.
   - The report is appended to `state.current_reports`.

3. Consensus
   - When the number of collected reports >= `config.quorum`, `process_consensus()` is invoked:
     - `consensus_engine.apply_consensus()` returns a `ConsensusDecision`.
     - Audit log is updated with `log_consensus`.
     - Decision is saved to `state.recent_decisions` and counters incremented.
     - Determine majority hash via `get_majority_hash`.
     - Branch:
       - `TRUSTED`: if no baseline exists, prompt to establish baseline; else compare with baseline.
       - `COMPROMISED`: prompt operator (approve baseline update, reject → trigger security response, or ignore).
       - `UNCERTAIN`: log an alert, identify outliers.
     - `state.current_reports` is cleared after processing.

4. Baseline updates and security response
   - Baseline updates are persisted to disk via `Baseline.save()` and recorded in audit logs.
   - `trigger_security_response()` currently logs and prints an actionable checklist. It can be extended to integrate with notification systems (email, PagerDuty), or policy-driven quarantine actions.

---

## Extending and testing

Suggested additions and improvements:
- Authentication / Authorization: add API keys, JWT, or mTLS for the HTTP API.
- Persistent storage for reports & decisions: a database, or append-only audit store, rather than relying on logs and in-memory lists.
- Monitoring/metrics: expose Prometheus metrics (counters/gauges) for decisions, alerts, and signature failures.
- Event-driven integrations: trigger external incident management when decision is `COMPROMISED`.
- Tests: add unit tests for:
  - `ConsensusEngine.apply_consensus()` (cover all vote patterns and quorum edge cases).
  - `CryptoUtils.sign_data()` / `verify_signature()` round-trip using generated keys.
  - `Baseline.save()`/`load()` for atomicity.
  - Flask endpoints using `app.test_client()` to validate request/response flows and error handling.
- CI: linting (flake8/pylint), unit test runs, and packaging checks.

Testing hints:
- Use the `CryptoUtils.generate_keypair()` to create ephemeral keys for test monitors, sign sample reports using `sign_data()` and then verify end-to-end using the Flask test client.
- Simulate quorum by posting a sequence of reports with varying `result` fields to `POST /attest` and assert the returned consensus result.

---

## Security considerations & operational guidance

- Protect private key files (`keys/*.priv`) with tight filesystem permissions and consider using a hardware or cloud-backed key management system (HSM/KMS) in production.
- Ensure `config.yaml` and `data/baseline.json` are readable only by the service account and backed up.
- Audit logs may contain sensitive information (hash prefixes, monitor IDs). Ensure logs are forwarded to a protected logging pipeline and access-controlled.
- Consider enforcing TLS for the Flask server (via a reverse proxy like nginx or using `gunicorn` with certificates) when exposing the API over untrusted networks.
- When `require_signatures` is `true`, the control node will refuse unsigned or invalidly signed reports. Make sure monitors sign using the exact canonical format expected by `SignatureVerifier`.

---

## Troubleshooting (common issues)

- Missing config file error
  - Symptom: `FileNotFoundError` on startup referencing `config.yaml`.
  - Fix: Ensure `control_node/config.yaml` exists and is properly formatted YAML.

- Signature verification failures
  - Symptom: Incoming reports rejected with 403; `signature_failures` increments.
  - Common causes:
    - Public key path in `config.yaml` is incorrect or points to the wrong file.
    - Monitor signed a differently-ordered canonical string (ensure consistent `monitor_id|timestamp|kernel_hash|result` format).
    - Timezone or timestamp formatting differences.
    - File permissions prevent reading public key.
  - Fix: Verify public keys and signing code match the expected canonical format.

- Baseline file corruption
  - Symptom: Warning printed when loading baseline; baseline not restored.
  - Fix: Verify `data/baseline.json` is valid JSON; use backups if available.

- Flask server not reachable
  - Symptom: Server not binding or connection refused.
  - Fix: Validate `server.host` and `server.port` in `config.yaml` and check firewall rules. If running under systemd, check logs for `notify` socket or permission issues.

---

## Quick developer reference (where to make changes)

- Change API behavior or endpoints: `control_node.py`
- Change data model shapes or persistence policies: `models.py`
- Modify consensus rules: `consensus.py`
- Update signature/key handling: `crypto_utils.py`
- Change configuration schema or defaults: `config.py` and `config.yaml`
- Look at logging formats and rotation settings: `audit_logger.py`
- Improve operator prompts: `user_interaction.py`
- Update packaging/installation steps: `install.sh` and `requirements.txt`

---

If you want, I can:
- Generate a `doceumentation.md` file with more diagrams (sequence or flowcharts) or an OpenAPI spec and example client code for all endpoints.
- Produce unit test scaffolding for the consensus logic and API endpoints.
- Create a systemd service file and a production deployment recipe (gunicorn + nginx + TLS).
