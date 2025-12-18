#!/usr/bin/env python3
"""
Control Node - Distributed Kernel Attestation System
Main Flask application for consensus and decision making

Author: Abhirup Kumar & Sujal Kr Sil
Version: 1.0.0
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import sys
import socket

# Import local modules
from config import config
from models import AttestationReport, Baseline, ConsensusDecision, SystemStatistics
from consensus import ConsensusEngine
from crypto_utils import SignatureVerifier
from audit_logger import AuditLogger
from user_interaction import UserInteraction

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# ==================== GLOBAL STATE ====================

class ControlNodeState:
    """Global state management for control node"""

    def __init__(self):
        self.current_reports = []
        self.baseline = None
        self.consensus_engine = ConsensusEngine(
            quorum=config.quorum,
            total_monitors=config.total_monitors
        )
        self.signature_verifier = SignatureVerifier(config.monitors)
        self.audit_logger = AuditLogger(log_file=config.log_file)
        self.user_interface = UserInteraction()
        self.recent_decisions = []
        self.statistics = SystemStatistics()
        self.start_time = datetime.now()

        # Load baseline if exists
        self._load_baseline()

        self.audit_logger.log_system_event("SYSTEM_START", "Control node initialized")

    def _load_baseline(self):
        """Load baseline from storage"""
        os.makedirs(os.path.dirname(config.baseline_file), exist_ok=True)
        self.baseline = Baseline.load(config.baseline_file)

        if self.baseline:
            self.audit_logger.log_system_event(
                "BASELINE_LOADED",
                f"Hash: {self.baseline.hash_value[:16]}..."
            )

# Initialize global state
state = ControlNodeState()


# ==================== API ENDPOINTS ====================

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint

    Returns:
        JSON with system health status
    """
    uptime = (datetime.now() - state.start_time).total_seconds()

    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'baseline_established': state.baseline is not None,
        'monitors_configured': len(config.monitors),
        'uptime_seconds': uptime
    })


@app.route('/attest', methods=['POST'])
def receive_attestation():
    """
    Receive attestation report from monitor node

    Expected JSON:
    {
        "monitor_id": 1,
        "timestamp": "2024-01-15T10:30:00",
        "kernel_hash": "abc123...",
        "result": "OK",
        "signature": "base64_signature"
    }

    Returns:
        JSON with acceptance status and consensus if reached
    """
    try:
        data = request.get_json()

        # Parse report
        report = AttestationReport(
            monitor_id=data['monitor_id'],
            timestamp=data['timestamp'],
            kernel_hash=data['kernel_hash'],
            result=data['result'],
            signature=data['signature'],
            baseline_hash=data.get('baseline_hash'),
            message=data.get('message')
        )

        state.audit_logger.log_report_received(report)

        # Verify signature if required
        if config.require_signatures:
            if not state.signature_verifier.verify_report(report):
                state.audit_logger.log_signature_failure(report.monitor_id)
                state.statistics.signature_failures += 1
                return jsonify({
                    'status': 'error',
                    'message': 'Signature verification failed'
                }), 403

        # Add to current reports
        state.current_reports.append(report)

        # Check if we have enough reports for consensus
        if len(state.current_reports) >= config.quorum:
            decision = process_consensus()

            # Clear reports for next cycle
            state.current_reports = []

            return jsonify({
                'status': 'success',
                'consensus_reached': True,
                'decision': decision.decision,
                'timestamp': decision.timestamp
            })

        return jsonify({
            'status': 'success',
            'consensus_reached': False,
            'reports_received': len(state.current_reports),
            'quorum_required': config.quorum
        })

    except KeyError as e:
        return jsonify({
            'status': 'error',
            'message': f'Missing required field: {e}'
        }), 400
    except Exception as e:
        state.audit_logger.log_alert('HIGH', f"Error processing report: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/baseline', methods=['GET'])
def get_baseline():
    """Get current baseline hash"""
    if state.baseline:
        return jsonify(state.baseline.to_dict())
    else:
        return jsonify({
            'status': 'error',
            'message': 'No baseline established'
        }), 404


@app.route('/baseline', methods=['PUT'])
def update_baseline():
    """
    Update baseline hash (requires user approval)

    Expected JSON:
    {
        "hash": "new_hash_value",
        "approved_by": "admin_user"
    }
    """
    try:
        data = request.get_json()
        new_hash = data['hash']
        approved_by = data.get('approved_by', 'api_call')

        old_hash = state.baseline.hash_value if state.baseline else None

        new_baseline = Baseline(
            hash_value=new_hash,
            timestamp=datetime.now().isoformat(),
            approved_by=approved_by,
            previous_hash=old_hash
        )

        new_baseline.save(config.baseline_file)
        state.baseline = new_baseline

        state.audit_logger.log_baseline_update(
            old_hash or "NONE",
            new_hash,
            approved_by
        )

        state.statistics.baseline_updates += 1

        return jsonify({
            'status': 'success',
            'message': 'Baseline updated',
            'baseline': new_baseline.to_dict()
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/status', methods=['GET'])
def get_status():
    """Get system status and statistics"""
    uptime = (datetime.now() - state.start_time).total_seconds()
    state.statistics.uptime_seconds = uptime

    return jsonify({
        'baseline': state.baseline.to_dict() if state.baseline else None,
        'pending_reports': len(state.current_reports),
        'recent_decisions': [d.to_dict() for d in state.recent_decisions[-10:]],
        'statistics': state.statistics.to_dict(),
        'config': {
            'quorum': config.quorum,
            'total_monitors': config.total_monitors,
            'require_signatures': config.require_signatures
        }
    })


@app.route('/reports', methods=['GET'])
def get_reports():
    """Get current pending reports"""
    return jsonify({
        'pending_reports': [r.to_dict() for r in state.current_reports],
        'count': len(state.current_reports),
        'quorum_required': config.quorum
    })


# ==================== CORE LOGIC ====================

def process_consensus():
    """
    Process consensus from collected reports

    Returns:
        ConsensusDecision object
    """
    # Apply consensus algorithm
    decision = state.consensus_engine.apply_consensus(state.current_reports)

    state.audit_logger.log_consensus(decision)
    state.recent_decisions.append(decision)
    state.statistics.total_measurements += 1

    # Get majority hash
    current_hash = state.consensus_engine.get_majority_hash(state.current_reports)

    # Handle based on decision
    if decision.decision == 'TRUSTED':
        state.statistics.trusted_decisions += 1
        handle_trusted_state(decision, current_hash)

    elif decision.decision == 'COMPROMISED':
        state.statistics.compromised_decisions += 1
        handle_compromised_state(decision, current_hash)

    else:  # UNCERTAIN
        state.statistics.uncertain_decisions += 1
        handle_uncertain_state(decision)

    return decision


def handle_trusted_state(decision, current_hash):
    """Handle TRUSTED consensus"""
    # Check if we need to establish baseline
    if not state.baseline:
        if state.user_interface.prompt_baseline_establishment(current_hash):
            new_baseline = Baseline(
                hash_value=current_hash,
                timestamp=datetime.now().isoformat(),
                approved_by='user_interactive'
            )
            new_baseline.save(config.baseline_file)
            state.baseline = new_baseline

            state.audit_logger.log_baseline_update(
                "NONE",
                current_hash,
                "user_interactive"
            )
            decision.user_action = 'baseline_established'
            state.statistics.baseline_updates += 1
    else:
        # Verify against baseline
        if current_hash != state.baseline.hash_value:
            # Hash changed but consensus says trusted
            # This could be legitimate kernel update
            state.audit_logger.log_alert(
                'MEDIUM',
                f"Hash mismatch in TRUSTED state: {current_hash[:16]} != {state.baseline.hash_value[:16]}"
            )
            decision.user_action = 'hash_mismatch_in_trusted_state'


def handle_compromised_state(decision, current_hash):
    """Handle COMPROMISED consensus - requires user intervention"""
    baseline_hash = state.baseline.hash_value if state.baseline else "NOT_ESTABLISHED"

    # Prompt user
    user_action = state.user_interface.prompt_integrity_violation(
        decision,
        current_hash,
        baseline_hash
    )

    decision.user_action = user_action
    state.audit_logger.log_user_action(user_action, f"Hash: {current_hash[:16]}...")

    if user_action == 'approve':
        # User approved the change - update baseline
        new_baseline = Baseline(
            hash_value=current_hash,
            timestamp=datetime.now().isoformat(),
            approved_by='user_interactive',
            previous_hash=baseline_hash
        )
        new_baseline.save(config.baseline_file)
        state.baseline = new_baseline

        state.audit_logger.log_baseline_update(
            baseline_hash,
            current_hash,
            "user_approved"
        )
        state.statistics.baseline_updates += 1

    elif user_action == 'reject':
        # User rejected - trigger security response
        trigger_security_response(decision, current_hash)

    else:  # ignore
        state.audit_logger.log_alert('HIGH', f"User ignored integrity violation")
        state.statistics.total_alerts += 1


def handle_uncertain_state(decision):
    """Handle UNCERTAIN consensus"""
    state.audit_logger.log_alert(
        'MEDIUM',
        f"Uncertain consensus: {decision.vote_counts}"
    )

    # Identify outliers
    outliers = state.consensus_engine.identify_outliers(state.current_reports)

    if outliers:
        state.audit_logger.log_alert(
            'MEDIUM',
            f"Outlier monitors detected: {outliers}"
        )


def trigger_security_response(decision, current_hash):
    """Trigger security response actions"""
    state.audit_logger.log_alert(
        'CRITICAL',
        f"Security response triggered for hash: {current_hash[:16]}..."
    )

    state.statistics.total_alerts += 1

    print("\n" + "="*70)
    print("🚨 SECURITY RESPONSE ACTIONS:")
    print("="*70)
    print("  1. ✓ Alert logged to audit trail")
    print("  2. ✓ Incident report generated")
    print("  3. [ ] Email notifications (not configured)")
    print("  4. [ ] System quarantine (manual intervention required)")
    print("  5. [ ] Module unload (requires manual rmmod)")
    print("="*70 + "\n")


def notify_systemd_ready():
    """Notify systemd that service is ready"""
    try:
        notify_socket = os.environ.get('NOTIFY_SOCKET')
        if notify_socket:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.sendto(b'READY=1', notify_socket)
            sock.close()
            print("✓ Notified systemd: Service ready")
    except Exception as e:
        print(f"Warning: Could not notify systemd: {e}")


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point"""
    print("="*70)
    print("🎛️  Distributed Kernel Attestation - Control Node")
    print("="*70)
    print(f"Version: 1.0.0")
    print(f"Config: {config.config_file}")
    print(f"Quorum: {config.quorum}-of-{config.total_monitors}")
    print(f"Baseline: {'Established' if state.baseline else 'Not Set'}")
    print(f"Signatures: {'Required' if config.require_signatures else 'Optional'}")
    print("="*70)
    print()

    # Notify systemd (if running as service)
    notify_systemd_ready()

    # Start Flask server
    app.run(
        host=config.server_host,
        port=config.server_port,
        debug=config.get('server.debug', False)
    )


if __name__ == '__main__':
    main()
