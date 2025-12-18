import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime
import json

class AuditLogger:
    """
    Structured audit logging for security events

    Features:
    - Rotating log files (prevents disk fill-up)
    - Structured format (easy parsing)
    - Multiple log levels
    - Console + file output
    """

    def __init__(self, log_file='logs/attest.log', max_bytes=100*1024*1024, backup_count=5):
        """
        Initialize audit logger

        Args:
            log_file: Path to log file
            max_bytes: Max size before rotation (default: 100MB)
            backup_count: Number of backup logs to keep
        """
        self.logger = logging.getLogger('attestation_audit')
        self.logger.setLevel(logging.INFO)

        # Create logs directory if needed
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Rotating file handler
        handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )

        # Format: timestamp | level | message
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

        # Console handler (for real-time monitoring)
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        self.logger.addHandler(console)

        self.log_system_event("AUDIT_LOGGER_INITIALIZED", f"Logging to {log_file}")

    def log_report_received(self, report):
        """Log incoming attestation report"""
        self.logger.info(
            f"REPORT_RECEIVED | Monitor={report.monitor_id} | "
            f"Result={report.result} | Hash={report.kernel_hash[:16]}..."
        )

    def log_consensus(self, decision):
        """Log consensus decision"""
        self.logger.info(
            f"CONSENSUS | Decision={decision.decision} | "
            f"Votes={decision.vote_counts} | Quorum={decision.quorum_met}"
        )

    def log_user_action(self, action, details):
        """Log user-initiated action"""
        self.logger.warning(
            f"USER_ACTION | Action={action} | Details={details}"
        )

    def log_baseline_update(self, old_hash, new_hash, approved_by):
        """Log baseline hash change"""
        self.logger.warning(
            f"BASELINE_UPDATE | Old={old_hash[:16] if old_hash else 'NONE'}... | "
            f"New={new_hash[:16]}... | By={approved_by}"
        )

    def log_alert(self, severity, message):
        """Log security alert"""
        if severity == 'CRITICAL':
            self.logger.error(f"SECURITY_ALERT | Severity={severity} | {message}")
        else:
            self.logger.warning(f"SECURITY_ALERT | Severity={severity} | {message}")

    def log_signature_failure(self, monitor_id):
        """Log signature verification failure"""
        self.logger.error(
            f"SIGNATURE_FAILURE | Monitor={monitor_id} | "
            f"Possible tampering or key mismatch"
        )

    def log_system_event(self, event_type, details):
        """Log general system event"""
        self.logger.info(f"{event_type} | {details}")

    def log_statistics(self, stats):
        """Log system statistics"""
        self.logger.info(
            f"STATISTICS | Total={stats.total_measurements} | "
            f"Trusted={stats.trusted_decisions} | "
            f"Compromised={stats.compromised_decisions} | "
            f"Alerts={stats.total_alerts}"
        )
