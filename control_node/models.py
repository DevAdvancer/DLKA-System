from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional, List
import json
import os

@dataclass
class AttestationReport:
    """
    Attestation report from a monitor node

    Attributes:
        monitor_id: Unique identifier for monitor (1, 2, or 3)
        timestamp: ISO-8601 timestamp when measurement was taken
        kernel_hash: SHA256 hash of kernel (64 hex characters)
        result: 'OK' (match), 'ALERT' (mismatch), or 'ERROR'
        signature: ECDSA signature (base64-encoded)
        baseline_hash: Optional baseline hash monitor was comparing against
        message: Optional human-readable message
    """
    monitor_id: int
    timestamp: str
    kernel_hash: str
    result: str  # 'OK', 'ALERT', 'ERROR'
    signature: str
    baseline_hash: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        """Create from dictionary"""
        return cls(**data)

    def __repr__(self):
        return f"Report(monitor={self.monitor_id}, result={self.result}, hash={self.kernel_hash[:16]}...)"


@dataclass
class ConsensusDecision:
    """
    Result of consensus voting

    Attributes:
        decision: Final decision ('TRUSTED', 'COMPROMISED', 'UNCERTAIN')
        timestamp: When consensus was reached
        reports: List of attestation reports that were voted on
        quorum_met: Whether minimum number of reports were received
        vote_counts: Dictionary of vote counts (e.g., {'OK': 2, 'ALERT': 1})
        user_action: What user decided ('approve', 'reject', 'ignore')
        notes: Additional information about the decision
    """
    decision: str  # 'TRUSTED', 'COMPROMISED', 'UNCERTAIN'
    timestamp: str
    reports: List[AttestationReport]
    quorum_met: bool
    vote_counts: dict
    user_action: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self):
        """Convert to dictionary (suitable for JSON)"""
        return {
            'decision': self.decision,
            'timestamp': self.timestamp,
            'quorum_met': self.quorum_met,
            'vote_counts': self.vote_counts,
            'reports': [r.to_dict() for r in self.reports],
            'user_action': self.user_action,
            'notes': self.notes
        }

    def __repr__(self):
        return f"Consensus(decision={self.decision}, votes={self.vote_counts}, quorum={self.quorum_met})"


@dataclass
class Baseline:
    """
    Kernel baseline hash (the "trusted" reference)

    Attributes:
        hash_value: SHA256 hash of trusted kernel state
        timestamp: When baseline was established/updated
        approved_by: Who approved this baseline
        previous_hash: Previous baseline (for audit trail)
        version: Kernel version this baseline corresponds to
    """
    hash_value: str
    timestamp: str
    approved_by: str
    previous_hash: Optional[str] = None
    version: Optional[str] = None

    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        """Create from dictionary"""
        return cls(**data)

    def save(self, filepath):
        """
        Save baseline to JSON file

        Creates directory if it doesn't exist.
        Atomically writes file to prevent corruption.
        """
        # Create directory if needed
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Write to temporary file first (atomic write)
        temp_path = filepath + '.tmp'
        with open(temp_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

        # Rename (atomic operation on POSIX systems)
        os.replace(temp_path, filepath)

    @classmethod
    def load(cls, filepath):
        """
        Load baseline from JSON file

        Returns:
            Baseline object if file exists, None otherwise
        """
        if not os.path.exists(filepath):
            return None

        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Warning: Could not load baseline from {filepath}: {e}")
            return None

    def __repr__(self):
        return f"Baseline(hash={self.hash_value[:16]}..., approved_by={self.approved_by})"


@dataclass
class SystemStatistics:
    """
    System statistics for monitoring
    """
    total_measurements: int = 0
    trusted_decisions: int = 0
    compromised_decisions: int = 0
    uncertain_decisions: int = 0
    total_alerts: int = 0
    baseline_updates: int = 0
    signature_failures: int = 0
    uptime_seconds: float = 0
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return asdict(self)
