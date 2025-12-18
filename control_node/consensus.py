from typing import List, Dict
from collections import Counter
from models import AttestationReport, ConsensusDecision
from datetime import datetime

class ConsensusEngine:
    """
    Implements 2-of-3 majority voting for kernel attestation

    Design Philosophy:
    - Trust the majority: If 2+ nodes agree, accept their verdict
    - Tolerate 1 faulty node: System remains secure even if 1 monitor compromised
    - Explicit quorum: Require minimum votes before making decision

    Voting Rules:
    1. If ≥2 nodes report 'OK' → Decision: TRUSTED
    2. If ≥2 nodes report 'ALERT' → Decision: COMPROMISED
    3. Otherwise → Decision: UNCERTAIN (investigate)
    """

    def __init__(self, quorum: int = 2, total_monitors: int = 3):
        """
        Initialize consensus engine

        Args:
            quorum: Minimum votes needed for decision (default: 2)
            total_monitors: Total number of monitor nodes (default: 3)
        """
        self.quorum = quorum
        self.total_monitors = total_monitors

        # Validate configuration
        if quorum > total_monitors:
            raise ValueError(f"Quorum ({quorum}) cannot exceed total monitors ({total_monitors})")

        if quorum < 1:
            raise ValueError(f"Quorum must be at least 1")

    def apply_consensus(self, reports: List[AttestationReport]) -> ConsensusDecision:
        """
        Apply consensus algorithm to attestation reports

        Args:
            reports: List of attestation reports from monitor nodes

        Returns:
            ConsensusDecision object with final verdict

        Example:
            reports = [
                Report(monitor=1, result='OK'),
                Report(monitor=2, result='OK'),
                Report(monitor=3, result='ALERT')
            ]
            decision = engine.apply_consensus(reports)
            # decision.decision == 'TRUSTED' (2 OK votes)
        """

        # Count votes
        results = [r.result for r in reports]
        vote_counts = dict(Counter(results))

        ok_count = vote_counts.get('OK', 0)
        alert_count = vote_counts.get('ALERT', 0)
        error_count = vote_counts.get('ERROR', 0)

        # Apply voting rules
        if ok_count >= self.quorum:
            decision = 'TRUSTED'
            notes = f"{ok_count} monitors report kernel is trusted"
        elif alert_count >= self.quorum:
            decision = 'COMPROMISED'
            notes = f"{alert_count} monitors detected integrity violation"
        else:
            decision = 'UNCERTAIN'
            notes = f"Split vote: OK={ok_count}, ALERT={alert_count}, ERROR={error_count}"

        # Check if quorum was met
        quorum_met = len(reports) >= self.quorum

        if not quorum_met:
            notes += f" | WARNING: Quorum not met ({len(reports)}/{self.quorum})"

        return ConsensusDecision(
            decision=decision,
            timestamp=datetime.now().isoformat(),
            reports=reports,
            quorum_met=quorum_met,
            vote_counts=vote_counts,
            notes=notes
        )

    def check_hash_consistency(self, reports: List[AttestationReport]) -> bool:
        """
        Check if all monitors report the same hash

        Args:
            reports: List of attestation reports

        Returns:
            True if all hashes match, False otherwise

        Note:
            Only checks reports with result='OK'
            (ALERT reports may have different hashes)
        """
        hashes = set(r.kernel_hash for r in reports if r.result == 'OK')
        return len(hashes) <= 1

    def get_majority_hash(self, reports: List[AttestationReport]) -> str:
        """
        Get the hash reported by majority of nodes

        Args:
            reports: List of attestation reports

        Returns:
            Most common hash value, or None if no reports

        Example:
            reports = [
                Report(hash="abc123"),
                Report(hash="abc123"),
                Report(hash="def456")
            ]
            majority = engine.get_majority_hash(reports)
            # majority == "abc123"
        """
        hashes = [r.kernel_hash for r in reports if r.result != 'ERROR']

        if not hashes:
            return None

        hash_counts = Counter(hashes)
        return hash_counts.most_common(1)[0][0]

    def identify_outliers(self, reports: List[AttestationReport]) -> List[int]:
        """
        Identify monitor nodes reporting different results from majority

        Useful for detecting:
        - Compromised monitors
        - Network issues
        - Configuration problems

        Args:
            reports: List of attestation reports

        Returns:
            List of monitor IDs that disagree with majority

        Example:
            reports = [
                Report(monitor=1, result='OK'),
                Report(monitor=2, result='OK'),
                Report(monitor=3, result='ALERT')  ← Outlier
            ]
            outliers = engine.identify_outliers(reports)
            # outliers == [3]
        """
        if not reports:
            return []

        # Get majority result
        results = [r.result for r in reports]
        majority_result = Counter(results).most_common(1)[0][0]

        # Find monitors that disagree
        outliers = [r.monitor_id for r in reports if r.result != majority_result]

        return outliers

    def get_decision_summary(self, decision: ConsensusDecision) -> str:
        """
        Get human-readable summary of consensus decision

        Args:
            decision: ConsensusDecision object

        Returns:
            Formatted string describing the decision
        """
        summary = f"""
Consensus Decision: {decision.decision}
Timestamp: {decision.timestamp}
Quorum Met: {decision.quorum_met}
Vote Breakdown: {decision.vote_counts}
Notes: {decision.notes}
"""
        return summary.strip()
