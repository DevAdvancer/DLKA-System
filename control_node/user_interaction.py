import sys
from colorama import Fore, Style, init
from tabulate import tabulate
from datetime import datetime

init(autoreset=True)

class UserInteraction:
    """
    Handle user prompts and approvals

    Displays detailed information about integrity violations
    and collects user decisions.
    """

    @staticmethod
    def prompt_integrity_violation(decision, current_hash, baseline_hash):
        """
        Display integrity violation and prompt user

        Args:
            decision: ConsensusDecision object
            current_hash: Current measured hash
            baseline_hash: Expected baseline hash

        Returns:
            'approve', 'reject', or 'ignore'
        """
        print("\n" + "="*70)
        print(Fore.RED + Style.BRIGHT + "⚠️  KERNEL INTEGRITY VIOLATION DETECTED")
        print("="*70 + "\n")

        print(Fore.YELLOW + "Consensus Decision: " + Fore.RED + decision.decision)
        print(Fore.YELLOW + f"Timestamp: {decision.timestamp}")
        print(Fore.YELLOW + f"Quorum Met: {decision.quorum_met}\n")

        # Vote breakdown table
        vote_table = [["Result", "Count"]]
        for result, count in decision.vote_counts.items():
            vote_table.append([result, count])

        print(Fore.CYAN + "Vote Breakdown:")
        print(tabulate(vote_table, headers='firstrow', tablefmt='grid'))
        print()

        # Hash comparison
        print(Fore.CYAN + "Hash Comparison:")
        print(f"  Expected (Baseline): {Fore.GREEN}{baseline_hash}")
        print(f"  Current (Measured):  {Fore.RED}{current_hash}")
        print()

        # Monitor reports table
        report_table = [["Monitor ID", "Result", "Hash (first 16 chars)", "Timestamp"]]
        for report in decision.reports:
            color = Fore.GREEN if report.result == 'OK' else Fore.RED
            report_table.append([
                report.monitor_id,
                color + report.result,
                report.kernel_hash[:16] + "...",
                report.timestamp.split('T')[1][:8]  # Just time part
            ])

        print(Fore.CYAN + "Individual Monitor Reports:")
        print(tabulate(report_table, headers='firstrow', tablefmt='grid'))
        print()

        # Possible causes
        print(Fore.YELLOW + "Possible Causes:")
        print("  1. Legitimate kernel update/upgrade")
        print("  2. Driver or module installation")
        print("  3. " + Fore.RED + "Rootkit or malware infection")
        print("  4. " + Fore.RED + "Unauthorized system modification")
        print()

        # Action prompt
        print(Fore.YELLOW + "Available Actions:")
        print("  [A] " + Fore.GREEN + "Approve" + Fore.RESET + " - Update baseline to new hash")
        print("      Use if this is a legitimate change (kernel update, etc.)")
        print()
        print("  [R] " + Fore.RED + "Reject" + Fore.RESET + "  - Trigger security response")
        print("      Use if this is unauthorized or suspicious")
        print()
        print("  [I] " + Fore.YELLOW + "Ignore" + Fore.RESET + "  - Log event but take no action")
        print("      Use if you want to investigate first")
        print()

        # Get user input
        while True:
            choice = input(Fore.WHITE + "Your decision [A/R/I]: ").strip().upper()

            if choice == 'A':
                confirm = input(Fore.YELLOW + "⚠️  Confirm baseline update? [yes/no]: ").strip().lower()
                if confirm == 'yes':
                    print(Fore.GREEN + "✓ Baseline will be updated to new hash")
                    return 'approve'
                else:
                    print(Fore.RED + "✗ Approval cancelled.")
                    continue

            elif choice == 'R':
                confirm = input(Fore.RED + "⚠️  Confirm security response? [yes/no]: ").strip().lower()
                if confirm == 'yes':
                    print(Fore.RED + "✓ Security response will be triggered")
                    return 'reject'
                else:
                    print(Fore.RED + "✗ Rejection cancelled.")
                    continue

            elif choice == 'I':
                print(Fore.YELLOW + "ℹ Event will be logged for investigation")
                return 'ignore'

            else:
                print(Fore.RED + "✗ Invalid choice. Please enter A, R, or I.")

    @staticmethod
    def prompt_baseline_establishment(kernel_hash):
        """
        Prompt to establish initial baseline

        Args:
            kernel_hash: Hash to potentially use as baseline

        Returns:
            True if user accepts, False otherwise
        """
        print("\n" + "="*70)
        print(Fore.CYAN + Style.BRIGHT + "📋 ESTABLISH BASELINE HASH")
        print("="*70 + "\n")

        print("No baseline hash is currently set.")
        print("This is the first measurement from the kernel.\n")

        print(Fore.YELLOW + "Kernel Hash:")
        print(f"  {Fore.GREEN}{kernel_hash}\n")

        print("By accepting this hash as the baseline, you are declaring")
        print("that the current kernel state is " + Fore.GREEN + "trusted and secure" + Fore.RESET + ".")
        print()
        print(Fore.YELLOW + "⚠️  Important: Only accept if you are confident the system is clean!")
        print()

        choice = input(Fore.WHITE + "Accept this as baseline? [yes/no]: ").strip().lower()

        if choice == 'yes':
            print(Fore.GREEN + "✓ Baseline established")
            return True
        else:
            print(Fore.RED + "✗ Baseline not set (will prompt again on next measurement)")
            return False

    @staticmethod
    def display_status(baseline, recent_decisions):
        """
        Display current system status

        Args:
            baseline: Current Baseline object (or None)
            recent_decisions: List of recent ConsensusDecision objects
        """
        print("\n" + "="*70)
        print(Fore.CYAN + Style.BRIGHT + "📊 ATTESTATION SYSTEM STATUS")
        print("="*70 + "\n")

        # Baseline status
        if baseline:
            print(Fore.GREEN + "✓ Baseline Established:")
            print(f"  Hash: {baseline.hash_value}")
            print(f"  Established: {baseline.timestamp}")
            print(f"  Approved By: {baseline.approved_by}")
            if baseline.previous_hash:
                print(f"  Previous: {baseline.previous_hash[:16]}...")
            print()
        else:
            print(Fore.RED + "✗ No Baseline Established")
            print("  Waiting for first measurement...\n")

        # Recent decisions
        if recent_decisions:
            print(Fore.CYAN + "Recent Decisions (last 5):")
            decision_table = [["Timestamp", "Decision", "Votes", "User Action"]]

            for dec in recent_decisions[-5:]:
                timestamp = dec.timestamp.split('T')[1][:8]  # Just time
                votes = f"OK:{dec.vote_counts.get('OK',0)} ALERT:{dec.vote_counts.get('ALERT',0)}"
                action = dec.user_action or 'N/A'

                decision_table.append([timestamp, dec.decision, votes, action])

            print(tabulate(decision_table, headers='firstrow', tablefmt='grid'))
        else:
            print(Fore.YELLOW + "No recent decisions\n")

        print()
