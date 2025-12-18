from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import base64
import os

class CryptoUtils:
    """Cryptographic utility functions"""

    @staticmethod
    def generate_keypair():
        """
        Generate ECDSA keypair for monitor nodes

        Returns:
            Tuple of (private_key_pem, public_key_pem)

        Usage:
            priv, pub = CryptoUtils.generate_keypair()
            with open('monitor1.priv', 'wb') as f:
                f.write(priv)
        """
        # Use NIST P-256 curve (secp256r1)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def sign_data(private_key_pem: bytes, data: str) -> str:
        """
        Sign data with ECDSA private key

        Args:
            private_key_pem: Private key in PEM format
            data: String to sign

        Returns:
            Base64-encoded signature
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        signature = private_key.sign(
            data.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )

        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(public_key_pem: bytes, data: str, signature_b64: str) -> bool:
        """
        Verify ECDSA signature

        Args:
            public_key_pem: Public key in PEM format
            data: Original data that was signed
            signature_b64: Base64-encoded signature

        Returns:
            True if signature is valid, False otherwise

        Example:
            valid = CryptoUtils.verify_signature(
                pub_key,
                "monitor_id|timestamp|hash|result",
                "MEUCIQDx7+9kZX..."
            )
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)

            public_key.verify(
                signature,
                data.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True

        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False

    @staticmethod
    def load_public_key(filepath: str) -> bytes:
        """
        Load public key from PEM file

        Args:
            filepath: Path to .pub file

        Returns:
            Public key in PEM format (bytes)

        Raises:
            FileNotFoundError if key file doesn't exist
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Public key not found: {filepath}")

        with open(filepath, 'rb') as f:
            return f.read()


class SignatureVerifier:
    """
    Verifies monitor node signatures

    Loads public keys for all monitors during initialization
    and provides a simple interface for report verification.
    """

    def __init__(self, monitors_config):
        """
        Initialize signature verifier

        Args:
            monitors_config: List of monitor configurations from config.yaml
                Each entry should have 'id' and 'public_key_path'
        """
        self.public_keys = {}

        for monitor in monitors_config:
            monitor_id = monitor['id']
            key_path = monitor['public_key_path']

            try:
                self.public_keys[monitor_id] = CryptoUtils.load_public_key(key_path)
                print(f"✓ Loaded public key for Monitor {monitor_id}")
            except Exception as e:
                print(f"✗ Failed to load key for Monitor {monitor_id}: {e}")

    def verify_report(self, report: 'AttestationReport') -> bool:
        """
        Verify a monitor's attestation report signature

        Args:
            report: AttestationReport object

        Returns:
            True if signature is valid, False otherwise

        Process:
        1. Check if we have public key for this monitor
        2. Reconstruct the signed data (monitor_id|timestamp|hash|result)
        3. Verify signature using monitor's public key
        """
        if report.monitor_id not in self.public_keys:
            print(f"⚠ No public key for Monitor {report.monitor_id}")
            return False

        # Reconstruct signed data (must match what monitor signed)
        signed_data = f"{report.monitor_id}|{report.timestamp}|{report.kernel_hash}|{report.result}"

        public_key = self.public_keys[report.monitor_id]

        return CryptoUtils.verify_signature(
            public_key,
            signed_data,
            report.signature
        )
