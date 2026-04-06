"""
SANKƆFA-BRIDGE — Secrets Manager
Stage 2 Hardening

Handles all credentials and sensitive configuration.
Never exposes raw secrets in logs, stack traces, or API responses.

Layers:
  1. Environment variables (.env file, never committed to source control)
  2. Encrypted secrets store (local for Stage 2, Vault/AWS SSM in Stage 5)
  3. Runtime secret masking — any string loaded here is masked in logs

VPF Principle: No system operates without auditability —
               but credentials are never part of that audit trail.
"""

import os
import base64
import hashlib
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load .env on import
load_dotenv(Path(__file__).parent.parent / ".env")


class SecretValue:
    """
    Wraps a secret string so it is never accidentally logged or printed.
    Use .reveal() only at the exact point of use.
    """
    def __init__(self, value: str, name: str = "SECRET"):
        self._value = value
        self._name = name

    def reveal(self) -> str:
        return self._value

    def __repr__(self):
        return f"<SecretValue name={self._name} value=***MASKED***>"

    def __str__(self):
        return f"***MASKED:{self._name}***"

    def __bool__(self):
        return bool(self._value)


class SecretsManager:
    """
    Centralized secrets manager.

    Stage 2: Environment variables + local encrypted store.
    Stage 5: Drop-in replacement with HashiCorp Vault or AWS SSM.

    All secrets are wrapped in SecretValue — never raw strings.
    """

    _instance = None
    _secrets: dict = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._secrets = {}
        self._encryption_key = self._derive_key()
        self._load_from_env()
        self._initialized = True

    def _derive_key(self) -> bytes:
        """
        Derive encryption key from system entropy.
        In production: use a proper KMS or Vault-managed key.
        """
        seed = os.getenv("SANKOFA_SECRET_SEED", "sankofa-bridge-dev-seed-replace-in-production")
        return base64.urlsafe_b64encode(
            hashlib.sha256(seed.encode()).digest()
        )

    def _fernet(self) -> Fernet:
        return Fernet(self._encryption_key)

    def _load_from_env(self):
        """Load all expected secrets from environment."""
        secret_keys = [
            "SANKOFA_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "SFTP_PRIVATE_KEY",
            "SOURCE_API_KEY",
            "RECEIVER_API_KEY",
            "AZURE_CONNECTION_STRING",
            "DATABASE_URL",
            "SANKOFA_SECRET_SEED",
        ]
        for key in secret_keys:
            val = os.getenv(key, "")
            if val:
                self._secrets[key] = SecretValue(val, key)

    def get(self, key: str, default: str = "") -> SecretValue:
        """Retrieve a secret by name."""
        if key in self._secrets:
            return self._secrets[key]
        val = os.getenv(key, default)
        return SecretValue(val, key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a value for storage."""
        return self._fernet().encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a stored value."""
        return self._fernet().decrypt(ciphertext.encode()).decode()

    def mask(self, value: str, visible_chars: int = 4) -> str:
        """Mask a secret for safe display in logs or UI."""
        if not value or len(value) <= visible_chars:
            return "***"
        return value[:visible_chars] + "***" + value[-2:]

    def rotate_api_key(self) -> str:
        """Generate a new API key."""
        import secrets
        new_key = f"skb_{secrets.token_urlsafe(32)}"
        self._secrets["SANKOFA_API_KEY"] = SecretValue(new_key, "SANKOFA_API_KEY")
        return new_key

    def validate_required_secrets(self, connector_type: str) -> tuple[bool, list]:
        """
        Check that all secrets required for the active connector are present.
        Returns (all_present, list_of_missing).
        """
        requirements = {
            "s3": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
            "sftp": ["SFTP_PRIVATE_KEY"],
            "rest_api": ["SOURCE_API_KEY"],
            "azure_blob": ["AZURE_CONNECTION_STRING"],
            "mock": [],
        }
        required = requirements.get(connector_type, [])
        missing = [k for k in required if not self.get(k)]
        return (len(missing) == 0, missing)


# Singleton
secrets_manager = SecretsManager()
