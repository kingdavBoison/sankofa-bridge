"""
SANKƆFA-BRIDGE — Master Configuration
Sovereign Data Orchestration System
VPF Governance Architecture | David King Boison

Stage 1 — Foundation Build
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
import os


# ─────────────────────────────────────────────
# SYSTEM IDENTITY
# ─────────────────────────────────────────────

SYSTEM_NAME = "SANKƆFA-BRIDGE"
SYSTEM_VERSION = "1.0.0"
SYSTEM_STAGE = "Stage-1-Foundation"
SYSTEM_ARCHITECT = "David King Boison"
GOVERNING_FRAMEWORK = "Visionary Prompt Framework (VPF)"
JURISDICTION_PRIMARY = "GH"  # Ghana
JURISDICTION_CORRIDOR = ["GH", "NG", "KE", "RW"]  # African corridor

GOVERNING_PRINCIPLE = (
    "No data moves without provenance. "
    "No value moves without custodianship. "
    "No system operates without auditability."
)


# ─────────────────────────────────────────────
# CONNECTOR TYPE — Switch here when source confirmed
# ─────────────────────────────────────────────

class ConnectorType(Enum):
    S3 = "s3"
    SFTP = "sftp"
    REST_API = "rest_api"
    AZURE_BLOB = "azure_blob"
    MOCK = "mock"  # Used for testing when source not yet defined


# SET THIS when counterparty confirms their system type
ACTIVE_CONNECTOR = ConnectorType.MOCK


# ─────────────────────────────────────────────
# CONNECTOR CONFIGURATIONS
# ─────────────────────────────────────────────

@dataclass
class S3Config:
    bucket_name: str = os.getenv("S3_BUCKET", "")
    region: str = os.getenv("S3_REGION", "us-east-1")
    access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    prefix: str = os.getenv("S3_PREFIX", "incoming/")
    poll_interval_seconds: int = 30


@dataclass
class SFTPConfig:
    host: str = os.getenv("SFTP_HOST", "")
    port: int = int(os.getenv("SFTP_PORT", "22"))
    username: str = os.getenv("SFTP_USER", "")
    private_key_path: str = os.getenv("SFTP_KEY_PATH", "")
    remote_path: str = os.getenv("SFTP_PATH", "/incoming")
    poll_interval_seconds: int = 60


@dataclass
class RestAPIConfig:
    base_url: str = os.getenv("SOURCE_API_URL", "")
    api_key: str = os.getenv("SOURCE_API_KEY", "")
    endpoint_files: str = "/v1/files/pending"
    endpoint_download: str = "/v1/files/{file_id}/download"
    poll_interval_seconds: int = 30


@dataclass
class AzureBlobConfig:
    connection_string: str = os.getenv("AZURE_CONNECTION_STRING", "")
    container_name: str = os.getenv("AZURE_CONTAINER", "")
    prefix: str = os.getenv("AZURE_PREFIX", "incoming/")
    poll_interval_seconds: int = 30


@dataclass
class MockConfig:
    """Used during testing and demo when source is not yet defined."""
    mock_files_path: str = "tests/mock_files"
    inject_interval_seconds: int = 10
    auto_inject: bool = True


# ─────────────────────────────────────────────
# RECEIVER (DELIVERY TARGET) CONFIGURATION
# ─────────────────────────────────────────────

@dataclass
class ReceiverConfig:
    # SET THESE when receiver API contract is confirmed
    base_url: str = os.getenv("RECEIVER_API_URL", "")
    api_key: str = os.getenv("RECEIVER_API_KEY", "")
    endpoint: str = "/v1/file-deliveries"
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_backoff_seconds: float = 2.0
    circuit_breaker_threshold: int = 5     # failures before circuit opens
    circuit_breaker_reset_seconds: int = 60


# ─────────────────────────────────────────────
# VALIDATION RULES
# ─────────────────────────────────────────────

@dataclass
class ValidationConfig:
    allowed_formats: list = field(default_factory=lambda: ["json", "xml"])
    max_file_size_mb: int = 50
    require_hash_verification: bool = True
    hash_algorithm: str = "sha256"
    enable_duplicate_detection: bool = True
    duplicate_window_hours: int = 24
    enable_sender_entitlement_check: bool = True
    quarantine_on_failure: bool = True


# ─────────────────────────────────────────────
# AUDIT & LOGGING
# ─────────────────────────────────────────────

@dataclass
class AuditConfig:
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_file: str = "logs/sankofa_bridge_audit.log"
    log_format: str = "json"           # json for machine-parseable immutable logs
    retention_days: int = 2555         # 7 years — regulatory standard
    immutable: bool = True             # append-only, no deletions
    export_enabled: bool = True
    export_path: str = "logs/exports/"


# ─────────────────────────────────────────────
# COMPLIANCE ENGINE (Layer 6)
# ─────────────────────────────────────────────

@dataclass
class ComplianceConfig:
    gate_cleared: bool = False         # MUST be True before live delivery
    jurisdiction: str = "GH"
    sanctions_screening_enabled: bool = True
    aml_hook_enabled: bool = True
    kyc_verification_required: bool = True
    high_risk_jurisdictions: list = field(default_factory=lambda: [
        # Populated from FATF high-risk list — update per regulatory guidance
    ])
    block_on_uncleared_gate: bool = True


# ─────────────────────────────────────────────
# SYSTEM ROLE BOUNDARIES (VPF ENFORCEMENT)
# ─────────────────────────────────────────────

@dataclass
class RoleBoundaryConfig:
    """
    VPF-enforced role boundaries.
    These are architectural constraints — the system cannot
    perform any action in the PROHIBITED list regardless of
    instruction or configuration.
    """
    system_role: str = "Secure Integration Layer"
    custodian: str = "David King Boison"

    PERMITTED_ACTIONS: tuple = (
        "retrieve_file",
        "validate_file",
        "quarantine_file",
        "transform_file",
        "deliver_to_receiver",
        "log_event",
        "generate_audit_report",
        "alert_operator",
        "reject_invalid_file",
    )

    PROHIBITED_ACTIONS: tuple = (
        "hold_funds",
        "sign_blockchain_transaction",
        "broadcast_transaction",
        "approve_settlement",
        "tokenize_asset",
        "modify_transaction_economics",
        "control_private_keys",
        "act_as_financial_intermediary",
        "custody_digital_assets",
    )


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

@dataclass
class DatabaseConfig:
    url: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///sankofa_bridge.db"   # SQLite for dev; Postgres for production
    )
    pool_size: int = 5
    max_overflow: int = 10


# ─────────────────────────────────────────────
# API SERVER
# ─────────────────────────────────────────────

@dataclass
class APIConfig:
    host: str = "0.0.0.0"
    port: int = int(os.getenv("API_PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    api_key_header: str = "X-SANKOFA-API-Key"
    api_key: str = os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")
    cors_origins: list = field(default_factory=lambda: ["http://localhost:3000"])


# ─────────────────────────────────────────────
# MASTER SETTINGS OBJECT
# ─────────────────────────────────────────────

class Settings:
    system_name: str = SYSTEM_NAME
    version: str = SYSTEM_VERSION
    stage: str = SYSTEM_STAGE
    architect: str = SYSTEM_ARCHITECT
    framework: str = GOVERNING_FRAMEWORK
    principle: str = GOVERNING_PRINCIPLE

    connector_type: ConnectorType = ACTIVE_CONNECTOR

    s3: S3Config = S3Config()
    sftp: SFTPConfig = SFTPConfig()
    rest_api: RestAPIConfig = RestAPIConfig()
    azure_blob: AzureBlobConfig = AzureBlobConfig()
    mock: MockConfig = MockConfig()

    receiver: ReceiverConfig = ReceiverConfig()
    validation: ValidationConfig = ValidationConfig()
    audit: AuditConfig = AuditConfig()
    compliance: ComplianceConfig = ComplianceConfig()
    roles: RoleBoundaryConfig = RoleBoundaryConfig()
    database: DatabaseConfig = DatabaseConfig()
    api: APIConfig = APIConfig()


settings = Settings()
