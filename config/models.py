"""
SANKƆFA-BRIDGE — Core Data Models
Canonical Message Object + File State Machine

Every file that enters the system is immediately converted into a
SankofaMessage — the single internal format that all layers operate on.
The source format (JSON, XML, S3 key, SFTP path) does not matter above Layer 1.

VPF Principle: No data moves without provenance.
Every SankofaMessage carries its full chain of custody.
"""

import uuid
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from dataclasses import dataclass, field


# ─────────────────────────────────────────────
# FILE STATE MACHINE
# Every file transitions through these states in order.
# No backward transitions. No skipping states.
# ─────────────────────────────────────────────

class FileState(str, Enum):
    DETECTED     = "detected"       # File found on source
    DOWNLOADING  = "downloading"    # Being retrieved
    QUARANTINED  = "quarantined"    # In quarantine zone, awaiting validation
    VALIDATING   = "validating"     # Validation in progress
    VALIDATED    = "validated"      # Passed all validation checks
    TRANSFORMING = "transforming"   # Being normalized to canonical form
    TRANSFORMED  = "transformed"    # Ready for delivery
    DELIVERING   = "delivering"     # Being sent to receiver API
    DELIVERED    = "delivered"      # Receiver acknowledged receipt
    ACKNOWLEDGED = "acknowledged"   # Full cycle complete
    FAILED       = "failed"         # Unrecoverable error — review required
    EXCEPTION    = "exception"      # Flagged for manual compliance review
    ARCHIVED     = "archived"       # Retention complete


# ─────────────────────────────────────────────
# VALIDATION RESULT
# ─────────────────────────────────────────────

class ValidationStatus(str, Enum):
    PASS    = "pass"
    FAIL    = "fail"
    WARNING = "warning"
    PENDING = "pending"


@dataclass
class ValidationResult:
    status: ValidationStatus = ValidationStatus.PENDING
    checks: Dict[str, bool] = field(default_factory=dict)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    completed_at: Optional[datetime] = None

    def add_check(self, name: str, passed: bool, message: str = ""):
        self.checks[name] = passed
        if not passed:
            self.errors.append(f"{name}: {message}")

    def add_warning(self, message: str):
        self.warnings.append(message)

    def finalize(self):
        self.completed_at = datetime.now(timezone.utc)
        if self.errors:
            self.status = ValidationStatus.FAIL
        elif self.warnings:
            self.status = ValidationStatus.WARNING
        else:
            self.status = ValidationStatus.PASS
        return self


# ─────────────────────────────────────────────
# DELIVERY RESULT
# ─────────────────────────────────────────────

@dataclass
class DeliveryResult:
    success: bool = False
    delivery_id: Optional[str] = None
    http_status: Optional[int] = None
    response_body: Optional[dict] = None
    attempts: int = 0
    delivered_at: Optional[datetime] = None
    error_message: Optional[str] = None


# ─────────────────────────────────────────────
# CHAIN OF CUSTODY ENTRY
# Every state change is recorded here.
# This is the provenance record.
# ─────────────────────────────────────────────

@dataclass
class CustodyEntry:
    timestamp: datetime
    from_state: Optional[FileState]
    to_state: FileState
    actor: str          # System layer or operator ID performing the transition
    action: str         # What was done
    notes: str = ""
    session_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "from_state": self.from_state.value if self.from_state else None,
            "to_state": self.to_state.value,
            "actor": self.actor,
            "action": self.action,
            "notes": self.notes,
            "session_id": self.session_id,
        }


# ─────────────────────────────────────────────
# SANKOFA MESSAGE — THE CANONICAL OBJECT
# This is the single internal format.
# Every file becomes one of these at Layer 1.
# ─────────────────────────────────────────────

@dataclass
class SankofaMessage:
    """
    The canonical data object for SANKƆFA-BRIDGE.

    VPF Provenance Fields: message_id, file_id, source_system,
    sender_entity_id, received_at_utc, file_hash_sha256.

    These CANNOT be None when a file is delivered. If they are,
    delivery is blocked by the compliance engine.
    """

    # ── Identity ──────────────────────────────
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    file_id: str = ""                    # Source-system-assigned ID (or generated)
    file_name: str = ""
    file_format: str = ""                # json / xml / binary

    # ── Provenance (VPF — mandatory) ──────────
    source_system: str = ""              # Which connector sourced this
    sender_entity_id: str = ""           # Registered sender identity
    receiver_entity_id: str = ""         # Registered receiver identity
    destination_system: str = ""         # Target API identifier
    received_at_utc: Optional[datetime] = None
    jurisdiction: str = "GH"
    classification: str = "restricted"

    # ── Integrity ─────────────────────────────
    file_hash_sha256: str = ""
    file_size_bytes: int = 0
    payload_version: str = "1.0"

    # ── State Machine ─────────────────────────
    state: FileState = FileState.DETECTED
    chain_of_custody: list = field(default_factory=list)  # list of CustodyEntry

    # ── Validation ────────────────────────────
    validation: Optional[ValidationResult] = None

    # ── Payload ───────────────────────────────
    raw_payload: Optional[bytes] = None      # Original file bytes (quarantine zone)
    transformed_payload: Optional[dict] = None  # Normalized delivery payload

    # ── Delivery ──────────────────────────────
    delivery: Optional[DeliveryResult] = None
    idempotency_key: str = field(default_factory=lambda: str(uuid.uuid4()))

    # ── Compliance ────────────────────────────
    compliance_flags: list = field(default_factory=list)
    exception_reason: Optional[str] = None

    # ── Metadata ──────────────────────────────
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ─────────────────────────────────────────
    # STATE TRANSITION
    # ─────────────────────────────────────────

    def transition(
        self,
        new_state: FileState,
        actor: str,
        action: str,
        notes: str = "",
        session_id: Optional[str] = None
    ) -> "SankofaMessage":
        """
        Move the message to a new state and record the custody entry.
        This is the ONLY way state should change — never set .state directly.
        """
        entry = CustodyEntry(
            timestamp=datetime.now(timezone.utc),
            from_state=self.state,
            to_state=new_state,
            actor=actor,
            action=action,
            notes=notes,
            session_id=session_id,
        )
        self.chain_of_custody.append(entry)
        self.state = new_state
        self.updated_at = datetime.now(timezone.utc)
        return self

    # ─────────────────────────────────────────
    # HASH COMPUTATION
    # ─────────────────────────────────────────

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of raw payload and store it."""
        if not self.raw_payload:
            raise ValueError("Cannot compute hash — raw_payload is empty")
        h = hashlib.sha256(self.raw_payload).hexdigest()
        self.file_hash_sha256 = h
        return h

    def verify_hash(self, expected_hash: str) -> bool:
        """Verify the payload against an expected hash."""
        if not self.raw_payload:
            return False
        actual = hashlib.sha256(self.raw_payload).hexdigest()
        return actual == expected_hash

    # ─────────────────────────────────────────
    # PROVENANCE CHECK
    # ─────────────────────────────────────────

    def has_provenance(self) -> tuple[bool, list]:
        """
        VPF Provenance Gate.
        Returns (True, []) if all mandatory fields are present.
        Returns (False, [missing_fields]) if provenance is incomplete.
        Delivery is BLOCKED if this returns False.
        """
        required = {
            "message_id": self.message_id,
            "file_id": self.file_id,
            "source_system": self.source_system,
            "sender_entity_id": self.sender_entity_id,
            "receiver_entity_id": self.receiver_entity_id,
            "received_at_utc": self.received_at_utc,
            "file_hash_sha256": self.file_hash_sha256,
            "jurisdiction": self.jurisdiction,
        }
        missing = [k for k, v in required.items() if not v]
        return (len(missing) == 0, missing)

    # ─────────────────────────────────────────
    # SERIALIZATION
    # ─────────────────────────────────────────

    def to_audit_dict(self) -> dict:
        """Serialize for audit log — excludes raw payload."""
        return {
            "message_id": self.message_id,
            "file_id": self.file_id,
            "file_name": self.file_name,
            "file_format": self.file_format,
            "source_system": self.source_system,
            "sender_entity_id": self.sender_entity_id,
            "receiver_entity_id": self.receiver_entity_id,
            "state": self.state.value,
            "file_hash_sha256": self.file_hash_sha256,
            "file_size_bytes": self.file_size_bytes,
            "jurisdiction": self.jurisdiction,
            "classification": self.classification,
            "received_at_utc": self.received_at_utc.isoformat() if self.received_at_utc else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "compliance_flags": self.compliance_flags,
            "chain_of_custody": [e.to_dict() for e in self.chain_of_custody],
            "validation_status": self.validation.status.value if self.validation else "pending",
            "metadata": self.metadata,
        }

    def to_delivery_payload(self) -> dict:
        """Build the payload for the receiver API."""
        return {
            "message_id": self.message_id,
            "source_system": self.source_system,
            "destination_system": self.destination_system,
            "sender_entity_id": self.sender_entity_id,
            "receiver_entity_id": self.receiver_entity_id,
            "file_hash_sha256": self.file_hash_sha256,
            "payload_version": self.payload_version,
            "jurisdiction": self.jurisdiction,
            "classification": self.classification,
            "received_at_utc": self.received_at_utc.isoformat() if self.received_at_utc else None,
            "payload": self.transformed_payload or {},
            "metadata": self.metadata,
        }
