"""
SANKƆFA-BRIDGE — Validation & Quarantine Engine (Layer 2)

Every file entering the system is quarantined first and
must pass ALL checks before moving to Layer 3.

Checks performed:
  1. File format validation
  2. File size check
  3. SHA-256 hash verification
  4. Schema validation (JSON/XML)
  5. Sender entitlement check
  6. Duplicate detection
  7. Provenance completeness (VPF gate)
  8. Compliance policy check

A file that fails ANY check goes to FAILED or EXCEPTION state.
It is NEVER silently passed through.

VPF Principle: No data moves without provenance.
"""

import json
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Set

from config.models import SankofaMessage, FileState, ValidationResult, ValidationStatus
from config.settings import settings
from audit.logger import audit, AuditEventType


# In-memory duplicate detection window
# In production: backed by Redis or database
_seen_hashes: dict[str, datetime] = {}


class ValidationEngine:
    """
    Layer 2 — Validation & Quarantine.
    Runs all checks on a quarantined SankofaMessage.
    Returns the message with ValidationResult populated.
    """

    ACTOR = "ValidationEngine"

    def validate(self, message: SankofaMessage) -> SankofaMessage:
        """
        Run the full validation suite.
        Returns message with .validation populated and state updated.
        """
        result = ValidationResult()

        message.transition(
            FileState.VALIDATING,
            actor=self.ACTOR,
            action="validation_started",
        )

        # Run all checks
        self._check_format(message, result)
        self._check_size(message, result)
        self._check_hash_integrity(message, result)
        self._check_schema(message, result)
        self._check_sender_entitlement(message, result)
        self._check_duplicates(message, result)
        self._check_provenance(message, result)
        self._check_compliance_policy(message, result)

        result.finalize()
        message.validation = result

        if result.status == ValidationStatus.FAIL:
            message.transition(
                FileState.FAILED,
                actor=self.ACTOR,
                action="validation_failed",
                notes="; ".join(result.errors),
            )
            audit.log_file_event(
                AuditEventType.FILE_VALIDATION_FAILED,
                message,
                actor=self.ACTOR,
                details={
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "checks": result.checks,
                }
            )

        elif result.status == ValidationStatus.WARNING:
            # Warnings: proceed but flag for compliance review
            message.compliance_flags.extend(result.warnings)
            message.transition(
                FileState.VALIDATED,
                actor=self.ACTOR,
                action="validation_passed_with_warnings",
                notes=f"Warnings: {'; '.join(result.warnings)}",
            )
            audit.log_file_event(
                AuditEventType.FILE_VALIDATED,
                message,
                actor=self.ACTOR,
                details={"warnings": result.warnings, "checks": result.checks}
            )

        else:
            message.transition(
                FileState.VALIDATED,
                actor=self.ACTOR,
                action="validation_passed",
            )
            audit.log_file_event(
                AuditEventType.FILE_VALIDATED,
                message,
                actor=self.ACTOR,
                details={"checks": result.checks}
            )

        return message

    # ─────────────────────────────────────────
    # CHECK 1 — File Format
    # ─────────────────────────────────────────

    def _check_format(self, message: SankofaMessage, result: ValidationResult):
        allowed = settings.validation.allowed_formats
        passed = message.file_format in allowed
        result.add_check(
            "file_format",
            passed,
            f"Format '{message.file_format}' not in allowed list: {allowed}"
        )

    # ─────────────────────────────────────────
    # CHECK 2 — File Size
    # ─────────────────────────────────────────

    def _check_size(self, message: SankofaMessage, result: ValidationResult):
        max_bytes = settings.validation.max_file_size_mb * 1024 * 1024
        passed = message.file_size_bytes <= max_bytes
        result.add_check(
            "file_size",
            passed,
            f"File size {message.file_size_bytes} bytes exceeds maximum {max_bytes} bytes"
        )

    # ─────────────────────────────────────────
    # CHECK 3 — Hash Integrity
    # ─────────────────────────────────────────

    def _check_hash_integrity(self, message: SankofaMessage, result: ValidationResult):
        if not settings.validation.require_hash_verification:
            result.add_check("hash_integrity", True)
            return

        if not message.raw_payload:
            result.add_check("hash_integrity", False, "No raw payload to hash")
            return

        if not message.file_hash_sha256:
            result.add_check("hash_integrity", False, "No hash recorded at ingestion")
            return

        # Recompute and verify
        computed = hashlib.sha256(message.raw_payload).hexdigest()
        passed = computed == message.file_hash_sha256
        result.add_check(
            "hash_integrity",
            passed,
            f"Hash mismatch — computed: {computed[:16]}... stored: {message.file_hash_sha256[:16]}..."
        )

    # ─────────────────────────────────────────
    # CHECK 4 — Schema Validation
    # ─────────────────────────────────────────

    def _check_schema(self, message: SankofaMessage, result: ValidationResult):
        if not message.raw_payload:
            result.add_check("schema", False, "No payload to validate")
            return

        if message.file_format == "json":
            try:
                parsed = json.loads(message.raw_payload.decode("utf-8"))
                # Store parsed content in metadata for transformation layer
                message.metadata["parsed_content"] = parsed
                result.add_check("schema", True)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                result.add_check("schema", False, f"JSON parse error: {e}")

        elif message.file_format == "xml":
            try:
                root = ET.fromstring(message.raw_payload)
                message.metadata["xml_root_tag"] = root.tag
                result.add_check("schema", True)
            except ET.ParseError as e:
                result.add_check("schema", False, f"XML parse error: {e}")

        else:
            result.add_warning(f"Schema validation not available for format: {message.file_format}")
            result.add_check("schema", True)

    # ─────────────────────────────────────────
    # CHECK 5 — Sender Entitlement
    # ─────────────────────────────────────────

    def _check_sender_entitlement(self, message: SankofaMessage, result: ValidationResult):
        if not settings.validation.enable_sender_entitlement_check:
            result.add_check("sender_entitlement", True)
            return

        if not message.sender_entity_id:
            result.add_check(
                "sender_entitlement",
                False,
                "sender_entity_id is empty — provenance requires a registered sender"
            )
            return

        # In production: query sender registry / database
        # For Stage 1: warn if ID has not been registered, but allow through
        # (registry not yet populated)
        if message.sender_entity_id.startswith("SENDER_TEST"):
            result.add_check("sender_entitlement", True)
        elif message.sender_entity_id:
            # Warn: sender not yet verified against registry
            result.add_warning(
                f"Sender '{message.sender_entity_id}' not verified in registry — "
                f"manual compliance review recommended"
            )
            result.add_check("sender_entitlement", True)
        else:
            result.add_check("sender_entitlement", False, "Empty sender ID")

    # ─────────────────────────────────────────
    # CHECK 6 — Duplicate Detection
    # ─────────────────────────────────────────

    def _check_duplicates(self, message: SankofaMessage, result: ValidationResult):
        if not settings.validation.enable_duplicate_detection:
            result.add_check("duplicate_check", True)
            return

        h = message.file_hash_sha256
        if not h:
            result.add_check("duplicate_check", True)
            return

        window = timedelta(hours=settings.validation.duplicate_window_hours)
        now = datetime.now(timezone.utc)

        if h in _seen_hashes:
            first_seen = _seen_hashes[h]
            if now - first_seen < window:
                result.add_check(
                    "duplicate_check",
                    False,
                    f"Duplicate file detected — same hash seen at {first_seen.isoformat()}"
                )
                return

        _seen_hashes[h] = now
        result.add_check("duplicate_check", True)

    # ─────────────────────────────────────────
    # CHECK 7 — Provenance Completeness (VPF)
    # ─────────────────────────────────────────

    def _check_provenance(self, message: SankofaMessage, result: ValidationResult):
        """
        VPF Gate: No data moves without provenance.
        At this stage, sender_entity_id and receiver_entity_id
        may not yet be set (receiver is set during transformation).
        We check what we can now; full provenance check runs before delivery.
        """
        checks_now = {
            "message_id": bool(message.message_id),
            "file_id": bool(message.file_id),
            "source_system": bool(message.source_system),
            "received_at_utc": bool(message.received_at_utc),
            "file_hash_sha256": bool(message.file_hash_sha256),
        }

        for field, ok in checks_now.items():
            if not ok:
                result.add_check(
                    "provenance",
                    False,
                    f"Provenance field missing: {field}"
                )
                return

        result.add_check("provenance", True)

    # ─────────────────────────────────────────
    # CHECK 8 — Compliance Policy
    # ─────────────────────────────────────────

    def _check_compliance_policy(self, message: SankofaMessage, result: ValidationResult):
        """
        Basic compliance rules for Stage 1.
        Layer 6 (Compliance Engine) runs deeper checks.
        """
        # Check jurisdiction not in high-risk list
        high_risk = settings.compliance.high_risk_jurisdictions
        if message.jurisdiction in high_risk:
            result.add_check(
                "compliance_policy",
                False,
                f"Jurisdiction '{message.jurisdiction}' is in high-risk list — escalate to compliance officer"
            )
            message.compliance_flags.append("HIGH_RISK_JURISDICTION")
            return

        # Classification check
        if message.classification not in ["restricted", "confidential", "internal"]:
            result.add_warning(f"Unusual classification: {message.classification}")

        result.add_check("compliance_policy", True)


# Singleton
validator = ValidationEngine()
