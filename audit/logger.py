"""
SANKƆFA-BRIDGE — Audit Ledger (Layer 5)
Append-only, tamper-evident, structured JSON event log.

VPF Principle: No system operates without auditability.

Every action in the system — file detections, state transitions,
validation outcomes, delivery attempts, compliance flags, operator
actions — is recorded here. Logs are never deleted or modified.
Exported for regulatory review on demand.
"""

import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pathlib import Path


class AuditEventType(str, Enum):
    # System lifecycle
    SYSTEM_START        = "SYSTEM_START"
    SYSTEM_STOP         = "SYSTEM_STOP"
    SYSTEM_ERROR        = "SYSTEM_ERROR"

    # File lifecycle
    FILE_DETECTED       = "FILE_DETECTED"
    FILE_DOWNLOADING    = "FILE_DOWNLOADING"
    FILE_QUARANTINED    = "FILE_QUARANTINED"
    FILE_VALIDATED      = "FILE_VALIDATED"
    FILE_VALIDATION_FAILED = "FILE_VALIDATION_FAILED"
    FILE_TRANSFORMED    = "FILE_TRANSFORMED"
    FILE_DELIVERED      = "FILE_DELIVERED"
    FILE_DELIVERY_FAILED = "FILE_DELIVERY_FAILED"
    FILE_ACKNOWLEDGED   = "FILE_ACKNOWLEDGED"
    FILE_FAILED         = "FILE_FAILED"
    FILE_EXCEPTION      = "FILE_EXCEPTION"
    FILE_ARCHIVED       = "FILE_ARCHIVED"

    # Compliance
    COMPLIANCE_GATE_CHECK   = "COMPLIANCE_GATE_CHECK"
    COMPLIANCE_FLAG_RAISED  = "COMPLIANCE_FLAG_RAISED"
    COMPLIANCE_CLEARED      = "COMPLIANCE_CLEARED"
    PROVENANCE_CHECK_FAILED = "PROVENANCE_CHECK_FAILED"
    PROHIBITED_ACTION_BLOCKED = "PROHIBITED_ACTION_BLOCKED"

    # Connector
    CONNECTOR_CONNECTED     = "CONNECTOR_CONNECTED"
    CONNECTOR_ERROR         = "CONNECTOR_ERROR"
    CONNECTOR_POLL          = "CONNECTOR_POLL"

    # Delivery
    DELIVERY_ATTEMPT        = "DELIVERY_ATTEMPT"
    DELIVERY_RETRY          = "DELIVERY_RETRY"
    CIRCUIT_BREAKER_OPEN    = "CIRCUIT_BREAKER_OPEN"
    CIRCUIT_BREAKER_RESET   = "CIRCUIT_BREAKER_RESET"

    # Operator
    OPERATOR_ACTION         = "OPERATOR_ACTION"
    OPERATOR_OVERRIDE       = "OPERATOR_OVERRIDE"
    EXCEPTION_REVIEWED      = "EXCEPTION_REVIEWED"

    # Export
    AUDIT_EXPORT            = "AUDIT_EXPORT"


class SankofaAuditLogger:
    """
    Append-only structured audit logger.

    Produces one JSON object per line (JSONL format).
    Each entry is immutable once written.
    Suitable for ingestion into ELK, Splunk, or cloud logging.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)

        self.audit_file = self.log_dir / f"sankofa_audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        self.session_id = self._generate_session_id()

        # Python logger for stdout (structured)
        self.logger = logging.getLogger("sankofa.audit")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S'
            ))
            self.logger.addHandler(handler)

        self._initialized = True
        self.log(AuditEventType.SYSTEM_START, "SYSTEM", {
            "system": "SANKƆFA-BRIDGE",
            "version": "1.0.0",
            "session_id": self.session_id,
            "principle": "No data moves without provenance. No value moves without custodianship. No system operates without auditability."
        })

    def _generate_session_id(self) -> str:
        import uuid
        return f"SESSION-{str(uuid.uuid4())[:8].upper()}"

    def log(
        self,
        event_type: AuditEventType,
        actor: str,
        details: dict,
        message_id: Optional[str] = None,
        file_name: Optional[str] = None,
        level: str = "INFO"
    ) -> dict:
        """
        Write an immutable audit event.
        Returns the event dict for reference.
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "event_type": event_type.value,
            "actor": actor,
            "level": level,
        }

        if message_id:
            event["message_id"] = message_id
        if file_name:
            event["file_name"] = file_name

        event["details"] = details

        # Write to JSONL audit file (append-only)
        try:
            with open(self.audit_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            self.logger.error(f"AUDIT WRITE FAILURE: {e} — event: {event_type.value}")

        # Write to stdout logger
        log_line = f"[{event_type.value}] actor={actor}"
        if message_id:
            log_line += f" msg_id={message_id[:8]}"
        if file_name:
            log_line += f" file={file_name}"

        if level == "ERROR":
            self.logger.error(log_line)
        elif level == "WARNING":
            self.logger.warning(log_line)
        else:
            self.logger.info(log_line)

        return event

    def log_file_event(
        self,
        event_type: AuditEventType,
        message,   # SankofaMessage
        actor: str,
        details: dict = None
    ):
        """Convenience method for file lifecycle events."""
        self.log(
            event_type=event_type,
            actor=actor,
            details={
                "state": message.state.value,
                "source_system": message.source_system,
                "sender_entity_id": message.sender_entity_id,
                "file_hash_sha256": message.file_hash_sha256[:16] + "..." if message.file_hash_sha256 else "",
                "jurisdiction": message.jurisdiction,
                **(details or {}),
            },
            message_id=message.message_id,
            file_name=message.file_name,
        )

    def log_prohibited_action(self, actor: str, action: str, context: str = ""):
        """
        VPF Role Boundary violation attempt.
        Logged as CRITICAL — always written regardless of log level.
        """
        self.log(
            event_type=AuditEventType.PROHIBITED_ACTION_BLOCKED,
            actor=actor,
            details={
                "action_attempted": action,
                "context": context,
                "vpf_boundary": "SYSTEM_ROLE_BOUNDARY_ENFORCED",
                "result": "BLOCKED",
            },
            level="ERROR"
        )

    def export_audit_report(
        self,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        message_id: Optional[str] = None
    ) -> list:
        """
        Export audit events for regulatory review.
        Filtered by date range or specific message.
        """
        events = []
        try:
            with open(self.audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    event = json.loads(line)

                    if message_id and event.get("message_id") != message_id:
                        continue

                    if from_date:
                        event_time = datetime.fromisoformat(event["timestamp"])
                        if event_time < from_date:
                            continue

                    if to_date:
                        event_time = datetime.fromisoformat(event["timestamp"])
                        if event_time > to_date:
                            continue

                    events.append(event)

        except FileNotFoundError:
            pass

        self.log(
            AuditEventType.AUDIT_EXPORT,
            actor="SYSTEM",
            details={"events_exported": len(events), "filter_message_id": message_id}
        )
        return events


# Singleton instance — import this throughout the system
audit = SankofaAuditLogger()
