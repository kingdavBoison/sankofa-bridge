"""
SANKƆFA-BRIDGE — Exception Management
Stage 3 — Compliance Layer

When the compliance engine blocks a message, it lands here.
Human compliance officers review, resolve, or escalate.

Every exception decision is logged in the audit ledger.
No exception is silently dropped.
No exception auto-resolves without a human decision.

VPF Principle: No value moves without custodianship.
Exceptions are where custodianship is most visible.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List
from dataclasses import dataclass, field

from config.models import SankofaMessage, FileState
from audit.logger import audit, AuditEventType


class ExceptionStatus(str, Enum):
    OPEN       = "open"        # Awaiting assignment
    ASSIGNED   = "assigned"    # Under review
    ESCALATED  = "escalated"   # Sent to senior compliance / regulator
    RESOLVED   = "resolved"    # Cleared — may retry delivery
    REJECTED   = "rejected"    # Permanently blocked — no retry


class ExceptionPriority(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class ExceptionRecord:
    exception_id: str = field(default_factory=lambda: f"EXC-{str(uuid.uuid4())[:8].upper()}")
    message_id: str = ""
    file_name: str = ""
    reason: str = ""
    flags: list = field(default_factory=list)
    priority: ExceptionPriority = ExceptionPriority.MEDIUM
    status: ExceptionStatus = ExceptionStatus.OPEN
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution: Optional[str] = None
    escalation_reason: Optional[str] = None
    retry_approved: bool = False
    compliance_report: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "exception_id": self.exception_id,
            "message_id": self.message_id,
            "file_name": self.file_name,
            "reason": self.reason,
            "flags": self.flags,
            "priority": self.priority.value,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "resolution": self.resolution,
            "retry_approved": self.retry_approved,
        }


class ExceptionManager:
    """
    Manages the exception queue and review workflow.

    Stage 3: In-memory queue (backed by DB via API).
    Stage 5: Full workflow engine with notifications and SLA tracking.
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
        self._queue: dict[str, ExceptionRecord] = {}   # exception_id → record
        self._message_index: dict[str, str] = {}        # message_id → exception_id
        self._initialized = True

    def create(
        self,
        message: SankofaMessage,
        compliance_report: Optional[dict] = None,
    ) -> ExceptionRecord:
        """Create an exception record for a blocked message."""

        # Determine priority from flags
        priority = self._assess_priority(message.compliance_flags)

        record = ExceptionRecord(
            message_id=message.message_id,
            file_name=message.file_name,
            reason=message.exception_reason or "Compliance flag raised",
            flags=list(message.compliance_flags),
            priority=priority,
            compliance_report=compliance_report,
        )

        self._queue[record.exception_id] = record
        self._message_index[message.message_id] = record.exception_id

        audit.log(
            AuditEventType.FILE_EXCEPTION,
            actor="ExceptionManager",
            details={
                "exception_id": record.exception_id,
                "priority": priority.value,
                "flags": message.compliance_flags,
                "reason": record.reason,
            },
            message_id=message.message_id,
            file_name=message.file_name,
        )

        return record

    def assign(
        self,
        exception_id: str,
        officer: str,
    ) -> Optional[ExceptionRecord]:
        """Assign an exception to a compliance officer."""
        record = self._queue.get(exception_id)
        if not record:
            return None
        record.status = ExceptionStatus.ASSIGNED
        record.assigned_to = officer
        record.updated_at = datetime.now(timezone.utc)

        audit.log(
            AuditEventType.EXCEPTION_REVIEWED,
            actor=officer,
            details={
                "action": "assigned",
                "exception_id": exception_id,
            },
            message_id=record.message_id,
        )
        return record

    def resolve(
        self,
        exception_id: str,
        resolution: str,
        resolved_by: str,
        approve_retry: bool = False,
    ) -> Optional[ExceptionRecord]:
        """
        Resolve an exception.
        If approve_retry=True, the message will be queued for redelivery.
        """
        record = self._queue.get(exception_id)
        if not record:
            return None

        record.status = ExceptionStatus.RESOLVED
        record.resolution = resolution
        record.resolved_by = resolved_by
        record.resolved_at = datetime.now(timezone.utc)
        record.updated_at = datetime.now(timezone.utc)
        record.retry_approved = approve_retry

        audit.log(
            AuditEventType.EXCEPTION_REVIEWED,
            actor=resolved_by,
            details={
                "action": "resolved",
                "exception_id": exception_id,
                "resolution": resolution,
                "retry_approved": approve_retry,
            },
            message_id=record.message_id,
        )
        return record

    def escalate(
        self,
        exception_id: str,
        escalation_reason: str,
        escalated_by: str,
    ) -> Optional[ExceptionRecord]:
        """Escalate to senior compliance officer or regulator."""
        record = self._queue.get(exception_id)
        if not record:
            return None

        record.status = ExceptionStatus.ESCALATED
        record.priority = ExceptionPriority.CRITICAL
        record.escalation_reason = escalation_reason
        record.updated_at = datetime.now(timezone.utc)

        audit.log(
            AuditEventType.COMPLIANCE_FLAG_RAISED,
            actor=escalated_by,
            details={
                "action": "escalated",
                "exception_id": exception_id,
                "reason": escalation_reason,
                "priority": "CRITICAL",
            },
            message_id=record.message_id,
            level="ERROR",
        )
        return record

    def reject(
        self,
        exception_id: str,
        rejection_reason: str,
        rejected_by: str,
    ) -> Optional[ExceptionRecord]:
        """Permanently reject — no retry will be approved."""
        record = self._queue.get(exception_id)
        if not record:
            return None

        record.status = ExceptionStatus.REJECTED
        record.resolution = rejection_reason
        record.resolved_by = rejected_by
        record.resolved_at = datetime.now(timezone.utc)
        record.retry_approved = False
        record.updated_at = datetime.now(timezone.utc)

        audit.log(
            AuditEventType.EXCEPTION_REVIEWED,
            actor=rejected_by,
            details={
                "action": "rejected_permanently",
                "exception_id": exception_id,
                "reason": rejection_reason,
            },
            message_id=record.message_id,
        )
        return record

    def get(self, exception_id: str) -> Optional[ExceptionRecord]:
        return self._queue.get(exception_id)

    def get_by_message(self, message_id: str) -> Optional[ExceptionRecord]:
        exc_id = self._message_index.get(message_id)
        return self._queue.get(exc_id) if exc_id else None

    def list_open(self) -> List[ExceptionRecord]:
        return sorted(
            [r for r in self._queue.values()
             if r.status in [ExceptionStatus.OPEN, ExceptionStatus.ASSIGNED]],
            key=lambda r: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}[r.priority.value],
                r.created_at,
            )
        )

    def summary(self) -> dict:
        all_records = list(self._queue.values())
        return {
            "total": len(all_records),
            "open": sum(1 for r in all_records if r.status == ExceptionStatus.OPEN),
            "assigned": sum(1 for r in all_records if r.status == ExceptionStatus.ASSIGNED),
            "escalated": sum(1 for r in all_records if r.status == ExceptionStatus.ESCALATED),
            "resolved": sum(1 for r in all_records if r.status == ExceptionStatus.RESOLVED),
            "rejected": sum(1 for r in all_records if r.status == ExceptionStatus.REJECTED),
            "by_priority": {
                p.value: sum(1 for r in all_records if r.priority == p)
                for p in ExceptionPriority
            },
        }

    def _assess_priority(self, flags: list) -> ExceptionPriority:
        critical_flags = {
            "SANCTIONS_HIT_SENDER",
            "SANCTIONS_HIT_RECEIVER",
            "HIGH_RISK_JURISDICTION",
        }
        high_flags = {
            "AML_VELOCITY_BREACH",
            "AML_STRUCTURING_SUSPECTED",
            "PROVENANCE_INCOMPLETE",
            "COMPLIANCE_GATE_NOT_CLEARED",
        }
        flag_set = set(flags)
        if flag_set & critical_flags:
            return ExceptionPriority.CRITICAL
        if flag_set & high_flags:
            return ExceptionPriority.HIGH
        if flags:
            return ExceptionPriority.MEDIUM
        return ExceptionPriority.LOW


# Singleton
exception_manager = ExceptionManager()
