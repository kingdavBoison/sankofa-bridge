"""
SANKƆFA-BRIDGE — Compliance Engine (Layer 6)
Stage 3 — Compliance Layer

This is the sovereignty gate of the entire system.
No file passes to delivery without clearing this layer.

Functions:
  1. Sanctions screening — check sender/receiver against watchlists
  2. Jurisdiction enforcement — FATF risk tiers, African corridor rules
  3. AML pattern detection — velocity, threshold, structuring flags
  4. KYC registry verification — sender/receiver must be registered
  5. Provenance completeness — final VPF gate before delivery
  6. Exception routing — flags that need human compliance review
  7. Compliance report generation — regulatory-ready evidence packages

VPF Principle: No value moves without custodianship.
The compliance engine is where custodianship is enforced mechanically.

Stage 3: Rule-based engine with hook architecture.
Stage 5: Plug in licensed screening API (Refinitiv, Dow Jones, ComplyAdvantage).
"""

import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from enum import Enum
from dataclasses import dataclass, field

from config.models import SankofaMessage, FileState
from config.settings import settings
from audit.logger import audit, AuditEventType


# ─────────────────────────────────────────────
# COMPLIANCE FLAG CODES
# ─────────────────────────────────────────────

class ComplianceFlag(str, Enum):
    # Sanctions
    SANCTIONS_HIT_SENDER       = "SANCTIONS_HIT_SENDER"
    SANCTIONS_HIT_RECEIVER     = "SANCTIONS_HIT_RECEIVER"
    SANCTIONS_SCREENING_SKIPPED = "SANCTIONS_SCREENING_SKIPPED"

    # Jurisdiction
    HIGH_RISK_JURISDICTION     = "HIGH_RISK_JURISDICTION"
    JURISDICTION_MISMATCH      = "JURISDICTION_MISMATCH"
    UNSUPPORTED_JURISDICTION   = "UNSUPPORTED_JURISDICTION"

    # AML
    AML_VELOCITY_BREACH        = "AML_VELOCITY_BREACH"
    AML_THRESHOLD_BREACH       = "AML_THRESHOLD_BREACH"
    AML_STRUCTURING_SUSPECTED  = "AML_STRUCTURING_SUSPECTED"
    AML_UNUSUAL_PATTERN        = "AML_UNUSUAL_PATTERN"

    # KYC
    KYC_SENDER_NOT_REGISTERED  = "KYC_SENDER_NOT_REGISTERED"
    KYC_RECEIVER_NOT_REGISTERED = "KYC_RECEIVER_NOT_REGISTERED"
    KYC_VERIFICATION_PENDING   = "KYC_VERIFICATION_PENDING"

    # Provenance
    PROVENANCE_INCOMPLETE      = "PROVENANCE_INCOMPLETE"
    SENDER_ID_MISSING          = "SENDER_ID_MISSING"
    RECEIVER_ID_MISSING        = "RECEIVER_ID_MISSING"

    # Gate
    COMPLIANCE_GATE_NOT_CLEARED = "COMPLIANCE_GATE_NOT_CLEARED"


class ComplianceSeverity(str, Enum):
    INFO     = "INFO"      # Log only — no blocking
    WARNING  = "WARNING"   # Flag for review — allow through
    BLOCK    = "BLOCK"     # Hard stop — escalate to compliance officer
    CRITICAL = "CRITICAL"  # Immediate escalation — potential regulatory breach


@dataclass
class ComplianceCheckResult:
    flag: ComplianceFlag
    severity: ComplianceSeverity
    message: str
    evidence: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def blocks(self) -> bool:
        return self.severity in [ComplianceSeverity.BLOCK, ComplianceSeverity.CRITICAL]

    def to_dict(self) -> dict:
        return {
            "flag": self.flag.value,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ComplianceReport:
    message_id: str
    file_name: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    checks: list = field(default_factory=list)   # list of ComplianceCheckResult
    overall_status: str = "PENDING"              # CLEAR / FLAGGED / BLOCKED / ESCALATED
    requires_human_review: bool = False
    blocking_flags: list = field(default_factory=list)
    warning_flags: list = field(default_factory=list)
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    resolution: Optional[str] = None

    def finalize(self) -> "ComplianceReport":
        self.blocking_flags = [c for c in self.checks if c.blocks()]
        self.warning_flags  = [c for c in self.checks
                                if c.severity == ComplianceSeverity.WARNING]

        if any(c.severity == ComplianceSeverity.CRITICAL for c in self.checks):
            self.overall_status = "ESCALATED"
            self.requires_human_review = True
        elif self.blocking_flags:
            self.overall_status = "BLOCKED"
            self.requires_human_review = True
        elif self.warning_flags:
            self.overall_status = "FLAGGED"
            self.requires_human_review = True
        else:
            self.overall_status = "CLEAR"

        return self

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "file_name": self.file_name,
            "generated_at": self.generated_at.isoformat(),
            "overall_status": self.overall_status,
            "requires_human_review": self.requires_human_review,
            "blocking_flags": [c.to_dict() for c in self.blocking_flags],
            "warning_flags": [c.to_dict() for c in self.warning_flags],
            "all_checks": [c.to_dict() for c in self.checks],
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "resolution": self.resolution,
        }


# ─────────────────────────────────────────────
# JURISDICTION FRAMEWORK
# African-first, FATF-aligned
# ─────────────────────────────────────────────

# African Digital Finance Corridor — supported jurisdictions
AFRICAN_CORRIDOR = {
    "GH": {"name": "Ghana", "risk_tier": 1, "fatf_member": True},
    "NG": {"name": "Nigeria", "risk_tier": 1, "fatf_member": True},
    "KE": {"name": "Kenya", "risk_tier": 1, "fatf_member": True},
    "RW": {"name": "Rwanda", "risk_tier": 1, "fatf_member": True},
    "ZA": {"name": "South Africa", "risk_tier": 1, "fatf_member": True},
    "TZ": {"name": "Tanzania", "risk_tier": 2, "fatf_member": False},
    "UG": {"name": "Uganda", "risk_tier": 2, "fatf_member": False},
    "SN": {"name": "Senegal", "risk_tier": 2, "fatf_member": False},
    "CI": {"name": "Côte d'Ivoire", "risk_tier": 2, "fatf_member": False},
    "ET": {"name": "Ethiopia", "risk_tier": 2, "fatf_member": False},
}

# FATF grey list and high-risk jurisdictions — update per FATF guidance
FATF_HIGH_RISK: set = set()   # Populated from FATF public list
FATF_GREY_LIST: set = set()   # Currently monitored jurisdictions


# ─────────────────────────────────────────────
# SANCTIONS WATCHLIST (Stage 3 stub)
# Stage 5: replace with Refinitiv / ComplyAdvantage live API
# ─────────────────────────────────────────────

# Format: normalized entity IDs on watchlists
# In production: query live screening API per transaction
SANCTIONS_WATCHLIST: set = {
    # Test entries — real system queries live API
    "SANCTIONED_ENTITY_001",
    "SANCTIONED_ENTITY_002",
}


# ─────────────────────────────────────────────
# AML VELOCITY TRACKER (in-memory for Stage 3)
# Stage 5: backed by Redis for distributed tracking
# ─────────────────────────────────────────────

_velocity_window: dict = {}   # sender_id → list of timestamps


# ─────────────────────────────────────────────
# COMPLIANCE ENGINE
# ─────────────────────────────────────────────

class ComplianceEngine:
    """
    Layer 6 — Compliance & Sovereignty Engine.

    Runs after validation and transformation, before delivery.
    Every check either clears, warns, or blocks the message.

    BLOCKED messages go to the exception queue for human review.
    CLEAR messages proceed to Layer 4 delivery.
    """

    ACTOR = "ComplianceEngine"

    # AML thresholds (GHS — Ghana Cedis)
    # Adjust per jurisdiction and regulatory guidance
    AML_SINGLE_THRESHOLD    = 10_000   # Single transaction reporting threshold
    AML_DAILY_VELOCITY      = 5        # Max files per sender per day
    AML_STRUCTURING_WINDOW  = 3        # Files within 1 hour triggering structuring check

    def run(self, message: SankofaMessage) -> tuple[SankofaMessage, ComplianceReport]:
        """
        Execute all compliance checks on a transformed message.
        Returns (updated_message, compliance_report).
        """
        report = ComplianceReport(
            message_id=message.message_id,
            file_name=message.file_name,
        )

        # Run all checks
        self._check_sanctions(message, report)
        self._check_jurisdiction(message, report)
        self._check_kyc_registry(message, report)
        self._check_aml_patterns(message, report)
        self._check_provenance_final(message, report)

        report.finalize()

        # Apply results to message
        for check in report.checks:
            if check.flag.value not in message.compliance_flags:
                message.compliance_flags.append(check.flag.value)

        if report.overall_status == "CLEAR":
            audit.log(
                AuditEventType.COMPLIANCE_CLEARED,
                self.ACTOR,
                {"overall_status": "CLEAR", "checks_run": len(report.checks)},
                message_id=message.message_id,
                file_name=message.file_name,
            )

        elif report.overall_status in ["BLOCKED", "ESCALATED"]:
            message.exception_reason = (
                f"Compliance {report.overall_status}: "
                + "; ".join(c.flag.value for c in report.blocking_flags)
            )
            message.transition(
                FileState.EXCEPTION,
                actor=self.ACTOR,
                action=f"compliance_{report.overall_status.lower()}",
                notes=message.exception_reason,
            )
            audit.log(
                AuditEventType.COMPLIANCE_FLAG_RAISED,
                self.ACTOR,
                {
                    "status": report.overall_status,
                    "blocking_flags": [c.flag.value for c in report.blocking_flags],
                    "requires_human_review": True,
                },
                message_id=message.message_id,
                file_name=message.file_name,
                level="WARNING" if report.overall_status == "BLOCKED" else "ERROR",
            )

        else:  # FLAGGED — warnings only
            audit.log(
                AuditEventType.COMPLIANCE_FLAG_RAISED,
                self.ACTOR,
                {
                    "status": "FLAGGED",
                    "warning_flags": [c.flag.value for c in report.warning_flags],
                },
                message_id=message.message_id,
                file_name=message.file_name,
            )

        return message, report

    # ─────────────────────────────────────────
    # CHECK 1 — Sanctions Screening
    # ─────────────────────────────────────────

    def _check_sanctions(self, message: SankofaMessage, report: ComplianceReport):
        if not settings.compliance.sanctions_screening_enabled:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.SANCTIONS_SCREENING_SKIPPED,
                severity=ComplianceSeverity.WARNING,
                message="Sanctions screening is disabled in configuration.",
            ))
            return

        # Check sender
        sender = (message.sender_entity_id or "").upper()
        if sender in SANCTIONS_WATCHLIST:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.SANCTIONS_HIT_SENDER,
                severity=ComplianceSeverity.CRITICAL,
                message=f"Sender entity '{sender}' matched sanctions watchlist.",
                evidence={"entity_id": sender, "list": "SANKOFA_INTERNAL_WATCHLIST"},
            ))

        # Check receiver
        receiver = (message.receiver_entity_id or "").upper()
        if receiver in SANCTIONS_WATCHLIST:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.SANCTIONS_HIT_RECEIVER,
                severity=ComplianceSeverity.CRITICAL,
                message=f"Receiver entity '{receiver}' matched sanctions watchlist.",
                evidence={"entity_id": receiver, "list": "SANKOFA_INTERNAL_WATCHLIST"},
            ))

        # Hook point for live screening API (Stage 5)
        # result = await screening_api.screen(sender, receiver)
        # if result.hit: report.checks.append(...)

    # ─────────────────────────────────────────
    # CHECK 2 — Jurisdiction Enforcement
    # ─────────────────────────────────────────

    def _check_jurisdiction(self, message: SankofaMessage, report: ComplianceReport):
        jur = (message.jurisdiction or "").upper()

        if not jur:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.UNSUPPORTED_JURISDICTION,
                severity=ComplianceSeverity.BLOCK,
                message="Jurisdiction is not set. Cannot process without jurisdiction.",
            ))
            return

        if jur in FATF_HIGH_RISK:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.HIGH_RISK_JURISDICTION,
                severity=ComplianceSeverity.CRITICAL,
                message=f"Jurisdiction '{jur}' is on the FATF high-risk list.",
                evidence={"jurisdiction": jur, "list": "FATF_HIGH_RISK"},
            ))
            return

        if jur in FATF_GREY_LIST:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.HIGH_RISK_JURISDICTION,
                severity=ComplianceSeverity.BLOCK,
                message=f"Jurisdiction '{jur}' is on the FATF grey list — enhanced due diligence required.",
                evidence={"jurisdiction": jur, "list": "FATF_GREY_LIST"},
            ))
            return

        if jur not in AFRICAN_CORRIDOR:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.UNSUPPORTED_JURISDICTION,
                severity=ComplianceSeverity.WARNING,
                message=f"Jurisdiction '{jur}' is outside the supported African corridor.",
                evidence={"jurisdiction": jur, "supported": list(AFRICAN_CORRIDOR.keys())},
            ))

    # ─────────────────────────────────────────
    # CHECK 3 — KYC Registry
    # ─────────────────────────────────────────

    def _check_kyc_registry(self, message: SankofaMessage, report: ComplianceReport):
        if not settings.compliance.kyc_verification_required:
            return

        if not message.sender_entity_id:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.SENDER_ID_MISSING,
                severity=ComplianceSeverity.BLOCK,
                message="sender_entity_id is missing. KYC cannot be verified.",
            ))

        if not message.receiver_entity_id:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.RECEIVER_ID_MISSING,
                severity=ComplianceSeverity.BLOCK,
                message="receiver_entity_id is missing. KYC cannot be verified.",
            ))

        # Stage 3: warn if not in verified registry
        # Stage 5: query DBSenderRegistry for kyc_verified=True
        sender = message.sender_entity_id or ""
        if sender and not sender.startswith("SENDER_TEST"):
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.KYC_VERIFICATION_PENDING,
                severity=ComplianceSeverity.WARNING,
                message=f"Sender '{sender}' has not been KYC-verified in the registry.",
                evidence={"sender_entity_id": sender},
            ))

    # ─────────────────────────────────────────
    # CHECK 4 — AML Pattern Detection
    # ─────────────────────────────────────────

    def _check_aml_patterns(self, message: SankofaMessage, report: ComplianceReport):
        if not settings.compliance.aml_hook_enabled:
            return

        sender = message.sender_entity_id or "UNKNOWN"
        now = datetime.now(timezone.utc)

        # Track velocity
        if sender not in _velocity_window:
            _velocity_window[sender] = []

        # Purge entries older than 24 hours
        _velocity_window[sender] = [
            t for t in _velocity_window[sender]
            if now - t < timedelta(hours=24)
        ]
        _velocity_window[sender].append(now)

        daily_count = len(_velocity_window[sender])

        # Velocity breach
        if daily_count > self.AML_DAILY_VELOCITY:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.AML_VELOCITY_BREACH,
                severity=ComplianceSeverity.BLOCK,
                message=(
                    f"Sender '{sender}' has submitted {daily_count} files "
                    f"in 24 hours — exceeds threshold of {self.AML_DAILY_VELOCITY}."
                ),
                evidence={
                    "sender": sender,
                    "count_24h": daily_count,
                    "threshold": self.AML_DAILY_VELOCITY,
                },
            ))

        # Structuring detection — multiple files in short window
        recent = [t for t in _velocity_window[sender]
                  if now - t < timedelta(hours=1)]
        if len(recent) >= self.AML_STRUCTURING_WINDOW:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.AML_STRUCTURING_SUSPECTED,
                severity=ComplianceSeverity.WARNING,
                message=(
                    f"Sender '{sender}' submitted {len(recent)} files within 1 hour "
                    f"— possible structuring pattern. Flag for review."
                ),
                evidence={
                    "sender": sender,
                    "count_1h": len(recent),
                    "window_threshold": self.AML_STRUCTURING_WINDOW,
                },
            ))

        # Amount threshold check (if payload contains amount)
        if message.transformed_payload:
            payload = message.transformed_payload.get("payload", {})
            amount = None
            try:
                amount = float(
                    payload.get("amount")
                    or payload.get("original_fields", {}).get("amount", 0)
                    or 0
                )
            except (TypeError, ValueError):
                pass

            if amount and amount >= self.AML_SINGLE_THRESHOLD:
                report.checks.append(ComplianceCheckResult(
                    flag=ComplianceFlag.AML_THRESHOLD_BREACH,
                    severity=ComplianceSeverity.WARNING,
                    message=(
                        f"Transaction amount {amount:,.2f} GHS meets or exceeds "
                        f"reporting threshold of {self.AML_SINGLE_THRESHOLD:,} GHS."
                    ),
                    evidence={
                        "amount": amount,
                        "threshold": self.AML_SINGLE_THRESHOLD,
                        "currency": payload.get("currency", "GHS"),
                        "action_required": "File STR if suspicious",
                    },
                ))

    # ─────────────────────────────────────────
    # CHECK 5 — Final VPF Provenance Gate
    # ─────────────────────────────────────────

    def _check_provenance_final(self, message: SankofaMessage, report: ComplianceReport):
        ok, missing = message.has_provenance()
        if not ok:
            report.checks.append(ComplianceCheckResult(
                flag=ComplianceFlag.PROVENANCE_INCOMPLETE,
                severity=ComplianceSeverity.BLOCK,
                message=f"VPF provenance gate: mandatory fields missing: {missing}",
                evidence={"missing_fields": missing},
            ))

    # ─────────────────────────────────────────
    # COMPLIANCE REPORT GENERATION
    # Regulatory-ready evidence package
    # ─────────────────────────────────────────

    def generate_evidence_package(
        self,
        message: SankofaMessage,
        report: ComplianceReport,
    ) -> dict:
        """
        Generate a regulatory-ready compliance evidence package.
        Suitable for submission to Bank of Ghana, SEC Ghana,
        or other African regulatory bodies.
        """
        return {
            "evidence_package_id": f"EP-{message.message_id[:8].upper()}",
            "system": "SANKƆFA-BRIDGE",
            "governing_framework": "Visionary Prompt Framework (VPF)",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "jurisdiction": message.jurisdiction,
            "transaction": {
                "message_id": message.message_id,
                "file_name": message.file_name,
                "file_hash_sha256": message.file_hash_sha256,
                "sender_entity_id": message.sender_entity_id,
                "receiver_entity_id": message.receiver_entity_id,
                "received_at_utc": message.received_at_utc.isoformat() if message.received_at_utc else None,
                "source_system": message.source_system,
            },
            "compliance_report": report.to_dict(),
            "chain_of_custody": [e.to_dict() for e in message.chain_of_custody],
            "system_role_declaration": (
                "SANKƆFA-BRIDGE operates exclusively as a secure data integration layer. "
                "It does not hold funds, sign blockchain transactions, approve settlements, "
                "tokenize assets, or act as a financial intermediary."
            ),
            "vpf_principle": (
                "No data moves without provenance. "
                "No value moves without custodianship. "
                "No system operates without auditability."
            ),
        }

    def update_sanctions_list(self, entity_ids: list, action: str = "add"):
        """
        Update the internal sanctions watchlist.
        In Stage 5: this syncs from a licensed screening provider.
        """
        global SANCTIONS_WATCHLIST
        for eid in entity_ids:
            normalized = eid.upper().strip()
            if action == "add":
                SANCTIONS_WATCHLIST.add(normalized)
            elif action == "remove":
                SANCTIONS_WATCHLIST.discard(normalized)
        audit.log(
            AuditEventType.COMPLIANCE_GATE_CHECK,
            self.ACTOR,
            {
                "action": f"sanctions_list_{action}",
                "entities_affected": len(entity_ids),
                "list_size": len(SANCTIONS_WATCHLIST),
            }
        )


# Singleton
compliance_engine = ComplianceEngine()
