"""
SANKƆFA-BRIDGE — Multi-Tenant Partner Configuration
Stage 5 — African Corridor Scale

Manages the registry of sending and receiving partners
across the African digital finance corridor.

Each partner has:
  - A unique partner_id and jurisdiction
  - Connector configuration (source or destination)
  - Compliance profile (KYC status, AML tier, sanctions clearance)
  - Active/inactive status
  - Audit trail of registration and changes

Supported corridors (Stage 5):
  GH ↔ NG  Ghana ↔ Nigeria
  GH ↔ KE  Ghana ↔ Kenya
  GH ↔ RW  Ghana ↔ Rwanda
  GH ↔ ZA  Ghana ↔ South Africa
  NG ↔ KE  Nigeria ↔ Kenya

VPF Principle: Every partner is a registered, verified entity.
No anonymous parties in the corridor.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from enum import Enum

from audit.logger import audit, AuditEventType


class PartnerRole(str, Enum):
    SENDER   = "sender"
    RECEIVER = "receiver"
    BOTH     = "both"


class KYCStatus(str, Enum):
    NOT_STARTED  = "not_started"
    IN_PROGRESS  = "in_progress"
    VERIFIED     = "verified"
    SUSPENDED    = "suspended"
    REJECTED     = "rejected"


class AMLTier(str, Enum):
    STANDARD  = "standard"    # Normal monitoring
    ENHANCED  = "enhanced"    # Enhanced due diligence
    MONITORED = "monitored"   # Under active monitoring


@dataclass
class PartnerConfig:
    partner_id: str
    name: str
    jurisdiction: str
    role: PartnerRole
    kyc_status: KYCStatus = KYCStatus.NOT_STARTED
    aml_tier: AMLTier = AMLTier.STANDARD
    sanctions_cleared: bool = False
    active: bool = True

    # Connector details (populated when confirmed)
    connector_type: Optional[str] = None   # s3 / sftp / rest_api / azure_blob
    connector_config: dict = field(default_factory=dict)

    # Receiver API details
    api_endpoint: Optional[str] = None
    api_key_ref: Optional[str] = None     # Key name in secrets manager

    # Compliance metadata
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_reviewed: Optional[datetime] = None
    compliance_notes: str = ""
    allowed_corridors: list = field(default_factory=list)

    def is_production_ready(self) -> tuple[bool, list]:
        """Check if partner is ready for live transactions."""
        issues = []
        if self.kyc_status != KYCStatus.VERIFIED:
            issues.append(f"KYC not verified (status: {self.kyc_status.value})")
        if not self.sanctions_cleared:
            issues.append("Sanctions clearance not confirmed")
        if not self.active:
            issues.append("Partner is inactive")
        if self.role in [PartnerRole.SENDER, PartnerRole.BOTH] and not self.connector_type:
            issues.append("Source connector not configured")
        if self.role in [PartnerRole.RECEIVER, PartnerRole.BOTH] and not self.api_endpoint:
            issues.append("Receiver API endpoint not configured")
        return (len(issues) == 0, issues)

    def to_dict(self) -> dict:
        return {
            "partner_id": self.partner_id,
            "name": self.name,
            "jurisdiction": self.jurisdiction,
            "role": self.role.value,
            "kyc_status": self.kyc_status.value,
            "aml_tier": self.aml_tier.value,
            "sanctions_cleared": self.sanctions_cleared,
            "active": self.active,
            "connector_type": self.connector_type,
            "api_endpoint": self.api_endpoint,
            "registered_at": self.registered_at.isoformat(),
            "allowed_corridors": self.allowed_corridors,
            "compliance_notes": self.compliance_notes,
        }


class PartnerRegistry:
    """
    African Corridor Partner Registry.
    Manages all registered sending and receiving partners.
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
        self._partners: dict[str, PartnerConfig] = {}
        self._bootstrap_corridor_partners()
        self._initialized = True

    def _bootstrap_corridor_partners(self):
        """
        Pre-register known corridor partners at system init.
        These are PENDING KYC — not yet production-ready.
        Replace with your actual partner details.
        """
        bootstrap = [
            PartnerConfig(
                partner_id="PARTNER-GH-001",
                name="[Ghana Sender — To Be Named]",
                jurisdiction="GH",
                role=PartnerRole.SENDER,
                allowed_corridors=["GH-NG", "GH-KE"],
                compliance_notes="Awaiting KYC documentation",
            ),
            PartnerConfig(
                partner_id="PARTNER-NG-001",
                name="[Nigeria Receiver — To Be Named]",
                jurisdiction="NG",
                role=PartnerRole.RECEIVER,
                allowed_corridors=["GH-NG"],
                compliance_notes="Awaiting receiver API contract",
            ),
            PartnerConfig(
                partner_id="PARTNER-KE-001",
                name="[Kenya Receiver — To Be Named]",
                jurisdiction="KE",
                role=PartnerRole.RECEIVER,
                allowed_corridors=["GH-KE"],
                compliance_notes="Awaiting receiver API contract",
            ),
        ]
        for p in bootstrap:
            self._partners[p.partner_id] = p

    def register(self, partner: PartnerConfig, registered_by: str) -> PartnerConfig:
        self._partners[partner.partner_id] = partner
        audit.log(
            AuditEventType.OPERATOR_ACTION, actor=registered_by,
            details={"action": "partner_registered", "partner_id": partner.partner_id,
                     "jurisdiction": partner.jurisdiction, "role": partner.role.value}
        )
        return partner

    def get(self, partner_id: str) -> Optional[PartnerConfig]:
        return self._partners.get(partner_id)

    def list_by_jurisdiction(self, jurisdiction: str) -> list:
        return [p for p in self._partners.values() if p.jurisdiction == jurisdiction]

    def list_by_corridor(self, corridor: str) -> list:
        return [p for p in self._partners.values() if corridor in p.allowed_corridors]

    def list_production_ready(self) -> list:
        return [p for p in self._partners.values() if p.is_production_ready()[0]]

    def update_kyc(self, partner_id: str, status: KYCStatus, updated_by: str) -> Optional[PartnerConfig]:
        p = self._partners.get(partner_id)
        if not p:
            return None
        p.kyc_status = status
        p.last_reviewed = datetime.now(timezone.utc)
        audit.log(
            AuditEventType.COMPLIANCE_CLEARED if status == KYCStatus.VERIFIED
            else AuditEventType.COMPLIANCE_FLAG_RAISED,
            actor=updated_by,
            details={"action": "kyc_updated", "partner_id": partner_id, "status": status.value}
        )
        return p

    def summary(self) -> dict:
        all_p = list(self._partners.values())
        return {
            "total": len(all_p),
            "by_jurisdiction": {j: sum(1 for p in all_p if p.jurisdiction == j)
                                 for j in set(p.jurisdiction for p in all_p)},
            "by_kyc_status": {s.value: sum(1 for p in all_p if p.kyc_status == s)
                               for s in KYCStatus},
            "production_ready": len(self.list_production_ready()),
            "active": sum(1 for p in all_p if p.active),
        }


partner_registry = PartnerRegistry()
