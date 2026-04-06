"""
SANKƆFA-BRIDGE — Role-Based Access Control (RBAC)
Stage 2 Hardening

Defines roles, permissions, and authentication for all
human operators interacting with the system.

VPF Role Boundaries enforced here:
  - CUSTODIAN: Full system authority. David King Boison.
  - OPERATOR: File operations only. No financial authority.
  - COMPLIANCE_OFFICER: Exception review and compliance gate.
  - AUDITOR: Read-only access to logs and reports.
  - API_CLIENT: External integration (sender/receiver systems).

Zero trust: every API request is authenticated and authorized.
Every operator action is logged in the audit ledger.
"""

import hashlib
import hmac
import secrets
import time
from enum import Enum
from typing import Optional, Set
from dataclasses import dataclass, field
from audit.logger import audit, AuditEventType


# ─────────────────────────────────────────────
# ROLES & PERMISSIONS
# ─────────────────────────────────────────────

class Role(str, Enum):
    CUSTODIAN          = "custodian"
    OPERATOR           = "operator"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR            = "auditor"
    API_CLIENT         = "api_client"


class Permission(str, Enum):
    # File operations
    VIEW_FILES         = "view_files"
    RETRY_FILE         = "retry_file"
    ARCHIVE_FILE       = "archive_file"

    # Exception management
    VIEW_EXCEPTIONS    = "view_exceptions"
    REVIEW_EXCEPTION   = "review_exception"
    RESOLVE_EXCEPTION  = "resolve_exception"
    ESCALATE_EXCEPTION = "escalate_exception"

    # Compliance gate
    VIEW_GATE          = "view_gate"
    ANSWER_GATE        = "answer_gate"
    CLEAR_GATE         = "clear_gate"

    # Audit
    VIEW_AUDIT_LOG     = "view_audit_log"
    EXPORT_AUDIT       = "export_audit"

    # System
    VIEW_SYSTEM_STATUS = "view_system_status"
    MANAGE_CONNECTORS  = "manage_connectors"
    MANAGE_REGISTRY    = "manage_registry"
    MANAGE_OPERATORS   = "manage_operators"

    # Prohibited — listed here so they can be explicitly blocked
    HOLD_FUNDS                = "hold_funds"
    SIGN_BLOCKCHAIN           = "sign_blockchain"
    APPROVE_SETTLEMENT        = "approve_settlement"
    TOKENIZE_ASSET            = "tokenize_asset"
    CUSTODY_DIGITAL_ASSETS    = "custody_digital_assets"


# Role → permitted actions mapping
ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.CUSTODIAN: {
        Permission.VIEW_FILES,
        Permission.RETRY_FILE,
        Permission.ARCHIVE_FILE,
        Permission.VIEW_EXCEPTIONS,
        Permission.REVIEW_EXCEPTION,
        Permission.RESOLVE_EXCEPTION,
        Permission.ESCALATE_EXCEPTION,
        Permission.VIEW_GATE,
        Permission.ANSWER_GATE,
        Permission.CLEAR_GATE,
        Permission.VIEW_AUDIT_LOG,
        Permission.EXPORT_AUDIT,
        Permission.VIEW_SYSTEM_STATUS,
        Permission.MANAGE_CONNECTORS,
        Permission.MANAGE_REGISTRY,
        Permission.MANAGE_OPERATORS,
        # Note: prohibited actions are NOT listed here.
        # They cannot be granted to ANY role.
    },
    Role.OPERATOR: {
        Permission.VIEW_FILES,
        Permission.RETRY_FILE,
        Permission.VIEW_EXCEPTIONS,
        Permission.VIEW_SYSTEM_STATUS,
        Permission.VIEW_AUDIT_LOG,
    },
    Role.COMPLIANCE_OFFICER: {
        Permission.VIEW_FILES,
        Permission.VIEW_EXCEPTIONS,
        Permission.REVIEW_EXCEPTION,
        Permission.RESOLVE_EXCEPTION,
        Permission.ESCALATE_EXCEPTION,
        Permission.VIEW_GATE,
        Permission.ANSWER_GATE,
        Permission.CLEAR_GATE,
        Permission.VIEW_AUDIT_LOG,
        Permission.EXPORT_AUDIT,
        Permission.VIEW_SYSTEM_STATUS,
    },
    Role.AUDITOR: {
        Permission.VIEW_FILES,
        Permission.VIEW_EXCEPTIONS,
        Permission.VIEW_GATE,
        Permission.VIEW_AUDIT_LOG,
        Permission.EXPORT_AUDIT,
        Permission.VIEW_SYSTEM_STATUS,
    },
    Role.API_CLIENT: {
        Permission.VIEW_SYSTEM_STATUS,
    },
}

# Actions that are PROHIBITED for ALL roles — architectural enforcement
PROHIBITED_PERMISSIONS = {
    Permission.HOLD_FUNDS,
    Permission.SIGN_BLOCKCHAIN,
    Permission.APPROVE_SETTLEMENT,
    Permission.TOKENIZE_ASSET,
    Permission.CUSTODY_DIGITAL_ASSETS,
}


# ─────────────────────────────────────────────
# OPERATOR (USER) MODEL
# ─────────────────────────────────────────────

@dataclass
class Operator:
    operator_id: str
    name: str
    role: Role
    api_key_hash: str           # Never store raw API keys
    active: bool = True
    created_at: float = field(default_factory=time.time)
    last_seen: Optional[float] = None

    def has_permission(self, permission: Permission) -> bool:
        """Check if this operator has a specific permission."""
        # Prohibited actions blocked regardless of role
        if permission in PROHIBITED_PERMISSIONS:
            audit.log_prohibited_action(
                actor=self.operator_id,
                action=permission.value,
                context=f"RBAC check — permission not granted to any role"
            )
            return False
        return permission in ROLE_PERMISSIONS.get(self.role, set())

    def permissions(self) -> Set[Permission]:
        return ROLE_PERMISSIONS.get(self.role, set()) - PROHIBITED_PERMISSIONS


# ─────────────────────────────────────────────
# RBAC SERVICE
# ─────────────────────────────────────────────

class RBACService:
    """
    Manages operators, API key verification, and permission checks.

    Stage 2: In-memory store with hashed keys.
    Stage 5: Database-backed with MFA and SSO.
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
        self._operators: dict[str, Operator] = {}
        self._key_to_id: dict[str, str] = {}   # hashed_key → operator_id
        self._bootstrap()
        self._initialized = True

    def _hash_key(self, raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def _bootstrap(self):
        """
        Create the default CUSTODIAN operator on first run.
        In production: operators are registered through the admin API.
        Reads the API key fresh from environment every time — never cached.
        """
        import os
        from dotenv import load_dotenv
        load_dotenv(override=True)   # Always pick up latest .env
        bootstrap_key = os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")
        self.register_operator(
            operator_id="david-king-boison",
            name="David King Boison",
            role=Role.CUSTODIAN,
            raw_api_key=bootstrap_key,
        )

    def register_operator(
        self,
        operator_id: str,
        name: str,
        role: Role,
        raw_api_key: str,
    ) -> Operator:
        key_hash = self._hash_key(raw_api_key)
        op = Operator(
            operator_id=operator_id,
            name=name,
            role=role,
            api_key_hash=key_hash,
        )
        self._operators[operator_id] = op
        self._key_to_id[key_hash] = operator_id
        audit.log(
            AuditEventType.OPERATOR_ACTION,
            actor="RBACService",
            details={
                "action": "operator_registered",
                "operator_id": operator_id,
                "role": role.value,
            }
        )
        return op

    def authenticate(self, raw_api_key: str) -> Optional[Operator]:
        """Verify an API key and return the operator, or None."""
        key_hash = self._hash_key(raw_api_key)
        op_id = self._key_to_id.get(key_hash)
        if not op_id:
            return None
        op = self._operators.get(op_id)
        if op and op.active:
            op.last_seen = time.time()
            return op
        return None

    def authorize(
        self,
        operator: Operator,
        permission: Permission,
        resource: str = "",
    ) -> bool:
        """
        Check if operator can perform an action.
        Logs every authorization decision.
        """
        granted = operator.has_permission(permission)
        audit.log(
            AuditEventType.OPERATOR_ACTION,
            actor=operator.operator_id,
            details={
                "action": "authorization_check",
                "permission": permission.value,
                "resource": resource,
                "result": "GRANTED" if granted else "DENIED",
                "role": operator.role.value,
            }
        )
        return granted

    def generate_api_key(self, prefix: str = "skb") -> str:
        """Generate a new cryptographically secure API key."""
        return f"{prefix}_{secrets.token_urlsafe(32)}"

    def reset_for_testing(self):
        """Reset singleton state for test isolation. Never call in production."""
        self._operators = {}
        self._key_to_id = {}
        self._bootstrap()

    def deactivate_operator(self, operator_id: str, by: str):
        op = self._operators.get(operator_id)
        if op:
            op.active = False
            audit.log(
                AuditEventType.OPERATOR_ACTION,
                actor=by,
                details={"action": "operator_deactivated", "target": operator_id}
            )


# Singleton
rbac = RBACService()
