"""
SANKƆFA-BRIDGE — REST API (FastAPI)
Stage 2 Hardening

Exposes the system over HTTP for:
  - Operator dashboard queries
  - External status monitoring
  - Sender/receiver webhook callbacks
  - Exception management
  - Compliance gate management
  - Audit log export

All endpoints require API key authentication.
All actions are logged to the audit ledger.
Prohibited actions return 403 — they are never executed.

Run: uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
"""

import json
from datetime import datetime, timezone
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from config.models import FileState
from config.settings import settings
from config.database import db
from compliance.rbac import rbac, Permission, Role
from compliance.copilot import copilot
from compliance.live_copilot import live_copilot
from audit.logger import audit, AuditEventType


# ─────────────────────────────────────────────
# LIFESPAN — startup / shutdown
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.init_db()
    audit.log(AuditEventType.SYSTEM_START, "API", {
        "host": settings.api.host,
        "port": settings.api.port,
    })
    yield
    # Shutdown
    audit.log(AuditEventType.SYSTEM_STOP, "API", {"reason": "graceful_shutdown"})


# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────

app = FastAPI(
    title="SANKƆFA-BRIDGE",
    description=(
        "Sovereign Data Orchestration System — VPF Governance Architecture. "
        "No data moves without provenance. "
        "No value moves without custodianship. "
        "No system operates without auditability."
    ),
    version=settings.version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# AUTHENTICATION DEPENDENCY
# ─────────────────────────────────────────────

async def get_current_operator(
    x_sankofa_api_key: str = Header(..., alias="X-SANKOFA-API-Key")
):
    operator = rbac.authenticate(x_sankofa_api_key)
    if not operator:
        audit.log(
            AuditEventType.OPERATOR_ACTION,
            actor="UNKNOWN",
            details={"action": "auth_failed", "reason": "invalid_api_key"},
            level="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return operator


def require_permission(permission: Permission):
    async def checker(operator=Depends(get_current_operator)):
        if not rbac.authorize(operator, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}",
            )
        return operator
    return checker


# ─────────────────────────────────────────────
# PYDANTIC SCHEMAS
# ─────────────────────────────────────────────

class SystemStatusResponse(BaseModel):
    system: str
    version: str
    stage: str
    architect: str
    framework: str
    connector_type: str
    compliance_gate_cleared: bool
    principle: str


class MessageSummary(BaseModel):
    message_id: str
    file_name: str
    file_format: str
    source_system: str
    sender_entity_id: Optional[str]
    receiver_entity_id: Optional[str]
    state: str
    file_hash_sha256: Optional[str]
    jurisdiction: str
    compliance_flags: List[str]
    exception_reason: Optional[str]
    delivery_id: Optional[str]
    received_at_utc: Optional[str]
    created_at: str


class DashboardStats(BaseModel):
    total: int
    by_state: dict
    exceptions_open: int


class ComplianceGateAnswerRequest(BaseModel):
    question_id: int
    answer_text: str
    answered_by: str


class ExceptionResolutionRequest(BaseModel):
    resolution: str
    resolved_by: str


class RegisterSenderRequest(BaseModel):
    entity_id: str
    entity_name: str
    jurisdiction: str = "GH"
    notes: str = ""


# ─────────────────────────────────────────────
# PROHIBITED ACTIONS — explicit 403 endpoints
# ─────────────────────────────────────────────

PROHIBITED = [
    "/prohibited/hold-funds",
    "/prohibited/sign-blockchain",
    "/prohibited/approve-settlement",
    "/prohibited/tokenize-asset",
    "/prohibited/custody-assets",
]

for path in PROHIBITED:
    @app.post(path, include_in_schema=False)
    @app.get(path, include_in_schema=False)
    async def _prohibited(op=Depends(get_current_operator)):
        audit.log_prohibited_action(
            actor=op.operator_id,
            action=path,
            context="HTTP request to prohibited endpoint"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This action is outside the VPF-defined scope of SANKƆFA-BRIDGE. "
                "The system does not hold funds, sign blockchain transactions, "
                "approve settlements, tokenize assets, or custody digital assets."
            )
        )


# ─────────────────────────────────────────────
# SYSTEM ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    """Public health check — no auth required."""
    return {"status": "ok", "system": "SANKƆFA-BRIDGE", "version": settings.version}


@app.get("/v1/status", response_model=SystemStatusResponse, tags=["System"])
async def system_status(op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))):
    """Full system status — authenticated."""
    return SystemStatusResponse(
        system=settings.system_name,
        version=settings.version,
        stage=settings.stage,
        architect=settings.architect,
        framework=settings.framework,
        connector_type=settings.connector_type.value,
        compliance_gate_cleared=settings.compliance.gate_cleared,
        principle=settings.principle,
    )


@app.get("/v1/dashboard", response_model=DashboardStats, tags=["System"])
async def dashboard(op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))):
    """Dashboard summary statistics."""
    stats = await db.get_stats()
    exceptions = await db.list_exceptions(status="open")
    total = sum(stats.values())
    return DashboardStats(
        total=total,
        by_state={k.value if hasattr(k, 'value') else str(k): v for k, v in stats.items()},
        exceptions_open=len(exceptions),
    )


# ─────────────────────────────────────────────
# FILE / MESSAGE ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/v1/files", tags=["Files"])
async def list_files(
    state: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    op=Depends(require_permission(Permission.VIEW_FILES))
):
    """List processed files with optional state filter."""
    file_state = FileState(state) if state else None
    messages = await db.list_messages(state=file_state, limit=limit, offset=offset)
    return {
        "count": len(messages),
        "files": [_msg_to_summary(m) for m in messages]
    }


@app.get("/v1/files/{message_id}", tags=["Files"])
async def get_file(
    message_id: str,
    op=Depends(require_permission(Permission.VIEW_FILES))
):
    """Get full detail for a specific message including chain of custody."""
    msg = await db.get_message(message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    result = _msg_to_summary(msg)
    result["chain_of_custody"] = json.loads(msg.chain_of_custody or "[]")
    return result


@app.post("/v1/files/{message_id}/retry", tags=["Files"])
async def retry_file(
    message_id: str,
    op=Depends(require_permission(Permission.RETRY_FILE))
):
    """Queue a failed file for retry delivery."""
    msg = await db.get_message(message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    audit.log(
        AuditEventType.OPERATOR_ACTION,
        actor=op.operator_id,
        details={"action": "retry_queued", "message_id": message_id},
        message_id=message_id,
    )
    return {"status": "retry_queued", "message_id": message_id}


# ─────────────────────────────────────────────
# COMPLIANCE GATE ENDPOINTS
# ─────────────────────────────────────────────

COMPLIANCE_QUESTIONS = {
    1: {"category": "legal", "text": "Who are the legally recognized parties — sender, receiver, and platform?"},
    2: {"category": "legal", "text": "What licenses or regulatory approvals cover this in each jurisdiction?"},
    3: {"category": "legal", "text": "What is the legal classification — remittance, digital asset, or settlement?"},
    4: {"category": "legal", "text": "Who is legally responsible for the movement of funds at each stage?"},
    5: {"category": "legal", "text": "Has AML/KYC been completed on sender and receiver? By whom?"},
    6: {"category": "legal", "text": "Who is responsible for sanctions screening?"},
    7: {"category": "legal", "text": "Is tokenization legally permitted in each jurisdiction?"},
    8: {"category": "technical", "text": "What is the exact source system type?"},
    9: {"category": "technical", "text": "Who owns and controls the source system?"},
    10: {"category": "technical", "text": "What is the exact file format?"},
    11: {"category": "technical", "text": "What is the exact receiver API contract?"},
    12: {"category": "technical", "text": "Is there a sandbox environment available?"},
    13: {"category": "technical", "text": "What integrity verification method is used?"},
    14: {"category": "governance", "text": "Is there a formal contract governing the system operator?"},
    15: {"category": "governance", "text": "What is the compensation model?"},
    16: {"category": "governance", "text": "Who has final settlement authority?"},
    17: {"category": "governance", "text": "What incident response procedure exists?"},
    18: {"category": "governance", "text": "What data retention and deletion policy applies?"},
}


@app.get("/v1/compliance/gate", tags=["Compliance"])
async def get_compliance_gate(op=Depends(require_permission(Permission.VIEW_GATE))):
    """Get compliance gate status and all questions."""
    return {
        "gate_cleared": settings.compliance.gate_cleared,
        "total_questions": 18,
        "questions": COMPLIANCE_QUESTIONS,
    }


@app.post("/v1/compliance/gate/answer", tags=["Compliance"])
async def answer_compliance_question(
    body: ComplianceGateAnswerRequest,
    op=Depends(require_permission(Permission.ANSWER_GATE))
):
    """Record an answer to a compliance gate question."""
    if body.question_id not in COMPLIANCE_QUESTIONS:
        raise HTTPException(status_code=400, detail=f"Invalid question_id: {body.question_id}")

    audit.log(
        AuditEventType.COMPLIANCE_GATE_CHECK,
        actor=op.operator_id,
        details={
            "action": "question_answered",
            "question_id": body.question_id,
            "answered_by": body.answered_by,
        }
    )
    return {
        "status": "recorded",
        "question_id": body.question_id,
        "question_text": COMPLIANCE_QUESTIONS[body.question_id]["text"],
    }


# ─────────────────────────────────────────────
# EXCEPTION ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/v1/exceptions", tags=["Exceptions"])
async def list_exceptions(
    status: str = Query("open"),
    op=Depends(require_permission(Permission.VIEW_EXCEPTIONS))
):
    exceptions = await db.list_exceptions(status=status)
    return {
        "count": len(exceptions),
        "exceptions": [
            {
                "id": e.id,
                "message_id": e.message_id,
                "reason": e.reason,
                "flags": json.loads(e.flags or "[]"),
                "status": e.status,
                "created_at": e.created_at.isoformat(),
            }
            for e in exceptions
        ]
    }


@app.patch("/v1/exceptions/{exception_id}/resolve", tags=["Exceptions"])
async def resolve_exception(
    exception_id: str,
    body: ExceptionResolutionRequest,
    op=Depends(require_permission(Permission.RESOLVE_EXCEPTION))
):
    audit.log(
        AuditEventType.EXCEPTION_REVIEWED,
        actor=op.operator_id,
        details={
            "exception_id": exception_id,
            "resolution": body.resolution,
            "resolved_by": body.resolved_by,
        }
    )
    return {"status": "resolved", "exception_id": exception_id}


# ─────────────────────────────────────────────
# REGISTRY ENDPOINTS
# ─────────────────────────────────────────────

@app.post("/v1/registry/senders", tags=["Registry"])
async def register_sender(
    body: RegisterSenderRequest,
    op=Depends(require_permission(Permission.MANAGE_REGISTRY))
):
    sender = await db.register_sender(
        entity_id=body.entity_id,
        entity_name=body.entity_name,
        jurisdiction=body.jurisdiction,
        notes=body.notes,
    )
    audit.log(
        AuditEventType.OPERATOR_ACTION,
        actor=op.operator_id,
        details={"action": "sender_registered", "entity_id": body.entity_id}
    )
    return {"status": "registered", "entity_id": sender.entity_id}


# ─────────────────────────────────────────────
# AUDIT ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/v1/audit/export", tags=["Audit"])
async def export_audit(
    message_id: Optional[str] = Query(None),
    op=Depends(require_permission(Permission.EXPORT_AUDIT))
):
    """Export audit events. Filter by message_id if provided."""
    events = audit.export_audit_report(message_id=message_id)
    return {"count": len(events), "events": events}


# ─────────────────────────────────────────────
# DELIVERY WEBHOOK (receiver acknowledgement)
# ─────────────────────────────────────────────

class DeliveryAckRequest(BaseModel):
    message_id: str
    delivery_id: str
    status: str
    received_at: Optional[str] = None


@app.post("/v1/delivery/acknowledge", tags=["Delivery"])
async def acknowledge_delivery(
    body: DeliveryAckRequest,
    x_sankofa_api_key: str = Header(..., alias="X-SANKOFA-API-Key")
):
    """
    Receiver system calls this endpoint to acknowledge delivery.
    This closes the full file lifecycle.
    """
    operator = rbac.authenticate(x_sankofa_api_key)
    if not operator:
        raise HTTPException(status_code=401, detail="Invalid API key")

    audit.log(
        AuditEventType.FILE_ACKNOWLEDGED,
        actor=f"receiver:{operator.operator_id}",
        details={
            "delivery_id": body.delivery_id,
            "status": body.status,
            "received_at": body.received_at,
        },
        message_id=body.message_id,
    )
    return {"status": "acknowledged", "message_id": body.message_id}


# ─────────────────────────────────────────────
# COPILOT ENDPOINTS (Layer 7)
# ─────────────────────────────────────────────

class CopilotQueryRequest(BaseModel):
    query: str
    context: Optional[dict] = None


class ExplainFlagRequest(BaseModel):
    flag_code: str


class GuideExceptionRequest(BaseModel):
    exception_id: str


@app.post("/v1/copilot/query", tags=["Copilot"])
async def copilot_query(
    body: CopilotQueryRequest,
    op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))
):
    """
    Natural language query to the VPF Intelligence Copilot.
    Returns structured guidance, explanations, and actionable intelligence.
    The copilot informs — the custodian decides.
    """
    # Build live system state for context
    stats = await db.get_stats()
    exceptions = await db.list_exceptions(status="open")
    state = {
        "gate_cleared": settings.compliance.gate_cleared,
        "connector_type": settings.connector_type.value,
        "exceptions_open": len(exceptions),
        "total_messages": sum(stats.values()),
        "stats": {
            k.value if hasattr(k, "value") else str(k): v
            for k, v in stats.items()
        },
        "jurisdiction": settings.compliance.jurisdiction,
        **(body.context or {}),
    }
    response = copilot.query(
        text=body.query,
        operator_id=op.operator_id,
        system_state=state,
    )
    return response.to_dict()


@app.post("/v1/copilot/explain-flag", tags=["Copilot"])
async def explain_flag(
    body: ExplainFlagRequest,
    op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))
):
    """Get a plain-language explanation of a compliance flag with regulatory context."""
    response = copilot.explain_flag(body.flag_code)
    return response.to_dict()


@app.post("/v1/copilot/guide-exception", tags=["Copilot"])
async def guide_exception(
    body: GuideExceptionRequest,
    op=Depends(require_permission(Permission.VIEW_EXCEPTIONS))
):
    """Get step-by-step guidance for reviewing a specific exception."""
    exceptions = await db.list_exceptions(status="open")
    exc_record = next(
        (e for e in exceptions if e.id == body.exception_id), None
    )
    if not exc_record:
        raise HTTPException(status_code=404, detail="Exception not found")

    import json as _json
    record_dict = {
        "exception_id": exc_record.id,
        "message_id": exc_record.message_id,
        "reason": exc_record.reason,
        "flags": _json.loads(exc_record.flags or "[]"),
        "priority": exc_record.status,
    }
    response = copilot.guide_exception_review(record_dict)
    return response.to_dict()


@app.get("/v1/copilot/regulatory-briefing", tags=["Copilot"])
async def regulatory_briefing(
    jurisdiction: str = "GH",
    op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))
):
    """Get a regulatory briefing for a specific jurisdiction."""
    response = copilot.generate_regulatory_briefing(jurisdiction)
    return response.to_dict()


@app.get("/v1/copilot/status", tags=["Copilot"])
async def copilot_status(
    op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))
):
    """Get a natural language system status summary from the copilot."""
    stats = await db.get_stats()
    exceptions = await db.list_exceptions(status="open")
    state = {
        "gate_cleared": settings.compliance.gate_cleared,
        "connector_type": settings.connector_type.value,
        "exceptions_open": len(exceptions),
        "total_messages": sum(stats.values()),
        "stats": {
            k.value if hasattr(k, "value") else str(k): v
            for k, v in stats.items()
        },
        "jurisdiction": settings.compliance.jurisdiction,
    }
    response = copilot.generate_status_summary(state)
    return response.to_dict()


# ─────────────────────────────────────────────
# STAGE 6 — LIVE INTELLIGENCE ENDPOINTS
# ─────────────────────────────────────────────

class LiveQueryRequest(BaseModel):
    query: str
    context: Optional[dict] = None


class ComplianceReportRequest(BaseModel):
    message_id: str


class CorrespondenceRequest(BaseModel):
    recipient: str
    subject: str
    context: dict


@app.post("/v1/copilot/live-query", tags=["Copilot — Live Intelligence"])
async def live_copilot_query(
    body: LiveQueryRequest,
    op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))
):
    """
    Live Claude API-powered natural language query.
    Maintains multi-turn conversation history per operator session.
    Requires ANTHROPIC_API_KEY environment variable.
    Falls back gracefully if API key is not configured.
    """
    stats = await db.get_stats()
    exceptions = await db.list_exceptions(status="open")
    state = {
        "gate_cleared": settings.compliance.gate_cleared,
        "connector_type": settings.connector_type.value,
        "exceptions_open": len(exceptions),
        "total_messages": sum(stats.values()),
        "jurisdiction": settings.compliance.jurisdiction,
        **(body.context or {}),
    }
    return await live_copilot.query(
        text=body.query,
        operator_id=op.operator_id,
        system_state=state,
    )


@app.post("/v1/copilot/generate-compliance-report", tags=["Copilot — Live Intelligence"])
async def generate_compliance_report(
    body: ComplianceReportRequest,
    op=Depends(require_permission(Permission.EXPORT_AUDIT))
):
    """
    Generate a formal regulatory compliance report for a specific message.
    Suitable for Bank of Ghana submission.
    Requires ANTHROPIC_API_KEY.
    """
    msg = await db.get_message(body.message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    import json as _json
    message_audit = {
        "message_id": msg.message_id,
        "file_name": msg.file_name,
        "sender_entity_id": msg.sender_entity_id,
        "receiver_entity_id": msg.receiver_entity_id,
        "jurisdiction": msg.jurisdiction,
        "state": msg.state.value if hasattr(msg.state, "value") else str(msg.state),
        "compliance_flags": _json.loads(msg.compliance_flags or "[]"),
        "received_at_utc": msg.received_at_utc.isoformat() if msg.received_at_utc else None,
    }
    compliance_data = {
        "validation_status": msg.validation_status,
        "validation_errors": _json.loads(msg.validation_errors or "[]"),
        "exception_reason": msg.exception_reason,
    }
    report = await live_copilot.generate_compliance_report(
        message_audit=message_audit,
        compliance_report=compliance_data,
        operator_id=op.operator_id,
    )
    return {"report": report, "message_id": body.message_id,
            "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()}


@app.post("/v1/copilot/draft-correspondence", tags=["Copilot — Live Intelligence"])
async def draft_correspondence(
    body: CorrespondenceRequest,
    op=Depends(require_permission(Permission.EXPORT_AUDIT))
):
    """
    Draft formal regulatory correspondence (STR, CTR, inquiry response).
    Requires ANTHROPIC_API_KEY.
    """
    correspondence = await live_copilot.generate_regulatory_correspondence(
        recipient=body.recipient,
        subject=body.subject,
        context=body.context,
        operator_id=op.operator_id,
    )
    return {"correspondence": correspondence, "recipient": body.recipient,
            "drafted_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()}


@app.delete("/v1/copilot/session", tags=["Copilot — Live Intelligence"])
async def clear_copilot_session(
    op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))
):
    """Clear the current operator's conversation history to start a fresh session."""
    live_copilot.clear_session(op.operator_id)
    return {"status": "cleared", "operator_id": op.operator_id}


@app.get("/v1/copilot/intelligence-status", tags=["Copilot — Live Intelligence"])
async def intelligence_status(
    op=Depends(require_permission(Permission.VIEW_SYSTEM_STATUS))
):
    """Check whether live Claude API intelligence is configured and available."""
    configured = live_copilot.is_configured()
    return {
        "live_intelligence": configured,
        "model": live_copilot.MODEL if configured else None,
        "active_sessions": live_copilot.session_store.active_count(),
        "note": (
            "Live intelligence active." if configured
            else "Set ANTHROPIC_API_KEY to enable live Claude intelligence. Rule-based copilot is available at /v1/copilot/query."
        ),
    }


# ─────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────

def _msg_to_summary(msg) -> dict:
    return {
        "message_id": msg.message_id,
        "file_name": msg.file_name,
        "file_format": msg.file_format,
        "source_system": msg.source_system,
        "sender_entity_id": msg.sender_entity_id,
        "receiver_entity_id": msg.receiver_entity_id,
        "state": msg.state.value if hasattr(msg.state, 'value') else str(msg.state),
        "file_hash_sha256": msg.file_hash_sha256,
        "jurisdiction": msg.jurisdiction,
        "compliance_flags": json.loads(msg.compliance_flags or "[]"),
        "exception_reason": msg.exception_reason,
        "delivery_id": msg.delivery_id,
        "received_at_utc": msg.received_at_utc.isoformat() if msg.received_at_utc else None,
        "created_at": msg.created_at.isoformat() if msg.created_at else "",
    }
