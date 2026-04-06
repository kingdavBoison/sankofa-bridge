"""
SANKƆFA-BRIDGE — Intelligence Copilot (Layer 7)
Stage 4 — VPF Intelligence Layer

The copilot is the human-AI interface of the sovereignty architecture.
It reads live system state, reasons through compliance flags, guides
custodian decisions, and generates regulatory evidence packages.

VPF Design Principles enforced here:
  1. Human custodianship — copilot informs, never decides
  2. African epistemologies — reasoning frames are Sankofa-first
  3. Auditability — every copilot action is logged
  4. Role boundaries — copilot refuses financial decision requests
  5. Institutional intelligence — outputs legible to African regulators

The copilot has five intelligence modes:
  STATUS    — reads and summarises live system state
  EXPLAIN   — explains compliance flags in plain language
  GUIDE     — walks custodian through exception review workflow
  REPORT    — generates regulatory-ready evidence packages
  ADVISE    — strategic guidance on system configuration
"""

import json
from datetime import datetime, timezone
from typing import Optional

from config.models import FileState
from config.settings import settings
from compliance.engine import ComplianceFlag, ComplianceSeverity, AFRICAN_CORRIDOR
from audit.logger import audit, AuditEventType


# ─────────────────────────────────────────────
# COPILOT RESPONSE
# ─────────────────────────────────────────────

class CopilotResponse:
    def __init__(
        self,
        message: str,
        mode: str,
        actions: list = None,
        data: dict = None,
        requires_human_decision: bool = False,
        vpf_note: str = "",
    ):
        self.message = message
        self.mode = mode
        self.actions = actions or []
        self.data = data or {}
        self.requires_human_decision = requires_human_decision
        self.vpf_note = vpf_note
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "message": self.message,
            "mode": self.mode,
            "actions": self.actions,
            "data": self.data,
            "requires_human_decision": self.requires_human_decision,
            "vpf_note": self.vpf_note,
            "timestamp": self.timestamp,
        }


# ─────────────────────────────────────────────
# PROHIBITED RESPONSE — VPF boundary enforcement
# ─────────────────────────────────────────────

PROHIBITED_INTENTS = [
    "hold funds", "hold_funds",
    "sign transaction", "sign_transaction", "sign blockchain", "sign this",
    "approve settlement", "approve_settlement",
    "tokenize", "tokenisation", "tokenization",
    "custody", "custodial",
    "broadcast transaction", "broadcast_transaction",
    "move funds", "transfer funds",
    "wallet key", "private key",
    "bypass compliance", "skip compliance", "override compliance",
    "ignore sanctions", "bypass sanctions",
]

PROHIBITED_RESPONSE = CopilotResponse(
    message=(
        "That action is outside the defined scope of SANKƆFA-BRIDGE under "
        "VPF governance. This system operates exclusively as a secure data "
        "integration layer. It does not hold funds, sign or broadcast "
        "blockchain transactions, approve settlements, tokenize assets, "
        "custody digital assets, or bypass compliance controls. "
        "Those decisions and actions belong with licensed financial principals "
        "and their designated compliance officers — not with this system."
    ),
    mode="BOUNDARY",
    requires_human_decision=False,
    vpf_note=(
        "VPF Role Boundary: SANKƆFA-BRIDGE is a sovereign integration layer, "
        "not a financial intermediary."
    ),
)


# ─────────────────────────────────────────────
# FLAG EXPLANATIONS — plain language for each compliance flag
# African institutional context throughout
# ─────────────────────────────────────────────

FLAG_EXPLANATIONS = {
    ComplianceFlag.JURISDICTION_MISMATCH: {
        "title": "Jurisdiction mismatch",
        "plain": (
            "The jurisdiction declared in the file does not match the expected corridor. "
            "Verify the sending and receiving jurisdictions against the registered partner profile."
        ),
        "action": "Verify file jurisdiction against registered partner corridor.",
        "regulatory_basis": "VPF Partner Registry — Corridor Enforcement",
    },
    ComplianceFlag.UNSUPPORTED_JURISDICTION: {
        "title": "Unsupported jurisdiction",
        "plain": (
            "The transaction jurisdiction is outside the supported African digital finance corridor. "
            "SANKƆFA-BRIDGE currently supports: GH, NG, KE, RW, ZA, TZ, UG, SN, CI, ET. "
            "Transactions involving other jurisdictions require manual compliance review and "
            "potentially additional regulatory clearance."
        ),
        "action": "Verify jurisdiction. If legitimate, add to supported corridor with compliance approval.",
        "regulatory_basis": "VPF African Corridor Configuration",
    },
    ComplianceFlag.AML_UNUSUAL_PATTERN: {
        "title": "Unusual AML pattern",
        "plain": (
            "The system detected an unusual pattern in this sender's transaction behaviour "
            "that does not fit standard velocity or structuring categories but warrants review. "
            "Review the full sender activity log for context."
        ),
        "action": "Review sender activity log. Document findings.",
        "regulatory_basis": "FATF Recommendation 20 — Suspicious Transaction Reporting",
    },
    ComplianceFlag.KYC_SENDER_NOT_REGISTERED: {
        "title": "Sender not in KYC registry",
        "plain": (
            "The sending entity is not registered in the KYC registry. "
            "No transaction should proceed from an unregistered sender. "
            "Register and verify the sender before approving any retry."
        ),
        "action": "Register sender in registry. Complete KYC before retry.",
        "regulatory_basis": "FATF Recommendations 10-12 — Customer Due Diligence",
    },
    ComplianceFlag.KYC_RECEIVER_NOT_REGISTERED: {
        "title": "Receiver not in KYC registry",
        "plain": (
            "The receiving entity is not registered in the KYC registry. "
            "Delivering to an unregistered receiver creates regulatory exposure. "
            "Register and verify the receiver before approving any retry."
        ),
        "action": "Register receiver in registry. Complete KYC before retry.",
        "regulatory_basis": "FATF Recommendations 10-12 — Customer Due Diligence",
    },
    ComplianceFlag.SENDER_ID_MISSING: {
        "title": "Sender ID missing",
        "plain": (
            "The sender_entity_id field is empty. This is a hard provenance failure. "
            "No transaction can be processed without a identified sender. "
            "The source file or connector configuration must be corrected."
        ),
        "action": "Fix at connector or source. Sender identity is mandatory.",
        "regulatory_basis": "VPF Principle — No data moves without provenance",
    },
    ComplianceFlag.RECEIVER_ID_MISSING: {
        "title": "Receiver ID missing",
        "plain": (
            "The receiver_entity_id field is empty. "
            "The transformation layer must extract or inject the receiver identity "
            "before delivery can proceed. Review the field mapping configuration."
        ),
        "action": "Fix at transformation layer. Receiver identity is mandatory.",
        "regulatory_basis": "VPF Principle — No data moves without provenance",
    },
    ComplianceFlag.SANCTIONS_SCREENING_SKIPPED: {
        "title": "Sanctions screening disabled",
        "plain": (
            "Sanctions screening has been disabled in system configuration. "
            "This is only acceptable in controlled test environments. "
            "In any production or near-production environment, sanctions screening "
            "must be active. Re-enable it immediately by setting "
            "sanctions_screening_enabled = True in compliance configuration."
        ),
        "action": "Re-enable sanctions screening before any production activity.",
        "regulatory_basis": "FATF Recommendation 6 — Targeted Financial Sanctions",
    },
    ComplianceFlag.SANCTIONS_HIT_SENDER: {
        "title": "Sanctions match — sender",
        "plain": (
            "The sending entity matched an entry in the sanctions watchlist. "
            "This is a critical compliance block. Under Bank of Ghana AML/CFT "
            "guidelines and international FATF standards, no transaction may proceed "
            "with a sanctioned party. This requires immediate escalation to your "
            "chief compliance officer and likely notification to regulators."
        ),
        "action": "Escalate immediately. Do not approve retry. File STR if required.",
        "regulatory_basis": "FATF Recommendation 6 — Targeted Financial Sanctions",
    },
    ComplianceFlag.SANCTIONS_HIT_RECEIVER: {
        "title": "Sanctions match — receiver",
        "plain": (
            "The receiving entity matched an entry in the sanctions watchlist. "
            "Delivering data or instructions to a sanctioned entity — even indirectly — "
            "creates regulatory exposure. This requires the same escalation path as a "
            "sanctioned sender."
        ),
        "action": "Escalate immediately. Do not approve retry.",
        "regulatory_basis": "FATF Recommendation 6 — Targeted Financial Sanctions",
    },
    ComplianceFlag.HIGH_RISK_JURISDICTION: {
        "title": "High-risk jurisdiction",
        "plain": (
            "The jurisdiction associated with this transaction is on the FATF "
            "high-risk or grey list. Transactions involving these jurisdictions "
            "require enhanced due diligence under Bank of Ghana guidelines. "
            "This does not automatically mean the transaction is fraudulent — "
            "it means additional verification is required before proceeding."
        ),
        "action": "Enhanced due diligence required. Compliance officer review before retry.",
        "regulatory_basis": "FATF High-Risk Jurisdictions — Enhanced Due Diligence",
    },
    ComplianceFlag.AML_VELOCITY_BREACH: {
        "title": "AML velocity breach",
        "plain": (
            "This sender has submitted more files in a 24-hour window than the "
            "configured threshold allows. High transaction velocity is a known "
            "indicator of potential money laundering activity. This flag does not "
            "confirm wrongdoing — it means the pattern warrants review."
        ),
        "action": "Review sender's full activity log. Verify business justification for volume.",
        "regulatory_basis": "FATF Recommendation 20 — Suspicious Transaction Reporting",
    },
    ComplianceFlag.AML_STRUCTURING_SUSPECTED: {
        "title": "Structuring pattern suspected",
        "plain": (
            "Multiple files from this sender arrived within a short time window. "
            "Structuring — breaking up large transactions into smaller ones to avoid "
            "reporting thresholds — is a money laundering red flag. Review whether "
            "these files represent legitimate business volume or an attempt to "
            "circumvent controls."
        ),
        "action": "Review file amounts and timing. File STR if structuring is confirmed.",
        "regulatory_basis": "FATF Recommendation 20 — Suspicious Transaction Reporting",
    },
    ComplianceFlag.AML_THRESHOLD_BREACH: {
        "title": "Reporting threshold reached",
        "plain": (
            "The transaction amount meets or exceeds the configured reporting "
            "threshold. Under Bank of Ghana regulations, transactions at or above "
            "this level may require a Suspicious Transaction Report (STR) if "
            "suspicious indicators are present, or a Currency Transaction Report (CTR) "
            "for cash-equivalent transactions."
        ),
        "action": "Review for STR/CTR requirements. Document basis for proceeding.",
        "regulatory_basis": "Bank of Ghana AML/CFT Directive — Transaction Reporting",
    },
    ComplianceFlag.KYC_VERIFICATION_PENDING: {
        "title": "KYC not yet verified",
        "plain": (
            "The sender has not been verified in the KYC registry. Know Your Customer "
            "verification is a foundational requirement before processing transactions "
            "on behalf of any entity. This is a warning — the transaction can proceed "
            "with compliance officer approval — but KYC completion should be "
            "prioritised immediately."
        ),
        "action": "Complete KYC verification for this sender. Register in sender registry.",
        "regulatory_basis": "FATF Recommendations 10-12 — Customer Due Diligence",
    },
    ComplianceFlag.PROVENANCE_INCOMPLETE: {
        "title": "Provenance fields missing",
        "plain": (
            "One or more mandatory provenance fields are missing from this message. "
            "Under VPF governance, no data moves without complete provenance. "
            "Missing fields create gaps in the audit trail that could create "
            "regulatory exposure. The connector or transformation layer needs "
            "to be reviewed to ensure these fields are being populated."
        ),
        "action": "Identify which fields are missing. Fix at connector or transformation layer.",
        "regulatory_basis": "VPF Principle — No data moves without provenance",
    },
    ComplianceFlag.COMPLIANCE_GATE_NOT_CLEARED: {
        "title": "Compliance gate not cleared",
        "plain": (
            "The 18-question compliance gate has not been fully answered. "
            "This is a system-level block — no live delivery proceeds until the "
            "gate is cleared. This protects you, the system operator, from "
            "unknowingly processing transactions without the proper legal and "
            "compliance framework in place."
        ),
        "action": "Complete all 18 compliance gate questions. See /v1/compliance/gate.",
        "regulatory_basis": "VPF Stage 0 — Sovereignty Declaration",
    },
}


# ─────────────────────────────────────────────
# COPILOT ENGINE
# ─────────────────────────────────────────────

class CopilotEngine:
    """
    Layer 7 — VPF Intelligence Copilot.

    Processes natural language queries from the custodian
    and returns structured, actionable intelligence.

    Always defers financial decisions to humans.
    Always grounds reasoning in African regulatory context.
    Always logs its actions to the audit ledger.
    """

    ACTOR = "CopilotEngine"

    def __init__(self):
        # System state is injected at query time — copilot reads live state
        self._session_context: dict = {}

    def query(
        self,
        text: str,
        operator_id: str,
        system_state: Optional[dict] = None,
    ) -> CopilotResponse:
        """
        Process a natural language query from the custodian.
        Routes to the appropriate intelligence mode.
        """
        text_lower = text.lower().strip()

        # VPF boundary check — refuse prohibited intents
        if self._is_prohibited(text_lower):
            audit.log(
                AuditEventType.PROHIBITED_ACTION_BLOCKED,
                actor=operator_id,
                details={
                    "query": text[:100],
                    "result": "COPILOT_REFUSED",
                    "reason": "Prohibited intent detected",
                }
            )
            return PROHIBITED_RESPONSE

        # Log the query
        audit.log(
            AuditEventType.OPERATOR_ACTION,
            actor=operator_id,
            details={"action": "copilot_query", "query_preview": text[:80]},
        )

        # Route to intelligence mode
        response = self._route(text_lower, text, system_state or {}, operator_id)

        return response

    def explain_flag(self, flag_code: str) -> CopilotResponse:
        """Deep explanation of a specific compliance flag."""
        try:
            flag = ComplianceFlag(flag_code)
        except ValueError:
            return CopilotResponse(
                message=f"Unknown flag code: {flag_code}. Known flags: {[f.value for f in ComplianceFlag]}",
                mode="EXPLAIN",
            )

        info = FLAG_EXPLANATIONS.get(flag)
        if not info:
            return CopilotResponse(
                message=f"Flag '{flag_code}' is recorded but no detailed explanation is available yet.",
                mode="EXPLAIN",
            )

        return CopilotResponse(
            message=info["plain"],
            mode="EXPLAIN",
            data={
                "flag": flag_code,
                "title": info["title"],
                "recommended_action": info["action"],
                "regulatory_basis": info["regulatory_basis"],
            },
            requires_human_decision=True,
            vpf_note="Compliance decisions require a human officer — the copilot explains, you decide.",
        )

    def guide_exception_review(self, exception_record: dict) -> CopilotResponse:
        """
        Step-by-step guidance for reviewing a specific exception.
        Presents the facts, explains the flags, and asks the right questions
        without making the decision.
        """
        flags = exception_record.get("flags", [])
        priority = exception_record.get("priority", "medium")
        reason = exception_record.get("reason", "")

        flag_summaries = []
        for f in flags:
            info = FLAG_EXPLANATIONS.get(ComplianceFlag(f) if f in [cf.value for cf in ComplianceFlag] else None)
            if info:
                flag_summaries.append(f"• {info['title']}: {info['action']}")

        steps = self._build_review_steps(flags, priority)

        message = (
            f"Exception review guidance for: {exception_record.get('exception_id', 'Unknown')}.\n\n"
            f"Priority: {priority.upper()}\n"
            f"Reason: {reason}\n\n"
            f"Compliance flags raised:\n" +
            ("\n".join(flag_summaries) if flag_summaries else "No specific flags detailed.") +
            f"\n\nReview steps:\n" +
            "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        )

        return CopilotResponse(
            message=message,
            mode="GUIDE",
            data={
                "exception_id": exception_record.get("exception_id"),
                "review_steps": steps,
                "flags_explained": flag_summaries,
            },
            actions=[
                {"label": "Approve retry", "action": "resolve_retry", "requires_confirmation": True},
                {"label": "Reject permanently", "action": "reject", "requires_confirmation": True},
                {"label": "Escalate to senior compliance", "action": "escalate", "requires_confirmation": True},
            ],
            requires_human_decision=True,
            vpf_note=(
                "VPF Custodianship: You are the decision-maker. "
                "The copilot presents the facts; you authorise the outcome."
            ),
        )

    def generate_status_summary(self, system_state: dict) -> CopilotResponse:
        """Plain-language system status for the custodian."""
        stats = system_state.get("stats", {})
        gate = system_state.get("gate_cleared", False)
        connector = system_state.get("connector_type", "unknown")
        exceptions_open = system_state.get("exceptions_open", 0)
        total = system_state.get("total_messages", 0)

        issues = []
        if not gate:
            issues.append("Compliance gate is not cleared — live delivery is blocked.")
        if exceptions_open > 0:
            issues.append(f"{exceptions_open} open exception(s) require your review.")
        if connector == "mock":
            issues.append("System is running on MockConnector — no real source is connected.")

        health = "healthy" if not issues else ("attention needed" if len(issues) == 1 else "multiple issues")

        parts = [
            f"System status: {health.upper()}.",
            f"Connector: {connector}.",
            f"Compliance gate: {'CLEARED' if gate else 'NOT CLEARED'}.",
            f"Total messages processed: {total}.",
        ]
        if stats:
            state_line = ", ".join(f"{k}: {v}" for k, v in stats.items())
            parts.append(f"Message states — {state_line}.")
        if issues:
            parts.append("\nItems requiring your attention:")
            parts.extend(f"  • {i}" for i in issues)
        else:
            parts.append("No items requiring immediate attention.")

        return CopilotResponse(
            message="\n".join(parts),
            mode="STATUS",
            data=system_state,
            requires_human_decision=bool(issues),
            actions=[
                {"label": "View compliance gate", "action": "navigate_compliance_gate"},
                {"label": "Review open exceptions", "action": "navigate_exceptions"},
            ] if issues else [],
        )

    def generate_regulatory_briefing(self, jurisdiction: str = "GH") -> CopilotResponse:
        """
        Generate a regulatory briefing for the target jurisdiction.
        Grounds the system's compliance posture in local context.
        """
        jur_info = AFRICAN_CORRIDOR.get(jurisdiction, {})
        jur_name = jur_info.get("name", jurisdiction)
        risk_tier = jur_info.get("risk_tier", "unknown")
        fatf_member = jur_info.get("fatf_member", False)

        message = (
            f"Regulatory briefing — {jur_name} ({jurisdiction}).\n\n"
            f"FATF member: {'Yes' if fatf_member else 'No'}. "
            f"Risk tier: {risk_tier} (1 = lowest risk).\n\n"
            f"Key regulatory bodies:\n"
            f"  • Bank of Ghana (BoG) — primary AML/CFT supervisor\n"
            f"  • Securities and Exchange Commission Ghana (SEC)\n"
            f"  • Ghana Revenue Authority (GRA) — tax and reporting\n\n"
            f"Relevant regulations:\n"
            f"  • Anti-Money Laundering Act 2020 (Act 1044)\n"
            f"  • Payment Systems and Services Act 2019 (Act 987)\n"
            f"  • Data Protection Act 2012 (Act 843)\n\n"
            f"SANKƆFA-BRIDGE compliance posture for {jur_name}:\n"
            f"  • AML velocity and threshold checks active\n"
            f"  • Sanctions screening active (update from BoG watchlist)\n"
            f"  • KYC registry verification required for all senders\n"
            f"  • Full audit trail maintained for 7-year retention\n"
            f"  • Evidence packages exportable for regulatory submission"
        )

        return CopilotResponse(
            message=message,
            mode="ADVISE",
            data={"jurisdiction": jurisdiction, "jur_info": jur_info},
            vpf_note=(
                "VPF Indigenous Intelligence: regulatory frameworks are read "
                "through the lens of African institutional context, not imported defaults."
            ),
        )

    # ─────────────────────────────────────────
    # ROUTING
    # ─────────────────────────────────────────

    def _route(self, text_lower: str, text_orig: str, state: dict, operator_id: str) -> CopilotResponse:
        # STATUS queries
        if any(w in text_lower for w in ["status", "how is", "what is happening", "overview", "summary", "health"]):
            return self.generate_status_summary(state)

        # EXPLAIN flag queries
        for flag in ComplianceFlag:
            if flag.value.lower() in text_lower or flag.value.replace("_", " ").lower() in text_lower:
                return self.explain_flag(flag.value)

        if any(w in text_lower for w in ["explain", "what does", "what is", "mean", "flag", "why is"]):
            return self._explain_general(text_lower, state)

        # GUIDE exception queries
        if any(w in text_lower for w in ["exception", "review", "blocked", "resolve", "escalate", "reject"]):
            return self._guide_general(text_lower, state)

        # REPORT queries
        if any(w in text_lower for w in ["report", "evidence", "regulatory", "package", "export", "audit"]):
            return self._report_guidance(state)

        # ADVISE — regulatory and strategic
        if any(w in text_lower for w in ["ghana", "regulation", "compliance", "aml", "kyc", "fatf", "bank of ghana"]):
            return self.generate_regulatory_briefing(state.get("jurisdiction", "GH"))

        # GATE queries
        if any(w in text_lower for w in ["gate", "question", "clear", "proceed", "production"]):
            return self._gate_guidance(state)

        # CONNECTOR queries
        if any(w in text_lower for w in ["connector", "source", "server", "sftp", "s3", "api", "connect"]):
            return self._connector_guidance(state)

        # ROLE queries — who am I, what can I do
        if any(w in text_lower for w in ["my role", "custodian", "vpf", "what can i", "what should i"]):
            return self._role_guidance(operator_id)

        # Default — helpful orientation
        return self._default_response(state)

    def _explain_general(self, text: str, state: dict) -> CopilotResponse:
        return CopilotResponse(
            message=(
                "I can explain any compliance flag in detail. "
                "Ask me to explain a specific flag by name — for example: "
                "'explain SANCTIONS_HIT_SENDER' or 'what does AML_VELOCITY_BREACH mean'. "
                "I can also explain system concepts, jurisdiction rules, or the compliance gate."
            ),
            mode="EXPLAIN",
            actions=[
                {"label": f"Explain {f.value}", "action": f"explain_{f.value}"}
                for f in list(ComplianceFlag)[:5]
            ],
        )

    def _guide_general(self, text: str, state: dict) -> CopilotResponse:
        open_count = state.get("exceptions_open", 0)
        return CopilotResponse(
            message=(
                f"There are currently {open_count} open exception(s) in the queue. "
                "To review a specific exception, ask me to guide you through it — "
                "for example: 'guide me through exception EXC-XXXXXXXX'. "
                "I will walk you through the flags, explain each one in plain language, "
                "and present the options. The decision is always yours."
            ),
            mode="GUIDE",
            requires_human_decision=open_count > 0,
            actions=[{"label": "View open exceptions", "action": "navigate_exceptions"}],
        )

    def _report_guidance(self, state: dict) -> CopilotResponse:
        return CopilotResponse(
            message=(
                "I can generate three types of regulatory output:\n\n"
                "1. Evidence package — full provenance, compliance report, and chain of custody "
                "for a specific message. Suitable for Bank of Ghana submission.\n\n"
                "2. Audit export — complete immutable event log for a date range or message ID. "
                "Use: GET /v1/audit/export\n\n"
                "3. Exception summary — all flagged messages with outcomes, for compliance review. "
                "Use: GET /v1/exceptions\n\n"
                "Specify a message ID and I will help you build the evidence package."
            ),
            mode="REPORT",
            data={"endpoints": ["/v1/audit/export", "/v1/exceptions", "/v1/files/{message_id}"]},
        )

    def _gate_guidance(self, state: dict) -> CopilotResponse:
        gate_cleared = state.get("gate_cleared", False)
        if gate_cleared:
            return CopilotResponse(
                message=(
                    "The compliance gate is cleared. All 18 questions have been answered. "
                    "The system is authorised to proceed to live delivery once the "
                    "receiver API endpoint is configured."
                ),
                mode="ADVISE",
            )
        return CopilotResponse(
            message=(
                "The compliance gate is not yet cleared. This is the single most important "
                "action before live deployment. The gate has 18 questions across three categories:\n\n"
                "Legal & Jurisdictional (Q1–7): Who are the parties, what licences apply, "
                "who owns AML/KYC responsibility.\n\n"
                "Technical (Q8–13): What is the source system, what is the file format, "
                "what is the receiver API contract.\n\n"
                "Governance (Q14–18): Is there a formal contract, what is the compensation model, "
                "who has final settlement authority.\n\n"
                "Use POST /v1/compliance/gate/answer to record each answer as you receive it. "
                "Once all 18 are answered, set compliance.gate_cleared = True in configuration."
            ),
            mode="GUIDE",
            data={"gate_cleared": False, "endpoint": "/v1/compliance/gate"},
            requires_human_decision=True,
            actions=[{"label": "View compliance gate", "action": "navigate_compliance_gate"}],
        )

    def _connector_guidance(self, state: dict) -> CopilotResponse:
        connector = state.get("connector_type", "mock")
        return CopilotResponse(
            message=(
                f"Current connector: {connector.upper()}.\n\n"
                "SANKƆFA-BRIDGE supports four source system types:\n\n"
                "S3 — AWS object storage. Set: S3_BUCKET, S3_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.\n"
                "SFTP — SSH secure file transfer. Set: SFTP_HOST, SFTP_PORT, SFTP_USER, SFTP_KEY_PATH.\n"
                "REST_API — Third-party API endpoint. Set: SOURCE_API_URL, SOURCE_API_KEY.\n"
                "AZURE_BLOB — Azure Blob Storage. Set: AZURE_CONNECTION_STRING, AZURE_CONTAINER.\n\n"
                "Once the counterparty confirms their system type, change ACTIVE_CONNECTOR "
                "in config/settings.py. The rest of the pipeline is unaffected."
                + (
                    "\n\nCurrently running on MOCK — no real source connected. "
                    "Safe for testing, not for production."
                    if connector == "mock" else ""
                )
            ),
            mode="ADVISE",
            data={"current_connector": connector},
            actions=[{"label": "View connector config", "action": "view_settings"}],
        )

    def _role_guidance(self, operator_id: str) -> CopilotResponse:
        return CopilotResponse(
            message=(
                f"Your role: System Architect and Custodian under VPF governance.\n\n"
                "What this means:\n\n"
                "Authority you hold:\n"
                "  • Full system design and configuration authority\n"
                "  • Exception review and resolution authority\n"
                "  • Compliance gate management\n"
                "  • Operator registration and access control\n"
                "  • Regulatory reporting and evidence generation\n\n"
                "Authority that remains with other principals:\n"
                "  • Transaction approval or settlement authority\n"
                "  • Fund custody or movement authority\n"
                "  • Tokenization or blockchain execution authority\n\n"
                "This separation is the core of VPF custodianship. "
                "The system handles data. You govern the system. "
                "Financial principals govern the transactions."
            ),
            mode="ADVISE",
            vpf_note=(
                "VPF Human Intelligence: the custodian is always in the loop. "
                "No automated process has final authority over system governance."
            ),
        )

    def _default_response(self, state: dict) -> CopilotResponse:
        return CopilotResponse(
            message=(
                "I am your SANKƆFA-BRIDGE Intelligence Copilot, operating under "
                "VPF governance.\n\n"
                "I can help you with:\n"
                "  • System status — 'what is the current system status?'\n"
                "  • Compliance flags — 'explain SANCTIONS_HIT_SENDER'\n"
                "  • Exception review — 'guide me through exception EXC-XXXXXXXX'\n"
                "  • Regulatory briefing — 'what are the Ghana AML regulations?'\n"
                "  • Gate guidance — 'how do I clear the compliance gate?'\n"
                "  • Connector setup — 'how do I connect to an SFTP source?'\n"
                "  • Your role — 'what is my role as custodian?'\n\n"
                "What would you like to know?"
            ),
            mode="STATUS",
            data={"available_modes": ["STATUS", "EXPLAIN", "GUIDE", "REPORT", "ADVISE"]},
        )

    def _is_prohibited(self, text: str) -> bool:
        return any(phrase in text for phrase in PROHIBITED_INTENTS)

    def _build_review_steps(self, flags: list, priority: str) -> list:
        steps = [
            "Read the full exception record and all compliance flags.",
            "Review the chain of custody to understand how the file arrived.",
        ]
        if "SANCTIONS_HIT_SENDER" in flags or "SANCTIONS_HIT_RECEIVER" in flags:
            steps += [
                "Verify the sanctions match against the original watchlist source.",
                "Contact your AML/CFT officer — this requires immediate escalation.",
                "Do NOT approve retry until sanctions clearance is confirmed in writing.",
                "Determine if a Suspicious Activity Report (SAR) must be filed.",
            ]
        elif "AML_VELOCITY_BREACH" in flags or "AML_STRUCTURING_SUSPECTED" in flags:
            steps += [
                "Review the sender's full transaction history for the past 30 days.",
                "Request business justification for the transaction volume from the sender.",
                "Determine if the pattern constitutes structuring under AML definitions.",
                "Document your finding. Approve retry only if justification is satisfactory.",
            ]
        else:
            steps += [
                "Verify that the flagged condition has been addressed.",
                "Document the basis for your decision in the resolution field.",
                "Approve retry only if all flags have been satisfactorily resolved.",
            ]
        steps.append("Record your decision with your name, timestamp, and resolution text.")
        return steps


# Singleton
copilot = CopilotEngine()
