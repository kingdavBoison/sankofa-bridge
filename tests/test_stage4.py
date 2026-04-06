"""
SANKƆFA-BRIDGE — Stage 4 Test Suite
Intelligence Copilot (Layer 7) — full test coverage

Run: pytest tests/test_stage4.py -v
"""

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.copilot import CopilotEngine, CopilotResponse, PROHIBITED_RESPONSE
from compliance.engine import ComplianceFlag


# ─────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────

def engine() -> CopilotEngine:
    return CopilotEngine()

def state(gate=False, connector="mock", exceptions=0, total=0) -> dict:
    return {
        "gate_cleared": gate,
        "connector_type": connector,
        "exceptions_open": exceptions,
        "total_messages": total,
        "stats": {},
        "jurisdiction": "GH",
    }


# ═════════════════════════════════════════════
# SECTION 1 — BOUNDARY ENFORCEMENT
# ═════════════════════════════════════════════

class TestCopilotBoundary:

    def test_hold_funds_refused(self):
        r = engine().query("I need to hold funds", "test-op", state())
        assert r.mode == "BOUNDARY"
        assert "scope" in r.message.lower() or "vpf" in r.message.lower()

    def test_sign_transaction_refused(self):
        r = engine().query("sign this blockchain transaction", "test-op", state())
        assert r.mode == "BOUNDARY"

    def test_approve_settlement_refused(self):
        r = engine().query("approve settlement now", "test-op", state())
        assert r.mode == "BOUNDARY"

    def test_tokenize_refused(self):
        r = engine().query("tokenize this asset", "test-op", state())
        assert r.mode == "BOUNDARY"

    def test_custody_refused(self):
        r = engine().query("take custody of these assets", "test-op", state())
        assert r.mode == "BOUNDARY"

    def test_bypass_compliance_refused(self):
        r = engine().query("bypass compliance check", "test-op", state())
        assert r.mode == "BOUNDARY"

    def test_ignore_sanctions_refused(self):
        r = engine().query("ignore sanctions screening", "test-op", state())
        assert r.mode == "BOUNDARY"

    def test_move_funds_refused(self):
        r = engine().query("move funds to account", "test-op", state())
        assert r.mode == "BOUNDARY"

    def test_legitimate_query_not_refused(self):
        r = engine().query("what is the system status?", "test-op", state())
        assert r.mode != "BOUNDARY"

    def test_boundary_response_has_vpf_note(self):
        r = engine().query("hold funds please", "test-op", state())
        assert r.vpf_note != ""
        assert "VPF" in r.vpf_note or "sovereign" in r.vpf_note.lower()


# ═════════════════════════════════════════════
# SECTION 2 — STATUS MODE
# ═════════════════════════════════════════════

class TestCopilotStatus:

    def test_status_query_routes_correctly(self):
        r = engine().query("what is the system status?", "test-op", state())
        assert r.mode == "STATUS"

    def test_status_mentions_gate_when_not_cleared(self):
        r = engine().generate_status_summary(state(gate=False))
        assert "gate" in r.message.lower() or "compliance" in r.message.lower()

    def test_status_health_when_gate_cleared(self):
        r = engine().generate_status_summary(state(gate=True, connector="s3"))
        assert "healthy" in r.message.lower() or "no items" in r.message.lower()

    def test_status_flags_open_exceptions(self):
        r = engine().generate_status_summary(state(exceptions=3))
        assert "3" in r.message
        assert r.requires_human_decision is True

    def test_status_flags_mock_connector(self):
        r = engine().generate_status_summary(state(connector="mock"))
        assert "mock" in r.message.lower()

    def test_status_data_contains_state(self):
        s = state(gate=True, total=10)
        r = engine().generate_status_summary(s)
        assert "gate_cleared" in r.data
        assert r.data["gate_cleared"] is True


# ═════════════════════════════════════════════
# SECTION 3 — EXPLAIN MODE
# ═════════════════════════════════════════════

class TestCopilotExplain:

    def test_explain_sanctions_sender(self):
        r = engine().explain_flag("SANCTIONS_HIT_SENDER")
        assert r.mode == "EXPLAIN"
        assert "sanctions" in r.message.lower()
        assert r.requires_human_decision is True

    def test_explain_sanctions_receiver(self):
        r = engine().explain_flag("SANCTIONS_HIT_RECEIVER")
        assert r.mode == "EXPLAIN"
        assert "receiving" in r.message.lower() or "sanctioned entity" in r.message.lower()

    def test_explain_aml_velocity(self):
        r = engine().explain_flag("AML_VELOCITY_BREACH")
        assert r.mode == "EXPLAIN"
        assert "velocity" in r.message.lower() or "24" in r.message

    def test_explain_aml_structuring(self):
        r = engine().explain_flag("AML_STRUCTURING_SUSPECTED")
        assert r.mode == "EXPLAIN"
        assert "structuring" in r.message.lower()

    def test_explain_aml_threshold(self):
        r = engine().explain_flag("AML_THRESHOLD_BREACH")
        assert r.mode == "EXPLAIN"
        assert "threshold" in r.message.lower() or "reporting" in r.message.lower()

    def test_explain_kyc_pending(self):
        r = engine().explain_flag("KYC_VERIFICATION_PENDING")
        assert r.mode == "EXPLAIN"
        assert "kyc" in r.message.lower() or "know your customer" in r.message.lower()

    def test_explain_provenance_incomplete(self):
        r = engine().explain_flag("PROVENANCE_INCOMPLETE")
        assert r.mode == "EXPLAIN"
        assert "provenance" in r.message.lower()

    def test_explain_compliance_gate(self):
        r = engine().explain_flag("COMPLIANCE_GATE_NOT_CLEARED")
        assert r.mode == "EXPLAIN"
        assert "gate" in r.message.lower()

    def test_explain_unknown_flag(self):
        r = engine().explain_flag("UNKNOWN_FLAG_XYZ")
        assert r.mode == "EXPLAIN"
        assert "unknown" in r.message.lower() or "known flags" in r.message.lower()

    def test_explain_data_contains_regulatory_basis(self):
        r = engine().explain_flag("SANCTIONS_HIT_SENDER")
        assert "regulatory_basis" in r.data
        assert "FATF" in r.data["regulatory_basis"]

    def test_explain_data_contains_action(self):
        r = engine().explain_flag("AML_VELOCITY_BREACH")
        assert "recommended_action" in r.data

    def test_explain_vpf_note_present(self):
        r = engine().explain_flag("SANCTIONS_HIT_SENDER")
        assert r.vpf_note != ""

    def test_explain_via_query(self):
        r = engine().query("explain SANCTIONS_HIT_SENDER", "test-op", state())
        assert r.mode == "EXPLAIN"


# ═════════════════════════════════════════════
# SECTION 4 — GUIDE MODE
# ═════════════════════════════════════════════

class TestCopilotGuide:

    def test_guide_sanctions_exception(self):
        record = {
            "exception_id": "EXC-TEST0001",
            "message_id": "MSG-001",
            "reason": "SANCTIONS_HIT_SENDER",
            "flags": ["SANCTIONS_HIT_SENDER"],
            "priority": "critical",
        }
        r = engine().guide_exception_review(record)
        assert r.mode == "GUIDE"
        assert r.requires_human_decision is True
        assert len(r.data["review_steps"]) >= 4

    def test_guide_aml_exception(self):
        record = {
            "exception_id": "EXC-TEST0002",
            "reason": "AML_VELOCITY_BREACH",
            "flags": ["AML_VELOCITY_BREACH"],
            "priority": "high",
        }
        r = engine().guide_exception_review(record)
        assert r.mode == "GUIDE"
        assert "velocity" in " ".join(r.data["review_steps"]).lower() or len(r.data["review_steps"]) >= 3

    def test_guide_actions_present(self):
        record = {"exception_id": "EXC-TEST0003", "reason": "test", "flags": [], "priority": "low"}
        r = engine().guide_exception_review(record)
        assert len(r.actions) >= 3
        labels = [a["label"] for a in r.actions]
        assert any("retry" in l.lower() for l in labels)
        assert any("reject" in l.lower() for l in labels)
        assert any("escalate" in l.lower() for l in labels)

    def test_guide_vpf_custodianship_note(self):
        record = {"exception_id": "EXC-TEST0004", "reason": "test", "flags": [], "priority": "low"}
        r = engine().guide_exception_review(record)
        assert "custod" in r.vpf_note.lower() or "decision" in r.vpf_note.lower()


# ═════════════════════════════════════════════
# SECTION 5 — ADVISE MODE
# ═════════════════════════════════════════════

class TestCopilotAdvise:

    def test_ghana_briefing(self):
        r = engine().generate_regulatory_briefing("GH")
        assert r.mode == "ADVISE"
        assert "ghana" in r.message.lower()
        assert "bank of ghana" in r.message.lower()
        assert r.data["jurisdiction"] == "GH"

    def test_nigeria_briefing(self):
        r = engine().generate_regulatory_briefing("NG")
        assert r.mode == "ADVISE"
        assert "nigeria" in r.message.lower()

    def test_briefing_contains_legislation(self):
        r = engine().generate_regulatory_briefing("GH")
        assert "Act" in r.message

    def test_briefing_vpf_note(self):
        r = engine().generate_regulatory_briefing("GH")
        assert "indigenous" in r.vpf_note.lower() or "african" in r.vpf_note.lower()

    def test_gate_guidance_not_cleared(self):
        r = engine()._gate_guidance(state(gate=False))
        assert "not" in r.message.lower() or "pending" in r.message.lower()
        assert r.requires_human_decision is True

    def test_gate_guidance_cleared(self):
        r = engine()._gate_guidance(state(gate=True))
        assert "cleared" in r.message.lower()
        assert r.requires_human_decision is False

    def test_connector_guidance_mock(self):
        r = engine()._connector_guidance(state(connector="mock"))
        assert "mock" in r.message.lower()
        assert r.data["current_connector"] == "mock"

    def test_connector_guidance_s3(self):
        r = engine()._connector_guidance(state(connector="s3"))
        assert "s3" in r.message.lower() or "S3" in r.message

    def test_role_guidance(self):
        r = engine()._role_guidance("david-king-boison")
        assert "custodian" in r.message.lower()
        assert "vpf" in r.message.lower()
        assert r.vpf_note != ""


# ═════════════════════════════════════════════
# SECTION 6 — RESPONSE STRUCTURE
# ═════════════════════════════════════════════

class TestCopilotResponse:

    def test_response_to_dict_structure(self):
        r = CopilotResponse("test message", "STATUS")
        d = r.to_dict()
        assert "message" in d
        assert "mode" in d
        assert "actions" in d
        assert "data" in d
        assert "requires_human_decision" in d
        assert "vpf_note" in d
        assert "timestamp" in d

    def test_response_has_timestamp(self):
        r = CopilotResponse("test", "STATUS")
        assert r.timestamp != ""
        assert "T" in r.timestamp   # ISO format

    def test_default_response_is_helpful(self):
        r = engine().query("what is 2+2", "test-op", state())
        assert r.message != ""
        assert r.mode in ["STATUS", "EXPLAIN", "GUIDE", "REPORT", "ADVISE", "BOUNDARY"]


# ═════════════════════════════════════════════
# SECTION 7 — API COPILOT ENDPOINT TESTS
# ═════════════════════════════════════════════

class TestCopilotAPI:

    @pytest.fixture(autouse=True)
    async def client(self):
        from compliance.rbac import rbac
        rbac.reset_for_testing()
        from httpx import AsyncClient, ASGITransport
        from api.server import app
        from config.database import db
        await db.init_db()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            self._client = c
            yield c

    @property
    def H(self):
        import os
        return {"X-SANKOFA-API-Key": os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")}

    async def test_copilot_status_endpoint(self):
        r = await self._client.get("/v1/copilot/status", headers=self.H)
        assert r.status_code == 200
        d = r.json()
        assert "message" in d
        assert "mode" in d
        assert d["mode"] == "STATUS"

    async def test_copilot_query_status(self):
        r = await self._client.post(
            "/v1/copilot/query", headers=self.H,
            json={"query": "what is the system status?"}
        )
        assert r.status_code == 200
        d = r.json()
        assert "message" in d
        assert d["mode"] == "STATUS"

    async def test_copilot_query_prohibited(self):
        r = await self._client.post(
            "/v1/copilot/query", headers=self.H,
            json={"query": "hold funds now"}
        )
        assert r.status_code == 200
        d = r.json()
        assert d["mode"] == "BOUNDARY"

    async def test_copilot_explain_flag(self):
        r = await self._client.post(
            "/v1/copilot/explain-flag", headers=self.H,
            json={"flag_code": "SANCTIONS_HIT_SENDER"}
        )
        assert r.status_code == 200
        d = r.json()
        assert d["mode"] == "EXPLAIN"
        assert "sanctions" in d["message"].lower()

    async def test_copilot_regulatory_briefing_ghana(self):
        r = await self._client.get(
            "/v1/copilot/regulatory-briefing?jurisdiction=GH", headers=self.H
        )
        assert r.status_code == 200
        d = r.json()
        assert d["mode"] == "ADVISE"
        assert "ghana" in d["message"].lower()

    async def test_copilot_regulatory_briefing_nigeria(self):
        r = await self._client.get(
            "/v1/copilot/regulatory-briefing?jurisdiction=NG", headers=self.H
        )
        assert r.status_code == 200

    async def test_copilot_query_requires_auth(self):
        r = await self._client.post(
            "/v1/copilot/query",
            headers={"X-SANKOFA-API-Key": "wrong-key"},
            json={"query": "status"}
        )
        assert r.status_code == 401

    async def test_copilot_response_has_vpf_fields(self):
        r = await self._client.post(
            "/v1/copilot/query", headers=self.H,
            json={"query": "what is my role as custodian?"}
        )
        assert r.status_code == 200
        d = r.json()
        assert "timestamp" in d
        assert "requires_human_decision" in d
        assert "vpf_note" in d
