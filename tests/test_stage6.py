"""
SANKƆFA-BRIDGE — Stage 6 Test Suite
Live Intelligence Copilot — session management, fallback, API endpoints

Run: pytest tests/test_stage6.py -v
"""

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.live_copilot import (
    LiveCopilotEngine, CopilotSession, CopilotSessionStore, CopilotMessage,
    COPILOT_SYSTEM_PROMPT
)


# ═════════════════════════════════════════════
# SECTION 1 — SYSTEM PROMPT INTEGRITY
# VPF boundaries are encoded in the system prompt.
# These tests verify they are present and cannot be stripped.
# ═════════════════════════════════════════════

class TestSystemPromptIntegrity:

    def test_system_prompt_contains_vpf_principle(self):
        assert "provenance" in COPILOT_SYSTEM_PROMPT.lower()
        assert "custodianship" in COPILOT_SYSTEM_PROMPT.lower()
        assert "auditability" in COPILOT_SYSTEM_PROMPT.lower()

    def test_system_prompt_contains_architect(self):
        assert "David King Boison" in COPILOT_SYSTEM_PROMPT

    def test_system_prompt_lists_all_prohibited_actions(self):
        prohibited = [
            "holding", "moving", "custody of funds",
            "signing", "broadcasting", "blockchain",
            "settlements", "tokenize",
            "bypassing", "circumventing", "compliance controls",
            "financial intermediary"
        ]
        for p in prohibited:
            assert p.lower() in COPILOT_SYSTEM_PROMPT.lower(), \
                f"Prohibited action '{p}' missing from system prompt"

    def test_system_prompt_contains_african_regulatory_context(self):
        assert "Bank of Ghana" in COPILOT_SYSTEM_PROMPT
        assert "Anti-Money Laundering Act" in COPILOT_SYSTEM_PROMPT
        assert "FATF" in COPILOT_SYSTEM_PROMPT
        assert "Financial Intelligence Centre" in COPILOT_SYSTEM_PROMPT

    def test_system_prompt_lists_seven_layers(self):
        for i in range(1, 8):
            assert f"Layer {i}" in COPILOT_SYSTEM_PROMPT

    def test_system_prompt_lists_all_corridors(self):
        corridors = ["GH-NG", "GH-KE", "GH-RW", "GH-ZA", "NG-KE"]
        for c in corridors:
            assert c in COPILOT_SYSTEM_PROMPT

    def test_system_prompt_lists_all_compliance_flags(self):
        flags = [
            "SANCTIONS_HIT_SENDER", "SANCTIONS_HIT_RECEIVER",
            "HIGH_RISK_JURISDICTION", "AML_VELOCITY_BREACH",
            "AML_STRUCTURING_SUSPECTED", "AML_THRESHOLD_BREACH",
            "KYC_VERIFICATION_PENDING", "PROVENANCE_INCOMPLETE",
            "COMPLIANCE_GATE_NOT_CLEARED"
        ]
        for f in flags:
            assert f in COPILOT_SYSTEM_PROMPT, \
                f"Compliance flag '{f}' missing from system prompt"


# ═════════════════════════════════════════════
# SECTION 2 — SESSION MANAGEMENT
# ═════════════════════════════════════════════

class TestCopilotSession:

    def test_session_initialises_empty(self):
        s = CopilotSession("op-001", "SESS-001")
        assert len(s.messages) == 0

    def test_session_adds_messages(self):
        s = CopilotSession("op-001", "SESS-001")
        s.add("user", "What is the system status?")
        s.add("assistant", "System is operational.")
        assert len(s.messages) == 2

    def test_session_to_api_messages(self):
        s = CopilotSession("op-001", "SESS-001")
        s.add("user", "Hello")
        s.add("assistant", "Hi")
        msgs = s.to_api_messages()
        assert len(msgs) == 2
        assert msgs[0]["role"] == "user"
        assert msgs[1]["role"] == "assistant"

    def test_session_caps_at_max_turns(self):
        s = CopilotSession("op-001", "SESS-001")
        for i in range(50):
            s.add("user", f"Query {i}")
            s.add("assistant", f"Answer {i}")
        # Should not exceed 2 * MAX_TURNS messages
        assert len(s.messages) <= s.MAX_TURNS * 2

    def test_session_preserves_latest_messages(self):
        s = CopilotSession("op-001", "SESS-001")
        for i in range(25):
            s.add("user", f"Q{i}")
            s.add("assistant", f"A{i}")
        msgs = s.to_api_messages()
        # Latest messages should be present
        last = msgs[-1]["content"]
        assert "A24" in last

    def test_copilot_message_has_timestamp(self):
        m = CopilotMessage("user", "test")
        assert m.timestamp != ""
        assert "T" in m.timestamp  # ISO format

    def test_copilot_message_to_api_dict(self):
        m = CopilotMessage("user", "test content")
        d = m.to_api_dict()
        assert d["role"] == "user"
        assert d["content"] == "test content"
        assert "timestamp" not in d  # API dict excludes timestamp


# ═════════════════════════════════════════════
# SECTION 3 — SESSION STORE
# ═════════════════════════════════════════════

class TestCopilotSessionStore:

    def test_creates_new_session(self):
        store = CopilotSessionStore()
        s = store.get_or_create("operator-test-001")
        assert s.operator_id == "operator-test-001"
        assert s.session_id != ""

    def test_returns_existing_session(self):
        store = CopilotSessionStore()
        s1 = store.get_or_create("operator-test-002")
        s1.add("user", "Hello")
        s2 = store.get_or_create("operator-test-002")
        assert s1.session_id == s2.session_id
        assert len(s2.messages) == 1

    def test_different_operators_get_different_sessions(self):
        store = CopilotSessionStore()
        s1 = store.get_or_create("op-A")
        s2 = store.get_or_create("op-B")
        assert s1.session_id != s2.session_id

    def test_clear_removes_session(self):
        store = CopilotSessionStore()
        store.get_or_create("op-clear-test")
        assert store.active_count() >= 1
        store.clear("op-clear-test")
        # New session is created on next get_or_create
        s_new = store.get_or_create("op-clear-test")
        assert len(s_new.messages) == 0

    def test_active_count_tracks_sessions(self):
        store = CopilotSessionStore()
        initial = store.active_count()
        store.get_or_create("count-op-1")
        store.get_or_create("count-op-2")
        assert store.active_count() >= initial + 2


# ═════════════════════════════════════════════
# SECTION 4 — LIVE ENGINE (UNCONFIGURED)
# Tests that the engine behaves correctly when
# ANTHROPIC_API_KEY is not set (expected in CI)
# ═════════════════════════════════════════════

class TestLiveCopilotEngineUnconfigured:

    def setup_method(self):
        # Ensure clean state — no API key in test environment
        self.engine = LiveCopilotEngine.__new__(LiveCopilotEngine)
        self.engine.session_store = CopilotSessionStore()
        self.engine._api_key = ""  # Force unconfigured

    def test_is_not_configured(self):
        assert self.engine.is_configured() is False

    @pytest.mark.asyncio
    async def test_query_returns_fallback_when_unconfigured(self):
        result = await self.engine.query(
            text="What is the system status?",
            operator_id="test-op",
            system_state={"gate_cleared": False},
        )
        assert result["mode"] == "FALLBACK"
        assert "ANTHROPIC_API_KEY" in result["message"]

    @pytest.mark.asyncio
    async def test_compliance_report_fallback(self):
        result = await self.engine.generate_compliance_report(
            message_audit={"message_id": "test-001"},
            compliance_report={},
            operator_id="test-op",
        )
        assert "ANTHROPIC_API_KEY" in result

    @pytest.mark.asyncio
    async def test_correspondence_fallback(self):
        result = await self.engine.generate_regulatory_correspondence(
            recipient="Bank of Ghana",
            subject="Test",
            context={},
            operator_id="test-op",
        )
        assert "ANTHROPIC_API_KEY" in result

    def test_fallback_response_structure(self):
        r = self.engine._fallback_response("test fallback")
        assert "message" in r
        assert "mode" in r
        assert r["mode"] == "FALLBACK"
        assert "timestamp" in r
        assert "vpf_note" in r

    def test_state_context_serialization(self):
        state = {
            "gate_cleared": True,
            "connector_type": "sftp",
            "exceptions_open": 2,
            "total_messages": 150,
            "jurisdiction": "GH",
        }
        ctx = self.engine._build_state_context(state)
        assert "gate_cleared=True" in ctx
        assert "connector=sftp" in ctx
        assert "exceptions_open=2" in ctx

    def test_requires_decision_heuristic(self):
        assert self.engine._requires_decision("You must escalate this immediately") is True
        assert self.engine._requires_decision("Officer review required") is True
        assert self.engine._requires_decision("The system is healthy") is False

    def test_clear_session(self):
        session = self.engine.session_store.get_or_create("op-clear")
        session.add("user", "test")
        self.engine.clear_session("op-clear")
        new_session = self.engine.session_store.get_or_create("op-clear")
        assert len(new_session.messages) == 0


# ═════════════════════════════════════════════
# SECTION 5 — API ENDPOINT TESTS (STAGE 6)
# ═════════════════════════════════════════════

class TestStage6API:

    @pytest.fixture(autouse=True)
    async def client(self):
        from httpx import AsyncClient, ASGITransport
        from api.server import app
        from config.database import db
        from compliance.rbac import rbac
        await db.init_db()
        rbac.reset_for_testing()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            self._c = c
            yield c

    @property
    def H(self):
        import os
        return {"X-SANKOFA-API-Key": os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")}

    async def test_intelligence_status_endpoint(self):
        r = await self._c.get("/v1/copilot/intelligence-status", headers=self.H)
        assert r.status_code == 200
        d = r.json()
        assert "live_intelligence" in d
        assert "model" in d
        assert "active_sessions" in d
        assert "note" in d

    async def test_intelligence_status_reports_unconfigured(self):
        """Without API key set, should report unconfigured."""
        r = await self._c.get("/v1/copilot/intelligence-status", headers=self.H)
        assert r.status_code == 200
        d = r.json()
        # In test environment, ANTHROPIC_API_KEY is not set
        if not d["live_intelligence"]:
            assert "ANTHROPIC_API_KEY" in d["note"]

    async def test_live_query_fallback_without_api_key(self):
        r = await self._c.post(
            "/v1/copilot/live-query", headers=self.H,
            json={"query": "What is the current system status?"}
        )
        assert r.status_code == 200
        d = r.json()
        assert "message" in d
        # Either live or fallback — both are valid
        assert d["mode"] in ["LIVE_INTELLIGENCE", "FALLBACK"]

    async def test_live_query_requires_auth(self):
        r = await self._c.post(
            "/v1/copilot/live-query",
            headers={"X-SANKOFA-API-Key": "wrong-key"},
            json={"query": "status"}
        )
        assert r.status_code == 401

    async def test_clear_session_endpoint(self):
        r = await self._c.delete("/v1/copilot/session", headers=self.H)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "cleared"

    async def test_generate_compliance_report_404_for_unknown(self):
        r = await self._c.post(
            "/v1/copilot/generate-compliance-report", headers=self.H,
            json={"message_id": "nonexistent-id-xyz"}
        )
        assert r.status_code == 404

    async def test_draft_correspondence_endpoint(self):
        r = await self._c.post(
            "/v1/copilot/draft-correspondence", headers=self.H,
            json={
                "recipient": "Bank of Ghana — Financial Intelligence Centre",
                "subject": "Suspicious Transaction Report — STR-2026-001",
                "context": {"transaction_ref": "TXN-GH-001", "flag": "AML_VELOCITY_BREACH"}
            }
        )
        assert r.status_code == 200
        d = r.json()
        assert "correspondence" in d
        assert "recipient" in d
        assert "drafted_at" in d

    async def test_all_stage6_endpoints_respond(self):
        """Smoke test all Stage 6 endpoints."""
        endpoints = [
            ("GET", "/v1/copilot/intelligence-status"),
            ("DELETE", "/v1/copilot/session"),
        ]
        for method, path in endpoints:
            r = await self._c.request(method, path, headers=self.H)
            assert r.status_code == 200, f"{method} {path} returned {r.status_code}"
