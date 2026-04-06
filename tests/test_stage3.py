"""
SANKƆFA-BRIDGE — Stage 3 Test Suite
Compliance Engine + Exception Manager + Full Pipeline + API Live Tests

Run all: pytest tests/test_stage3.py -v
Run API tests only: pytest tests/test_stage3.py -v -k "API"
"""

import pytest
import json
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.models import SankofaMessage, FileState
from config.settings import settings
from compliance.engine import (
    ComplianceEngine, ComplianceFlag, ComplianceSeverity,
    SANCTIONS_WATCHLIST, FATF_HIGH_RISK, FATF_GREY_LIST
)
from compliance.exceptions import ExceptionManager, ExceptionStatus, ExceptionPriority
from validation.validator import ValidationEngine, _seen_hashes
from transformation.pipeline import TransformationEngine, DeliveryEngine


# ─────────────────────────────────────────────
# SHARED FIXTURES
# ─────────────────────────────────────────────

def fresh_message(
    sender="SENDER_TEST_COMP_001",
    receiver="RECEIVER_TEST_COMP_001",
    jurisdiction="GH",
    amount=500.0,
) -> SankofaMessage:
    payload = {
        "transaction_reference": f"TXN-{id(object()):08x}",
        "sender_entity_id": sender,
        "receiver_entity_id": receiver,
        "amount": amount,
        "currency": "GHS",
        "jurisdiction": jurisdiction,
    }
    raw = json.dumps(payload).encode()
    from datetime import datetime, timezone
    msg = SankofaMessage(
        file_name=f"test_{sender}.json",
        file_format="json",
        source_system="MockConnector",
        sender_entity_id=sender,
        receiver_entity_id=receiver,
        jurisdiction=jurisdiction,
        classification="restricted",
        raw_payload=raw,
        file_size_bytes=len(raw),
        file_id=f"FILE-{id(object()):08x}",
    )
    msg.compute_hash()
    msg.received_at_utc = datetime.now(timezone.utc)
    msg.transition(FileState.QUARANTINED, "TestFixture", "setup")
    return msg


def validated_and_transformed(msg: SankofaMessage) -> SankofaMessage:
    _seen_hashes.clear()
    msg = ValidationEngine().validate(msg)
    msg = TransformationEngine().transform(msg)
    return msg


# ═════════════════════════════════════════════
# SECTION 1 — COMPLIANCE ENGINE TESTS
# ═════════════════════════════════════════════

class TestComplianceEngine:

    def setup_method(self):
        _seen_hashes.clear()
        self.engine = ComplianceEngine()

    def test_clean_message_is_cleared(self):
        msg = validated_and_transformed(fresh_message())
        msg, report = self.engine.run(msg)
        assert report.overall_status == "CLEAR"
        assert not report.blocking_flags

    def test_sanctioned_sender_is_critical(self):
        SANCTIONS_WATCHLIST.add("SANCTIONED_SENDER_TEST")
        msg = validated_and_transformed(
            fresh_message(sender="SANCTIONED_SENDER_TEST")
        )
        msg, report = self.engine.run(msg)
        assert report.overall_status == "ESCALATED"
        flags = [c.flag for c in report.blocking_flags]
        assert ComplianceFlag.SANCTIONS_HIT_SENDER in flags
        SANCTIONS_WATCHLIST.discard("SANCTIONED_SENDER_TEST")

    def test_sanctioned_receiver_is_critical(self):
        SANCTIONS_WATCHLIST.add("SANCTIONED_RECEIVER_TEST")
        msg = validated_and_transformed(
            fresh_message(receiver="SANCTIONED_RECEIVER_TEST")
        )
        msg, report = self.engine.run(msg)
        assert report.overall_status == "ESCALATED"
        flags = [c.flag for c in report.blocking_flags]
        assert ComplianceFlag.SANCTIONS_HIT_RECEIVER in flags
        SANCTIONS_WATCHLIST.discard("SANCTIONED_RECEIVER_TEST")

    def test_fatf_high_risk_jurisdiction_escalated(self):
        FATF_HIGH_RISK.add("ZZ")
        msg = validated_and_transformed(fresh_message(jurisdiction="ZZ"))
        msg.jurisdiction = "ZZ"
        msg, report = self.engine.run(msg)
        assert report.overall_status == "ESCALATED"
        FATF_HIGH_RISK.discard("ZZ")

    def test_fatf_grey_list_jurisdiction_blocked(self):
        FATF_GREY_LIST.add("YY")
        msg = validated_and_transformed(fresh_message(jurisdiction="YY"))
        msg.jurisdiction = "YY"
        msg, report = self.engine.run(msg)
        assert report.overall_status in ["BLOCKED", "ESCALATED"]
        FATF_GREY_LIST.discard("YY")

    def test_unsupported_jurisdiction_is_warning(self):
        msg = validated_and_transformed(fresh_message(jurisdiction="US"))
        msg.jurisdiction = "US"
        msg, report = self.engine.run(msg)
        # Warning only — not blocked
        warning_flags = [c.flag for c in report.warning_flags]
        assert ComplianceFlag.UNSUPPORTED_JURISDICTION in warning_flags
        assert report.overall_status in ["CLEAR", "FLAGGED"]

    def test_ghana_jurisdiction_clears(self):
        msg = validated_and_transformed(fresh_message(jurisdiction="GH"))
        msg, report = self.engine.run(msg)
        assert not any(
            c.flag == ComplianceFlag.HIGH_RISK_JURISDICTION
            for c in report.checks
        )

    def test_aml_threshold_warning_on_large_amount(self):
        msg = validated_and_transformed(
            fresh_message(amount=50_000.0)  # Above 10k threshold
        )
        msg, report = self.engine.run(msg)
        warn_flags = [c.flag for c in report.warning_flags]
        assert ComplianceFlag.AML_THRESHOLD_BREACH in warn_flags

    def test_aml_small_amount_no_threshold_flag(self):
        msg = validated_and_transformed(fresh_message(amount=500.0))
        msg, report = self.engine.run(msg)
        flag_names = [c.flag for c in report.checks]
        assert ComplianceFlag.AML_THRESHOLD_BREACH not in flag_names

    def test_provenance_incomplete_blocks(self):
        msg = validated_and_transformed(fresh_message())
        msg.file_hash_sha256 = ""   # Strip provenance
        msg, report = self.engine.run(msg)
        assert report.overall_status in ["BLOCKED", "ESCALATED"]
        flags = [c.flag for c in report.blocking_flags]
        assert ComplianceFlag.PROVENANCE_INCOMPLETE in flags

    def test_compliance_report_structure(self):
        msg = validated_and_transformed(fresh_message())
        msg, report = self.engine.run(msg)
        d = report.to_dict()
        assert "message_id" in d
        assert "overall_status" in d
        assert "generated_at" in d
        assert "all_checks" in d
        assert isinstance(d["all_checks"], list)

    def test_evidence_package_generation(self):
        msg = validated_and_transformed(fresh_message())
        msg, report = self.engine.run(msg)
        pkg = self.engine.generate_evidence_package(msg, report)
        assert "evidence_package_id" in pkg
        assert "system" in pkg
        assert pkg["system"] == "SANKƆFA-BRIDGE"
        assert "chain_of_custody" in pkg
        assert "vpf_principle" in pkg
        assert "system_role_declaration" in pkg

    def test_sanctions_list_update(self):
        initial_size = len(SANCTIONS_WATCHLIST)
        self.engine.update_sanctions_list(["NEW_TEST_ENTITY"], action="add")
        assert "NEW_TEST_ENTITY" in SANCTIONS_WATCHLIST
        self.engine.update_sanctions_list(["NEW_TEST_ENTITY"], action="remove")
        assert len(SANCTIONS_WATCHLIST) == initial_size

    def test_blocked_message_transitions_to_exception(self):
        SANCTIONS_WATCHLIST.add("BLOCKED_SENDER_TEST")
        msg = validated_and_transformed(
            fresh_message(sender="BLOCKED_SENDER_TEST")
        )
        msg, report = self.engine.run(msg)
        assert msg.state == FileState.EXCEPTION
        assert msg.exception_reason is not None
        SANCTIONS_WATCHLIST.discard("BLOCKED_SENDER_TEST")


# ═════════════════════════════════════════════
# SECTION 2 — EXCEPTION MANAGER TESTS
# ═════════════════════════════════════════════

class TestExceptionManager:

    def setup_method(self):
        _seen_hashes.clear()
        self.manager = ExceptionManager.__new__(ExceptionManager)
        self.manager._queue = {}
        self.manager._message_index = {}
        self.manager._initialized = True

    def _exc_message(self) -> SankofaMessage:
        msg = fresh_message()
        msg.exception_reason = "Test compliance block"
        msg.compliance_flags = ["SANCTIONS_HIT_SENDER"]
        msg.transition(FileState.EXCEPTION, "TestFixture", "exception_raised")
        return msg

    def test_create_exception_record(self):
        msg = self._exc_message()
        record = self.manager.create(msg)
        assert record.exception_id.startswith("EXC-")
        assert record.message_id == msg.message_id
        assert record.status == ExceptionStatus.OPEN

    def test_critical_flags_give_critical_priority(self):
        msg = self._exc_message()
        msg.compliance_flags = ["SANCTIONS_HIT_SENDER"]
        record = self.manager.create(msg)
        assert record.priority == ExceptionPriority.CRITICAL

    def test_assign_exception(self):
        msg = self._exc_message()
        record = self.manager.create(msg)
        updated = self.manager.assign(record.exception_id, "compliance_officer_001")
        assert updated.status == ExceptionStatus.ASSIGNED
        assert updated.assigned_to == "compliance_officer_001"

    def test_resolve_with_retry(self):
        msg = self._exc_message()
        record = self.manager.create(msg)
        resolved = self.manager.resolve(
            record.exception_id,
            resolution="Verified legitimate — approved for retry",
            resolved_by="officer_dk",
            approve_retry=True,
        )
        assert resolved.status == ExceptionStatus.RESOLVED
        assert resolved.retry_approved is True
        assert resolved.resolved_at is not None

    def test_resolve_without_retry(self):
        msg = self._exc_message()
        record = self.manager.create(msg)
        resolved = self.manager.resolve(
            record.exception_id,
            resolution="Confirmed violation — no retry",
            resolved_by="officer_dk",
            approve_retry=False,
        )
        assert resolved.retry_approved is False

    def test_escalate_exception(self):
        msg = self._exc_message()
        record = self.manager.create(msg)
        escalated = self.manager.escalate(
            record.exception_id,
            escalation_reason="Potential OFAC violation — escalating to head of compliance",
            escalated_by="officer_dk",
        )
        assert escalated.status == ExceptionStatus.ESCALATED
        assert escalated.priority == ExceptionPriority.CRITICAL

    def test_reject_exception(self):
        msg = self._exc_message()
        record = self.manager.create(msg)
        rejected = self.manager.reject(
            record.exception_id,
            rejection_reason="Confirmed sanctions match — permanently rejected",
            rejected_by="chief_compliance_officer",
        )
        assert rejected.status == ExceptionStatus.REJECTED
        assert rejected.retry_approved is False

    def test_list_open_exceptions(self):
        for i in range(3):
            msg = self._exc_message()
            msg.message_id = f"MSG-{i}"
            self.manager.create(msg)
        open_list = self.manager.list_open()
        assert len(open_list) == 3

    def test_summary_counts(self):
        msg1 = self._exc_message()
        msg1.message_id = "S-1"
        msg2 = self._exc_message()
        msg2.message_id = "S-2"
        r1 = self.manager.create(msg1)
        r2 = self.manager.create(msg2)
        self.manager.resolve(r2.exception_id, "resolved", "officer")
        summary = self.manager.summary()
        assert summary["total"] == 2
        assert summary["open"] == 1
        assert summary["resolved"] == 1

    def test_get_by_message_id(self):
        msg = self._exc_message()
        record = self.manager.create(msg)
        found = self.manager.get_by_message(msg.message_id)
        assert found is not None
        assert found.exception_id == record.exception_id


# ═════════════════════════════════════════════
# SECTION 3 — FULL STAGE 3 PIPELINE INTEGRATION
# ═════════════════════════════════════════════

class TestStage3Pipeline:

    def setup_method(self):
        _seen_hashes.clear()

    @pytest.mark.asyncio
    async def test_clean_file_delivered_end_to_end(self):
        """Clean file: L2 → L3 → L6 CLEAR → L4 DELIVERED."""
        settings.compliance.gate_cleared = True
        settings.receiver.base_url = ""
        try:
            from connectors.connector import MockConnector
            connector = MockConnector()
            await connector.connect()
            desc = connector.inject_test_file(
                sender_id="SENDER_TEST_E2E",
                receiver_id="RECEIVER_TEST_E2E",
            )
            raw = await connector.download((await connector.poll())[0])
            msg = connector._build_message(
                file_id=desc["file_id"],
                file_name=desc["file_name"],
                raw_bytes=raw,
                sender_entity_id=desc["sender_entity_id"],
            )

            from main import SankofaOrchestrator
            result = await SankofaOrchestrator().process(msg)

            assert result.state == FileState.DELIVERED
            assert len(result.chain_of_custody) >= 5
            ok, missing = result.has_provenance()
            assert ok
        finally:
            settings.compliance.gate_cleared = False

    @pytest.mark.asyncio
    async def test_sanctioned_file_blocked_end_to_end(self):
        """Sanctioned sender: L2 → L3 → L6 ESCALATED → EXCEPTION."""
        settings.compliance.gate_cleared = True
        settings.receiver.base_url = ""
        SANCTIONS_WATCHLIST.add("SANCTIONED_E2E_SENDER")
        try:
            from connectors.connector import MockConnector
            connector = MockConnector()
            await connector.connect()
            desc = connector.inject_test_file(sender_id="SANCTIONED_E2E_SENDER")
            raw = await connector.download((await connector.poll())[0])
            msg = connector._build_message(
                file_id=desc["file_id"],
                file_name=desc["file_name"],
                raw_bytes=raw,
                sender_entity_id="SANCTIONED_E2E_SENDER",
            )
            from main import SankofaOrchestrator
            result = await SankofaOrchestrator().process(msg)
            assert result.state == FileState.EXCEPTION
            assert "SANCTIONS" in result.exception_reason
        finally:
            settings.compliance.gate_cleared = False
            SANCTIONS_WATCHLIST.discard("SANCTIONED_E2E_SENDER")


# ═════════════════════════════════════════════
# SECTION 4 — API LIVE TESTS
# ═════════════════════════════════════════════

class TestAPILive:
    """
    Tests against the live FastAPI application using httpx AsyncClient.
    No external network calls — all in-process.
    """

    @pytest.fixture(autouse=True)
    async def client(self):
        from compliance.rbac import rbac
        rbac.reset_for_testing()
        from httpx import AsyncClient, ASGITransport
        from api.server import app
        from config.database import db
        await db.init_db()   # Ensure tables exist before each test
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            self._client = c
            yield c

    @property
    def headers(self):
        import os
        key = os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")
        return {"X-SANKOFA-API-Key": key}

    async def test_health_endpoint(self):
        r = await self._client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["system"] == "SANKƆFA-BRIDGE"

    async def test_status_requires_auth(self):
        r = await self._client.get("/v1/status")
        assert r.status_code == 422   # Missing header

    async def test_status_with_valid_key(self):
        r = await self._client.get("/v1/status", headers=self.headers)
        assert r.status_code == 200
        data = r.json()
        assert data["system"] == "SANKƆFA-BRIDGE"
        assert "version" in data
        assert "principle" in data
        assert "architect" in data

    async def test_invalid_api_key_returns_401(self):
        r = await self._client.get(
            "/v1/status",
            headers={"X-SANKOFA-API-Key": "wrong-key-xyz"}
        )
        assert r.status_code == 401

    async def test_dashboard_endpoint(self):
        r = await self._client.get("/v1/dashboard", headers=self.headers)
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "by_state" in data
        assert "exceptions_open" in data

    async def test_files_list_endpoint(self):
        r = await self._client.get("/v1/files", headers=self.headers)
        assert r.status_code == 200
        data = r.json()
        assert "files" in data
        assert "count" in data

    async def test_files_list_with_state_filter(self):
        r = await self._client.get(
            "/v1/files?state=delivered", headers=self.headers
        )
        assert r.status_code == 200

    async def test_compliance_gate_view(self):
        r = await self._client.get("/v1/compliance/gate", headers=self.headers)
        assert r.status_code == 200
        data = r.json()
        assert data["total_questions"] == 18
        assert "questions" in data
        assert "1" in data["questions"]
        assert "18" in data["questions"]

    async def test_compliance_gate_answer(self):
        r = await self._client.post(
            "/v1/compliance/gate/answer",
            headers=self.headers,
            json={
                "question_id": 1,
                "answer_text": "Sender: FinCorp GH. Receiver: PayBridge NG. Platform: SANKƆFA-BRIDGE.",
                "answered_by": "David King Boison"
            }
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "recorded"
        assert data["question_id"] == 1

    async def test_compliance_gate_invalid_question(self):
        r = await self._client.post(
            "/v1/compliance/gate/answer",
            headers=self.headers,
            json={"question_id": 99, "answer_text": "test", "answered_by": "test"}
        )
        assert r.status_code == 400

    async def test_exceptions_list_endpoint(self):
        r = await self._client.get("/v1/exceptions", headers=self.headers)
        assert r.status_code == 200
        data = r.json()
        assert "exceptions" in data
        assert "count" in data

    async def test_audit_export_endpoint(self):
        r = await self._client.get("/v1/audit/export", headers=self.headers)
        assert r.status_code == 200
        data = r.json()
        assert "events" in data
        assert "count" in data

    async def test_register_sender_endpoint(self):
        r = await self._client.post(
            "/v1/registry/senders",
            headers=self.headers,
            json={
                "entity_id": "TEST_SENDER_API_001",
                "entity_name": "Test Sender Corporation",
                "jurisdiction": "GH",
                "notes": "Registered via API test"
            }
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "registered"
        assert data["entity_id"] == "TEST_SENDER_API_001"

    async def test_prohibited_hold_funds_returns_403(self):
        r = await self._client.post(
            "/prohibited/hold-funds", headers=self.headers
        )
        assert r.status_code == 403
        data = r.json()
        assert "VPF" in data["detail"] or "prohibited" in data["detail"].lower() or "scope" in data["detail"].lower()

    async def test_delivery_acknowledge_endpoint(self):
        r = await self._client.post(
            "/v1/delivery/acknowledge",
            headers=self.headers,
            json={
                "message_id": "TEST-MSG-001",
                "delivery_id": "TEST-DEL-001",
                "status": "accepted",
                "received_at": "2026-04-06T12:00:00Z"
            }
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "acknowledged"

    async def test_nonexistent_file_returns_404(self):
        r = await self._client.get(
            "/v1/files/nonexistent-message-id-xyz",
            headers=self.headers
        )
        assert r.status_code == 404
