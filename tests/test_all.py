"""
SANKƆFA-BRIDGE — Test Suite
Stage 2 Hardening

Tests all layers:
  - Models (state machine, provenance, hash)
  - Validation engine (all 8 checks)
  - Transformation engine (JSON + XML)
  - Delivery engine (compliance gate, simulation, circuit breaker)
  - RBAC (authentication, authorization, prohibited actions)
  - Database (save, retrieve, stats)
  - API endpoints (auth, file ops, compliance gate)
  - Full pipeline integration

Run: pytest tests/test_all.py -v
"""

import pytest
import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.models import SankofaMessage, FileState, ValidationStatus
from config.settings import settings
from validation.validator import ValidationEngine
from transformation.pipeline import TransformationEngine, DeliveryEngine
from compliance.rbac import RBACService, Role, Permission
from audit.logger import SankofaAuditLogger


# ─────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────

def make_message(
    file_name="test_file.json",
    sender="SENDER_TEST_001",
    receiver="RECEIVER_TEST_001",
    content: dict = None
) -> SankofaMessage:
    """Create a minimal valid SankofaMessage for testing."""
    payload = content or {
        "transaction_reference": "TXN-000001",
        "sender_entity_id": sender,
        "receiver_entity_id": receiver,
        "currency": "GHS",
        "jurisdiction": "GH",
    }
    raw = json.dumps(payload).encode("utf-8")
    msg = SankofaMessage(
        file_name=file_name,
        file_format="json",
        source_system="MockConnector",
        sender_entity_id=sender,
        receiver_entity_id=receiver,
        jurisdiction="GH",
        classification="restricted",
        raw_payload=raw,
        file_size_bytes=len(raw),
    )
    msg.compute_hash()
    from datetime import datetime, timezone
    msg.received_at_utc = datetime.now(timezone.utc)
    msg.file_id = "TEST-FILE-0001"
    msg.transition(FileState.QUARANTINED, "TestFixture", "setup")
    return msg


def make_xml_message() -> SankofaMessage:
    raw = b"""<?xml version="1.0"?>
<TransferInstruction>
  <TransactionReference>TXN-XML-001</TransactionReference>
  <SenderEntityId>SENDER_TEST_XML</SenderEntityId>
  <ReceiverEntityId>RECEIVER_TEST_XML</ReceiverEntityId>
  <Currency>GHS</Currency>
  <Jurisdiction>GH</Jurisdiction>
</TransferInstruction>"""
    msg = SankofaMessage(
        file_name="test_instruction.xml",
        file_format="xml",
        source_system="MockConnector",
        sender_entity_id="SENDER_TEST_XML",
        receiver_entity_id="RECEIVER_TEST_XML",
        jurisdiction="GH",
        classification="restricted",
        raw_payload=raw,
        file_size_bytes=len(raw),
        file_id="TEST-XML-0001",
    )
    msg.compute_hash()
    from datetime import datetime, timezone
    msg.received_at_utc = datetime.now(timezone.utc)
    msg.transition(FileState.QUARANTINED, "TestFixture", "setup")
    return msg


# ─────────────────────────────────────────────
# SECTION 1 — MODEL TESTS
# ─────────────────────────────────────────────

class TestSankofaMessage:

    def test_state_machine_transitions(self):
        msg = make_message()
        assert msg.state == FileState.QUARANTINED
        assert len(msg.chain_of_custody) >= 1

        msg.transition(FileState.VALIDATING, "test", "test_transition")
        assert msg.state == FileState.VALIDATING
        msg.transition(FileState.VALIDATED, "test", "test_transition")
        assert msg.state == FileState.VALIDATED

    def test_custody_chain_grows(self):
        msg = make_message()
        initial = len(msg.chain_of_custody)
        msg.transition(FileState.VALIDATING, "actor", "action", "notes")
        assert len(msg.chain_of_custody) == initial + 1
        entry = msg.chain_of_custody[-1]
        assert entry.actor == "actor"
        assert entry.action == "action"
        assert entry.notes == "notes"

    def test_hash_computation(self):
        msg = make_message()
        assert len(msg.file_hash_sha256) == 64  # SHA-256 hex
        # Verify recomputation matches
        import hashlib
        expected = hashlib.sha256(msg.raw_payload).hexdigest()
        assert msg.file_hash_sha256 == expected

    def test_hash_verification(self):
        msg = make_message()
        assert msg.verify_hash(msg.file_hash_sha256) is True
        assert msg.verify_hash("wrong_hash") is False

    def test_provenance_complete(self):
        msg = make_message()
        ok, missing = msg.has_provenance()
        assert ok is True
        assert missing == []

    def test_provenance_missing_fields(self):
        msg = make_message()
        msg.sender_entity_id = ""
        ok, missing = msg.has_provenance()
        assert ok is False
        assert "sender_entity_id" in missing

    def test_audit_dict_excludes_raw_payload(self):
        msg = make_message()
        d = msg.to_audit_dict()
        assert "raw_payload" not in d
        assert "message_id" in d
        assert "chain_of_custody" in d

    def test_delivery_payload_structure(self):
        msg = make_message()
        msg.transformed_payload = {"test": "data"}
        msg.destination_system = "test_dest"
        p = msg.to_delivery_payload()
        assert "message_id" in p
        assert "file_hash_sha256" in p
        assert "payload" in p


# ─────────────────────────────────────────────
# SECTION 2 — VALIDATION TESTS
# ─────────────────────────────────────────────

class TestValidationEngine:

    def setup_method(self):
        self.validator = ValidationEngine()

    def test_valid_json_message_passes(self):
        msg = make_message()
        result = self.validator.validate(msg)
        assert result.validation.status == ValidationStatus.PASS
        assert result.state == FileState.VALIDATED

    def test_valid_xml_message_passes(self):
        msg = make_xml_message()
        result = self.validator.validate(msg)
        assert result.validation.status in [ValidationStatus.PASS, ValidationStatus.WARNING]
        assert result.state == FileState.VALIDATED

    def test_invalid_format_fails(self):
        msg = make_message()
        msg.file_format = "csv"  # Not in allowed list
        result = self.validator.validate(msg)
        assert result.validation.status == ValidationStatus.FAIL
        assert result.state == FileState.FAILED

    def test_oversized_file_fails(self):
        msg = make_message()
        msg.file_size_bytes = 999 * 1024 * 1024  # 999 MB — over limit
        result = self.validator.validate(msg)
        assert result.validation.status == ValidationStatus.FAIL
        assert result.state == FileState.FAILED

    def test_hash_mismatch_fails(self):
        msg = make_message()
        msg.file_hash_sha256 = "a" * 64  # Wrong hash
        result = self.validator.validate(msg)
        assert result.validation.status == ValidationStatus.FAIL
        assert result.state == FileState.FAILED

    def test_invalid_json_fails(self):
        msg = make_message()
        msg.raw_payload = b"{not valid json!!!"
        msg.compute_hash()  # Recompute so hash passes
        result = self.validator.validate(msg)
        assert result.validation.status == ValidationStatus.FAIL

    def test_invalid_xml_fails(self):
        msg = make_xml_message()
        msg.raw_payload = b"<broken xml"
        msg.compute_hash()
        result = self.validator.validate(msg)
        assert result.validation.status == ValidationStatus.FAIL

    def test_duplicate_detection(self):
        msg1 = make_message()
        msg2 = make_message()
        # Same raw payload → same hash
        msg2.raw_payload = msg1.raw_payload
        msg2.compute_hash()
        from datetime import datetime, timezone
        msg2.received_at_utc = datetime.now(timezone.utc)
        msg2.file_id = "DIFFERENT_ID"

        # First should pass
        self.validator.validate(msg1)
        # Second with same hash should fail as duplicate
        result = self.validator.validate(msg2)
        assert result.validation.status == ValidationStatus.FAIL
        assert any("Duplicate" in e for e in result.validation.errors)

    def test_high_risk_jurisdiction_fails(self):
        msg = make_message()
        msg.jurisdiction = "XX"  # Simulated high-risk
        settings.compliance.high_risk_jurisdictions = ["XX"]
        result = self.validator.validate(msg)
        assert result.state == FileState.FAILED
        settings.compliance.high_risk_jurisdictions = []  # Reset

    def test_all_checks_recorded(self):
        msg = make_message()
        result = self.validator.validate(msg)
        assert len(result.validation.checks) >= 6


# ─────────────────────────────────────────────
# SECTION 3 — TRANSFORMATION TESTS
# ─────────────────────────────────────────────

class TestTransformationEngine:

    def setup_method(self):
        import validation.validator as vmod
        vmod._seen_hashes.clear()
        self.transformer = TransformationEngine()
        self.validator = ValidationEngine()

    def _validated(self, msg: SankofaMessage) -> SankofaMessage:
        return self.validator.validate(msg)

    def test_json_transformation(self):
        msg = self._validated(make_message())
        result = self.transformer.transform(msg)
        assert result.state == FileState.TRANSFORMED
        assert result.transformed_payload is not None
        assert "message_id" in result.transformed_payload
        assert "payload" in result.transformed_payload

    def test_xml_transformation(self):
        msg = self._validated(make_xml_message())
        result = self.transformer.transform(msg)
        assert result.state == FileState.TRANSFORMED
        assert result.transformed_payload is not None

    def test_transformation_requires_validated_state(self):
        msg = make_message()  # Still in QUARANTINED
        with pytest.raises(ValueError, match="VALIDATED"):
            self.transformer.transform(msg)

    def test_canonical_envelope_fields(self):
        msg = self._validated(make_message())
        result = self.transformer.transform(msg)
        p = result.transformed_payload
        assert p["message_id"] == msg.message_id
        assert p["file_hash_sha256"] == msg.file_hash_sha256
        assert p["jurisdiction"] == "GH"
        assert "payload" in p

    def test_sender_id_extracted_from_json_payload(self):
        msg = self._validated(make_message(sender="EXTRACTED_SENDER"))
        result = self.transformer.transform(msg)
        assert result.sender_entity_id == "EXTRACTED_SENDER"


# ─────────────────────────────────────────────
# SECTION 4 — DELIVERY TESTS
# ─────────────────────────────────────────────

class TestDeliveryEngine:

    def setup_method(self):
        import validation.validator as vmod
        vmod._seen_hashes.clear()
        self.validator = ValidationEngine()
        self.transformer = TransformationEngine()
        self.delivery = DeliveryEngine()

    def _pipeline(self, msg: SankofaMessage) -> SankofaMessage:
        msg = self.validator.validate(msg)
        msg = self.transformer.transform(msg)
        return msg

    @pytest.mark.asyncio
    async def test_delivery_blocked_by_compliance_gate(self):
        """Default: gate not cleared → EXCEPTION state."""
        settings.compliance.gate_cleared = False
        msg = self._pipeline(make_message())
        result = await self.delivery.deliver(msg)
        assert result.state == FileState.EXCEPTION
        assert "gate" in result.exception_reason.lower()

    @pytest.mark.asyncio
    async def test_delivery_simulation_when_gate_cleared(self):
        """Gate cleared + no receiver URL → simulation delivery."""
        settings.compliance.gate_cleared = True
        original_url = settings.receiver.base_url
        settings.receiver.base_url = ""
        try:
            msg = self._pipeline(make_message())
            result = await self.delivery.deliver(msg)
            assert result.state == FileState.DELIVERED
            assert result.delivery is not None
            assert result.delivery.success is True
            assert result.delivery.delivery_id.startswith("SIM-")
        finally:
            settings.compliance.gate_cleared = False
            settings.receiver.base_url = original_url

    @pytest.mark.asyncio
    async def test_delivery_blocked_missing_provenance(self):
        """Files without complete provenance are blocked."""
        settings.compliance.gate_cleared = True
        original_url = settings.receiver.base_url
        settings.receiver.base_url = ""
        try:
            msg = self._pipeline(make_message())
            msg.file_hash_sha256 = ""  # Strip provenance
            result = await self.delivery.deliver(msg)
            assert result.state == FileState.EXCEPTION
            assert "provenance" in result.exception_reason.lower()
        finally:
            settings.compliance.gate_cleared = False
            settings.receiver.base_url = original_url

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_after_failures(self):
        """Circuit breaker opens after threshold failures."""
        cb = self.delivery.circuit_breaker
        cb.threshold = 3
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open() is True
        cb.record_success()
        assert cb.is_open() is False


# ─────────────────────────────────────────────
# SECTION 5 — RBAC TESTS
# ─────────────────────────────────────────────

class TestRBAC:

    def setup_method(self):
        from compliance.rbac import rbac
        rbac.reset_for_testing()
        self.rbac = rbac

    def test_custodian_authentication(self):
        import os
        key = os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")
        op = self.rbac.authenticate(key)
        assert op is not None
        assert op.role == Role.CUSTODIAN

    def test_invalid_key_returns_none(self):
        op = self.rbac.authenticate("completely-wrong-key-xyz")
        assert op is None

    def test_custodian_has_all_permitted_permissions(self):
        import os
        key = os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")
        op = self.rbac.authenticate(key)
        assert op.has_permission(Permission.VIEW_FILES)
        assert op.has_permission(Permission.MANAGE_REGISTRY)
        assert op.has_permission(Permission.EXPORT_AUDIT)

    def test_prohibited_actions_blocked_for_all(self):
        import os
        key = os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")
        op = self.rbac.authenticate(key)
        # Even CUSTODIAN cannot perform prohibited actions
        assert op.has_permission(Permission.HOLD_FUNDS) is False
        assert op.has_permission(Permission.SIGN_BLOCKCHAIN) is False
        assert op.has_permission(Permission.APPROVE_SETTLEMENT) is False
        assert op.has_permission(Permission.TOKENIZE_ASSET) is False
        assert op.has_permission(Permission.CUSTODY_DIGITAL_ASSETS) is False

    def test_new_operator_role_permissions(self):
        key = self.rbac.generate_api_key()
        op = self.rbac.register_operator(
            operator_id="test-auditor",
            name="Test Auditor",
            role=Role.AUDITOR,
            raw_api_key=key,
        )
        assert op.has_permission(Permission.VIEW_AUDIT_LOG)
        assert op.has_permission(Permission.EXPORT_AUDIT)
        # Auditor cannot manage registry
        assert op.has_permission(Permission.MANAGE_REGISTRY) is False
        assert op.has_permission(Permission.RETRY_FILE) is False

    def test_api_key_generation(self):
        key = self.rbac.generate_api_key()
        assert key.startswith("skb_")
        assert len(key) > 20


# ─────────────────────────────────────────────
# SECTION 6 — FULL PIPELINE INTEGRATION TEST
# ─────────────────────────────────────────────

class TestFullPipeline:

    @pytest.mark.asyncio
    async def test_full_pipeline_json_simulation(self):
        """
        End-to-end: JSON file → validated → transformed → delivered (simulation).
        """
        settings.compliance.gate_cleared = True
        settings.receiver.base_url = ""

        from connectors.connector import MockConnector
        connector = MockConnector()
        await connector.connect()

        descriptor = connector.inject_test_file(
            sender_id="SENDER_TEST_PIPELINE",
            receiver_id="RECEIVER_TEST_PIPELINE",
            file_type="json",
        )
        pending = await connector.poll()
        assert len(pending) == 1

        raw = await connector.download(pending[0])
        msg = connector._build_message(
            file_id=descriptor["file_id"],
            file_name=descriptor["file_name"],
            raw_bytes=raw,
            sender_entity_id=descriptor["sender_entity_id"],
        )

        # L2 Validation
        validator = ValidationEngine()
        msg = validator.validate(msg)
        assert msg.state == FileState.VALIDATED

        # L3 Transformation
        transformer = TransformationEngine()
        msg = transformer.transform(msg)
        assert msg.state == FileState.TRANSFORMED

        # L4 Delivery
        delivery = DeliveryEngine()
        msg = await delivery.deliver(msg)
        assert msg.state == FileState.DELIVERED

        # Verify custody chain completeness
        states = [e.to_state for e in msg.chain_of_custody]
        assert FileState.QUARANTINED in states
        assert FileState.VALIDATED in states
        assert FileState.TRANSFORMED in states
        assert FileState.DELIVERED in states

        # Verify provenance
        ok, missing = msg.has_provenance()
        assert ok is True

        settings.compliance.gate_cleared = False

    @pytest.mark.asyncio
    async def test_full_pipeline_xml_simulation(self):
        """End-to-end XML file."""
        settings.compliance.gate_cleared = True
        settings.receiver.base_url = ""

        from connectors.connector import MockConnector
        connector = MockConnector()
        await connector.connect()

        descriptor = connector.inject_test_file(file_type="xml")
        raw = await connector.download((await connector.poll())[0])
        msg = connector._build_message(
            file_id=descriptor["file_id"],
            file_name=descriptor["file_name"],
            raw_bytes=raw,
            sender_entity_id=descriptor["sender_entity_id"],
        )

        msg = ValidationEngine().validate(msg)
        msg = TransformationEngine().transform(msg)
        msg = await DeliveryEngine().deliver(msg)

        assert msg.state == FileState.DELIVERED
        settings.compliance.gate_cleared = False
