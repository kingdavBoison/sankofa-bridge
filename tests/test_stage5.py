"""
SANKƆFA-BRIDGE — Stage 5 Test Suite
African Corridor Scale — Partner Registry + Production Readiness

Run: pytest tests/test_stage5.py -v
"""

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.partners import (
    PartnerRegistry, PartnerConfig, PartnerRole,
    KYCStatus, AMLTier
)
from config.secrets import SecretsManager, SecretValue
from config.settings import settings


# ═════════════════════════════════════════════
# SECTION 1 — PARTNER REGISTRY
# ═════════════════════════════════════════════

class TestPartnerRegistry:

    def setup_method(self):
        # Fresh registry per test
        self.registry = PartnerRegistry.__new__(PartnerRegistry)
        self.registry._partners = {}
        self.registry._initialized = True
        self.registry._bootstrap_corridor_partners()

    def test_bootstrap_creates_corridor_partners(self):
        partners = list(self.registry._partners.values())
        assert len(partners) >= 3

    def test_bootstrap_partners_are_pending_kyc(self):
        partners = list(self.registry._partners.values())
        for p in partners:
            assert p.kyc_status == KYCStatus.NOT_STARTED

    def test_register_new_partner(self):
        p = PartnerConfig(
            partner_id="PARTNER-TEST-001",
            name="Test Fintech Ghana",
            jurisdiction="GH",
            role=PartnerRole.SENDER,
            allowed_corridors=["GH-NG"],
        )
        self.registry.register(p, "david-king-boison")
        found = self.registry.get("PARTNER-TEST-001")
        assert found is not None
        assert found.name == "Test Fintech Ghana"

    def test_list_by_jurisdiction(self):
        gh_partners = self.registry.list_by_jurisdiction("GH")
        assert len(gh_partners) >= 1
        for p in gh_partners:
            assert p.jurisdiction == "GH"

    def test_list_by_corridor(self):
        partners = self.registry.list_by_corridor("GH-NG")
        assert len(partners) >= 1

    def test_update_kyc_status(self):
        p = PartnerConfig(
            partner_id="PARTNER-KYC-TEST",
            name="KYC Test Partner",
            jurisdiction="GH",
            role=PartnerRole.SENDER,
        )
        self.registry.register(p, "test")
        updated = self.registry.update_kyc(
            "PARTNER-KYC-TEST", KYCStatus.VERIFIED, "compliance_officer"
        )
        assert updated.kyc_status == KYCStatus.VERIFIED

    def test_production_ready_requires_kyc(self):
        p = PartnerConfig(
            partner_id="PARTNER-PROD-TEST",
            name="Production Test",
            jurisdiction="GH",
            role=PartnerRole.RECEIVER,
            kyc_status=KYCStatus.NOT_STARTED,
        )
        ready, issues = p.is_production_ready()
        assert ready is False
        assert any("KYC" in i for i in issues)

    def test_production_ready_all_checks_pass(self):
        p = PartnerConfig(
            partner_id="PARTNER-FULL-TEST",
            name="Fully Verified Partner",
            jurisdiction="GH",
            role=PartnerRole.RECEIVER,
            kyc_status=KYCStatus.VERIFIED,
            sanctions_cleared=True,
            active=True,
            api_endpoint="https://api.partner.example.com/v1/receive",
        )
        ready, issues = p.is_production_ready()
        assert ready is True
        assert issues == []

    def test_sender_requires_connector(self):
        p = PartnerConfig(
            partner_id="PARTNER-SEND-TEST",
            name="Sender Without Connector",
            jurisdiction="GH",
            role=PartnerRole.SENDER,
            kyc_status=KYCStatus.VERIFIED,
            sanctions_cleared=True,
            active=True,
            connector_type=None,   # Not configured
        )
        ready, issues = p.is_production_ready()
        assert ready is False
        assert any("connector" in i.lower() for i in issues)

    def test_registry_summary_structure(self):
        summary = self.registry.summary()
        assert "total" in summary
        assert "by_jurisdiction" in summary
        assert "by_kyc_status" in summary
        assert "production_ready" in summary

    def test_list_production_ready_empty_initially(self):
        ready = self.registry.list_production_ready()
        assert len(ready) == 0  # Bootstrap partners are not KYC-verified

    def test_partner_to_dict(self):
        p = PartnerConfig(
            partner_id="PARTNER-DICT-TEST",
            name="Dict Test",
            jurisdiction="GH",
            role=PartnerRole.SENDER,
        )
        d = p.to_dict()
        assert "partner_id" in d
        assert "jurisdiction" in d
        assert "kyc_status" in d
        assert "role" in d


# ═════════════════════════════════════════════
# SECTION 2 — SECRETS MANAGER
# ═════════════════════════════════════════════

class TestSecretsManager:

    def test_secret_value_masking(self):
        sv = SecretValue("my-super-secret-key", "TEST_KEY")
        assert "my-super-secret-key" not in str(sv)
        assert "***" in str(sv)
        assert "TEST_KEY" in str(sv)

    def test_secret_value_reveal(self):
        sv = SecretValue("actual-secret", "KEY")
        assert sv.reveal() == "actual-secret"

    def test_secret_bool_true(self):
        sv = SecretValue("nonempty", "KEY")
        assert bool(sv) is True

    def test_secret_bool_false(self):
        sv = SecretValue("", "KEY")
        assert bool(sv) is False

    def test_secret_repr_masks(self):
        sv = SecretValue("sensitive", "MY_KEY")
        assert "sensitive" not in repr(sv)
        assert "MASKED" in repr(sv)

    def test_encrypt_decrypt_roundtrip(self):
        sm = SecretsManager()
        plaintext = "test-secret-value-12345"
        encrypted = sm.encrypt(plaintext)
        assert encrypted != plaintext
        decrypted = sm.decrypt(encrypted)
        assert decrypted == plaintext

    def test_mask_shows_prefix_only(self):
        sm = SecretsManager()
        masked = sm.mask("skb_abc123def456ghi789", visible_chars=4)
        assert masked.startswith("skb_")
        assert "abc123def456" not in masked

    def test_generate_api_key_format(self):
        sm = SecretsManager()
        key = sm.rotate_api_key()
        assert key.startswith("skb_")
        assert len(key) > 20

    def test_validate_mock_connector_needs_no_secrets(self):
        sm = SecretsManager()
        ok, missing = sm.validate_required_secrets("mock")
        assert ok is True
        assert missing == []


# ═════════════════════════════════════════════
# SECTION 3 — PRODUCTION READINESS
# ═════════════════════════════════════════════

class TestProductionReadiness:

    def test_all_required_modules_importable(self):
        """Verify all production modules import without errors."""
        import config.settings
        import config.models
        import config.database
        import config.secrets
        import config.partners
        import connectors.connector
        import validation.validator
        import transformation.pipeline
        import compliance.engine
        import compliance.exceptions
        import compliance.copilot
        import compliance.rbac
        import audit.logger
        import api.server
        assert True

    def test_settings_has_all_required_fields(self):
        assert settings.system_name == "SANKƆFA-BRIDGE"
        assert settings.architect == "David King Boison"
        assert settings.framework == "Visionary Prompt Framework (VPF)"
        assert settings.principle != ""
        assert settings.version != ""

    def test_vpf_principle_complete(self):
        p = settings.principle
        assert "provenance" in p.lower()
        assert "custodianship" in p.lower()
        assert "auditability" in p.lower()

    def test_role_boundary_config_has_prohibited_list(self):
        from config.settings import RoleBoundaryConfig
        rb = RoleBoundaryConfig()
        prohibited = rb.PROHIBITED_ACTIONS
        assert "hold_funds" in prohibited
        assert "sign_blockchain_transaction" in prohibited
        assert "approve_settlement" in prohibited
        assert "tokenize_asset" in prohibited
        assert "custody_digital_assets" in prohibited

    def test_role_boundary_permitted_list(self):
        from config.settings import RoleBoundaryConfig
        rb = RoleBoundaryConfig()
        permitted = rb.PERMITTED_ACTIONS
        assert "retrieve_file" in permitted
        assert "validate_file" in permitted
        assert "deliver_to_receiver" in permitted
        assert "log_event" in permitted

    def test_african_corridor_jurisdictions_registered(self):
        from compliance.engine import AFRICAN_CORRIDOR
        assert "GH" in AFRICAN_CORRIDOR
        assert "NG" in AFRICAN_CORRIDOR
        assert "KE" in AFRICAN_CORRIDOR
        assert "RW" in AFRICAN_CORRIDOR
        assert "ZA" in AFRICAN_CORRIDOR

    def test_ghana_is_tier_1_fatf_member(self):
        from compliance.engine import AFRICAN_CORRIDOR
        gh = AFRICAN_CORRIDOR["GH"]
        assert gh["risk_tier"] == 1
        assert gh["fatf_member"] is True

    def test_all_compliance_flags_have_explanations(self):
        from compliance.engine import ComplianceFlag
        from compliance.copilot import FLAG_EXPLANATIONS
        for flag in ComplianceFlag:
            assert flag in FLAG_EXPLANATIONS, f"Missing explanation for {flag}"

    def test_audit_singleton_is_consistent(self):
        from audit.logger import audit, SankofaAuditLogger
        audit2 = SankofaAuditLogger()
        assert audit is audit2

    def test_database_tables_creatable(self):
        import asyncio
        from config.database import db
        asyncio.run(db.init_db())
        assert True


# ═════════════════════════════════════════════
# SECTION 4 — FULL CORRIDOR INTEGRATION
# ═════════════════════════════════════════════

class TestCorridorIntegration:

    def setup_method(self):
        import validation.validator as vmod
        vmod._seen_hashes.clear()

    @pytest.mark.asyncio
    async def test_ghana_to_nigeria_simulation(self):
        """Full GH→NG corridor simulation: inject → validate → transform → comply → deliver."""
        import json
        from datetime import datetime, timezone
        from config.models import SankofaMessage, FileState
        from config.settings import settings
        from validation.validator import ValidationEngine
        from transformation.pipeline import TransformationEngine, DeliveryEngine
        from compliance.engine import ComplianceEngine

        settings.compliance.gate_cleared = True
        settings.receiver.base_url = ""

        payload = {
            "transaction_reference": "TXN-GH-NG-001",
            "sender_entity_id": "SENDER_TEST_GH_001",
            "receiver_entity_id": "RECEIVER_TEST_NG_001",
            "amount": 5000.0,
            "currency": "GHS",
            "jurisdiction": "GH",
            "corridor": "GH-NG",
        }
        raw = json.dumps(payload).encode()
        msg = SankofaMessage(
            file_name="gh_ng_transfer_001.json",
            file_format="json",
            source_system="MockConnector",
            sender_entity_id="SENDER_TEST_GH_001",
            receiver_entity_id="RECEIVER_TEST_NG_001",
            jurisdiction="GH",
            classification="restricted",
            raw_payload=raw,
            file_size_bytes=len(raw),
            file_id="GH-NG-FILE-001",
        )
        msg.compute_hash()
        msg.received_at_utc = datetime.now(timezone.utc)
        msg.transition(FileState.QUARANTINED, "CorridorTest", "setup")

        # L2 Validate
        msg = ValidationEngine().validate(msg)
        assert msg.state == FileState.VALIDATED

        # L3 Transform
        msg = TransformationEngine().transform(msg)
        assert msg.state == FileState.TRANSFORMED

        # L6 Compliance
        msg, report = ComplianceEngine().run(msg)
        assert report.overall_status == "CLEAR"

        # L4 Deliver
        msg = await DeliveryEngine().deliver(msg)
        assert msg.state == FileState.DELIVERED

        # Verify corridor metadata preserved in original_fields
        original = msg.transformed_payload["payload"].get("original_fields", {})
        assert original.get("corridor") == "GH-NG"

        settings.compliance.gate_cleared = False

    @pytest.mark.asyncio
    async def test_multi_file_corridor_batch(self):
        """Process a batch of 5 files representing a corridor day's volume."""
        import asyncio
        from config.settings import settings
        from connectors.connector import MockConnector
        from validation.validator import ValidationEngine
        from transformation.pipeline import TransformationEngine, DeliveryEngine
        from compliance.engine import ComplianceEngine
        from config.models import FileState

        settings.compliance.gate_cleared = True
        settings.receiver.base_url = ""

        import validation.validator as vmod
        vmod._seen_hashes.clear()

        connector = MockConnector()
        await connector.connect()

        results = []
        for i in range(5):
            desc = connector.inject_test_file(
                sender_id=f"SENDER_TEST_BATCH_{i:03d}",
                receiver_id=f"RECEIVER_TEST_BATCH_{i:03d}",
                file_type="json" if i % 2 == 0 else "xml",
            )

        pending = await connector.poll()
        for desc in pending:
            raw = await connector.download(desc)
            msg = connector._build_message(
                file_id=desc["file_id"], file_name=desc["file_name"],
                raw_bytes=raw, sender_entity_id=desc["sender_entity_id"],
            )
            msg = ValidationEngine().validate(msg)
            if msg.state.value == "validated":
                msg = TransformationEngine().transform(msg)
                msg, _ = ComplianceEngine().run(msg)
                msg = await DeliveryEngine().deliver(msg)
            results.append(msg)

        delivered = sum(1 for m in results if m.state == FileState.DELIVERED)
        assert delivered == 5
        assert all(len(m.chain_of_custody) >= 5 for m in results)

        settings.compliance.gate_cleared = False


# ═════════════════════════════════════════════
# SECTION 5 — API PARTNER ENDPOINTS
# ═════════════════════════════════════════════

class TestPartnerAPI:

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
            self._c = c
            yield c

    @property
    def H(self):
        import os
        return {"X-SANKOFA-API-Key": os.getenv("SANKOFA_API_KEY", "dev-key-replace-in-production")}

    async def test_health_still_passing(self):
        r = await self._c.get("/health")
        assert r.status_code == 200

    async def test_full_api_surface_responds(self):
        """Smoke test all major API surface endpoints."""
        endpoints = [
            ("GET", "/health"),
            ("GET", "/v1/status"),
            ("GET", "/v1/dashboard"),
            ("GET", "/v1/files"),
            ("GET", "/v1/compliance/gate"),
            ("GET", "/v1/exceptions"),
            ("GET", "/v1/audit/export"),
            ("GET", "/v1/copilot/status"),
            ("GET", "/v1/copilot/regulatory-briefing?jurisdiction=GH"),
        ]
        for method, path in endpoints:
            r = await self._c.request(method, path, headers=self.H)
            assert r.status_code == 200, f"{method} {path} returned {r.status_code}"

    async def test_copilot_ghana_corridor_briefing(self):
        r = await self._c.get(
            "/v1/copilot/regulatory-briefing?jurisdiction=GH", headers=self.H
        )
        assert r.status_code == 200
        d = r.json()
        assert "bank of ghana" in d["message"].lower()

    async def test_copilot_nigeria_briefing(self):
        r = await self._c.get(
            "/v1/copilot/regulatory-briefing?jurisdiction=NG", headers=self.H
        )
        assert r.status_code == 200

    async def test_prohibited_endpoints_all_return_403(self):
        prohibited = [
            "/prohibited/hold-funds",
            "/prohibited/sign-blockchain",
            "/prohibited/approve-settlement",
            "/prohibited/tokenize-asset",
            "/prohibited/custody-assets",
        ]
        for path in prohibited:
            r = await self._c.post(path, headers=self.H)
            assert r.status_code == 403, f"{path} should return 403"
