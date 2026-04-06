"""
SANKƆFA-BRIDGE — Integration Test Runner
Path 2 — Real Source Integration

Tests your actual source system connection before going live.
Runs a complete dry-run: connect → poll → download one file →
validate → transform → compliance check → simulated delivery.

Usage:
  python integration/test_connection.py --type s3
  python integration/test_connection.py --type sftp
  python integration/test_connection.py --type rest_api
  python integration/test_connection.py --type azure_blob
  python integration/test_connection.py --auto      # reads ACTIVE_CONNECTOR from .env

Requires the relevant env vars to be set in .env first.
"""

import asyncio
import sys
import os
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

GOLD  = '\033[38;5;214m'
GREEN = '\033[0;32m'
RED   = '\033[0;31m'
AMBER = '\033[38;5;214m'
DIM   = '\033[2m'
BOLD  = '\033[1m'
RST   = '\033[0m'

def ok(msg):   print(f"  {GREEN}✓{RST} {msg}")
def warn(msg): print(f"  {AMBER}⚠{RST} {msg}")
def fail(msg): print(f"  {RED}✗{RST} {msg}")
def info(msg): print(f"  {DIM}→{RST} {msg}")
def hdr(msg):  print(f"\n{GOLD}{BOLD}{msg}{RST}\n{DIM}{'─'*45}{RST}")


class IntegrationTester:
    """
    Runs end-to-end integration tests against a real source system.
    Safe: read-only on source, simulated delivery (no real receiver calls).
    """

    def __init__(self, connector_type: str):
        self.connector_type = connector_type
        self.results = []
        self.start_time = datetime.now(timezone.utc)

    async def run(self):
        hdr(f"SANKƆFA-BRIDGE Integration Test — {self.connector_type.upper()}")
        print(f"  {DIM}Start: {self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}{RST}")

        # Step 1 — Environment check
        await self._test_environment()

        # Step 2 — Connector connection
        connected, connector = await self._test_connection()
        if not connected:
            self._report()
            return False

        # Step 3 — Poll for files
        files = await self._test_poll(connector)
        if not files:
            self._report()
            return False

        # Step 4 — Download one file
        message = await self._test_download(connector, files[0])
        if not message:
            self._report()
            return False

        # Step 5 — Full pipeline
        await self._test_pipeline(message)

        self._report()
        return all(r[0] for r in self.results)

    async def _test_environment(self):
        hdr("Step 1: Environment Check")
        required_vars = {
            "s3":        ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET"],
            "sftp":      ["SFTP_HOST", "SFTP_USER", "SFTP_KEY_PATH"],
            "rest_api":  ["SOURCE_API_URL", "SOURCE_API_KEY"],
            "azure_blob":["AZURE_CONNECTION_STRING", "AZURE_CONTAINER"],
        }
        vars_needed = required_vars.get(self.connector_type, [])
        all_set = True
        for v in vars_needed:
            val = os.getenv(v, "")
            if val:
                ok(f"{v} is set")
            else:
                fail(f"{v} is NOT set — required for {self.connector_type}")
                all_set = False
        self.results.append((all_set, "Environment variables"))

    async def _test_connection(self):
        hdr("Step 2: Source Connection")
        from config.settings import settings, ConnectorType
        settings.connector_type = ConnectorType(self.connector_type)

        # Use pre-seeded connector if available
        if hasattr(self, '_seeded_connector'):
            connector = self._seeded_connector
            ok(f"Using pre-seeded {self.connector_type} connector")
            self.results.append((True, f"Connect to {self.connector_type}"))
            return True, connector

        from connectors.connector import get_connector
        connector = get_connector()

        info(f"Connecting to {self.connector_type}...")
        try:
            connected = await connector.connect()
            if connected:
                ok(f"Connected to {self.connector_type} source")
                self.results.append((True, f"Connect to {self.connector_type}"))
                return True, connector
            else:
                fail("Connection returned False — check credentials")
                self.results.append((False, f"Connect to {self.connector_type}"))
                return False, None
        except Exception as e:
            fail(f"Connection failed: {e}")
            self.results.append((False, f"Connect to {self.connector_type}"))
            return False, None

    async def _test_poll(self, connector):
        hdr("Step 3: Poll for Files")
        info("Polling source for available files...")
        try:
            files = await connector.poll()
            if files:
                ok(f"Found {len(files)} file(s)")
                for f in files[:3]:
                    info(f"  {f.get('file_name', f.get('file_id', 'unknown'))} "
                         f"({f.get('size', '?')} bytes)")
                if len(files) > 3:
                    info(f"  ... and {len(files)-3} more")
                self.results.append((True, f"Poll — {len(files)} files found"))
                return files
            else:
                warn("No files found in source — check prefix/path configuration")
                warn("Place a test JSON file in the source location and re-run")
                self.results.append((False, "Poll — no files found"))
                return []
        except Exception as e:
            fail(f"Poll failed: {e}")
            self.results.append((False, "Poll"))
            return []

    async def _test_download(self, connector, file_descriptor):
        hdr("Step 4: Download Test File")
        fname = file_descriptor.get("file_name", "unknown")
        info(f"Downloading: {fname}")
        try:
            raw_bytes = await connector.download(file_descriptor)
            if raw_bytes:
                ok(f"Downloaded {len(raw_bytes):,} bytes")
                # Show first 200 chars of content
                preview = raw_bytes[:200].decode("utf-8", errors="replace").strip()
                info(f"Content preview: {preview[:100]}{'...' if len(preview)>100 else ''}")
                # Build SankofaMessage
                message = connector._build_message(
                    file_id=file_descriptor.get("file_id", "INTEGRATION-TEST-001"),
                    file_name=fname,
                    raw_bytes=raw_bytes,
                    sender_entity_id=file_descriptor.get("sender_entity_id", "INTEGRATION_TEST_SENDER"),
                    metadata={"integration_test": True, "source": self.connector_type}
                )
                ok(f"Message created — ID: {message.message_id[:16]}...")
                ok(f"Hash: {message.file_hash_sha256[:16]}...")
                self.results.append((True, f"Download — {len(raw_bytes):,} bytes"))
                return message
            else:
                fail("Download returned empty bytes")
                self.results.append((False, "Download"))
                return None
        except Exception as e:
            fail(f"Download failed: {e}")
            self.results.append((False, "Download"))
            return None

    async def _test_pipeline(self, message):
        hdr("Step 5: Pipeline Dry Run (no real delivery)")
        from config.settings import settings
        settings.compliance.gate_cleared = True
        settings.receiver.base_url = ""  # Simulation — no real receiver call

        import validation.validator as vmod
        vmod._seen_hashes.clear()

        # L2 Validation
        info("Running validation (Layer 2)...")
        from validation.validator import ValidationEngine
        message = ValidationEngine().validate(message)
        if message.state.value in ["validated", "failed"]:
            passed = message.state.value == "validated"
            (ok if passed else fail)(f"Validation: {message.validation.status.value.upper()}")
            if message.validation.errors:
                for e in message.validation.errors:
                    warn(f"  Error: {e}")
            if message.validation.warnings:
                for w in message.validation.warnings:
                    warn(f"  Warning: {w}")
            self.results.append((passed, f"Validation ({message.validation.status.value})"))
            if not passed:
                return

        # L3 Transformation
        info("Running transformation (Layer 3)...")
        try:
            from transformation.pipeline import TransformationEngine
            message = TransformationEngine().transform(message)
            ok(f"Transformed: {message.file_format} → canonical payload")
            ok(f"Payload keys: {list(message.transformed_payload.keys())}")
            self.results.append((True, "Transformation"))
        except Exception as e:
            fail(f"Transformation: {e}")
            self.results.append((False, "Transformation"))
            return

        # L6 Compliance
        info("Running compliance screening (Layer 6)...")
        from compliance.engine import ComplianceEngine
        message, report = ComplianceEngine().run(message)
        passed = report.overall_status in ["CLEAR", "FLAGGED"]
        (ok if passed else warn)(f"Compliance: {report.overall_status}")
        for flag in report.warning_flags:
            warn(f"  Warning: {flag.flag.value} — {flag.message[:80]}")
        for flag in report.blocking_flags:
            fail(f"  BLOCKED: {flag.flag.value} — {flag.message[:80]}")
        self.results.append((passed, f"Compliance ({report.overall_status})"))
        if not passed:
            warn("Compliance block — file will go to exception queue in production")
            return

        # L4 Delivery simulation
        info("Running delivery simulation (Layer 4, no real receiver)...")
        from transformation.pipeline import DeliveryEngine
        message = await DeliveryEngine().deliver(message)
        passed = message.state.value == "delivered"
        (ok if passed else fail)(f"Delivery: {message.state.value.upper()}")
        if message.delivery:
            ok(f"Delivery ID: {message.delivery.delivery_id}")
            ok(f"Mode: {(message.delivery.response_body or {}).get('mode', 'real')}")
        self.results.append((passed, f"Delivery ({message.state.value})"))

        # Chain of custody
        ok(f"Chain of custody: {len(message.chain_of_custody)} entries")
        for entry in message.chain_of_custody:
            info(f"  {entry.from_state.value if entry.from_state else 'START'} → {entry.to_state.value} ({entry.actor})")

        settings.compliance.gate_cleared = False

    def _report(self):
        hdr("Integration Test Results")
        passed = sum(1 for r in self.results if r[0])
        total  = len(self.results)
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()

        for success, name in self.results:
            (ok if success else fail)(name)

        print(f"\n  {BOLD}{'─'*40}{RST}")
        color = GREEN if passed == total else (AMBER if passed > 0 else RED)
        print(f"  {color}{BOLD}{passed}/{total} checks passed{RST}  ({elapsed:.1f}s)")

        if passed == total:
            print(f"\n  {GREEN}{BOLD}SOURCE INTEGRATION VERIFIED ✓{RST}")
            print(f"\n  {DIM}Your source system is ready for live use.{RST}")
            print(f"  {DIM}Next steps:{RST}")
            print(f"  {DIM}  1. Set COMPLIANCE_GATE_CLEARED=true in .env{RST}")
            print(f"  {DIM}  2. Set RECEIVER_API_URL and RECEIVER_API_KEY in .env{RST}")
            print(f"  {DIM}  3. Run: ./scripts/ops.sh ready{RST}")
            print(f"  {DIM}  4. Run: ./scripts/ops.sh deploy{RST}")
        elif passed > 0:
            print(f"\n  {AMBER}{BOLD}PARTIAL — fix warnings above and re-run{RST}")
        else:
            print(f"\n  {RED}{BOLD}FAILED — fix errors above and re-run{RST}")
        print()


async def main():
    parser = argparse.ArgumentParser(description="SANKƆFA-BRIDGE Integration Tester")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--type", choices=["s3","sftp","rest_api","azure_blob","mock"],
                       help="Connector type to test")
    group.add_argument("--auto", action="store_true",
                       help="Read connector type from ACTIVE_CONNECTOR env var")
    parser.add_argument("--seed", type=int, default=0,
                        help="Pre-inject N test files into mock connector before testing")
    args = parser.parse_args()

    connector_type = args.type
    if args.auto:
        connector_type = os.getenv("ACTIVE_CONNECTOR", "mock")
        info(f"Auto-detected connector: {connector_type}")

    tester = IntegrationTester(connector_type)
    # Pre-seed mock connector if requested
    if args.seed and connector_type == "mock":
        from connectors.connector import MockConnector
        mock = MockConnector()
        await mock.connect()
        for i in range(args.seed):
            mock.inject_test_file(
                sender_id=f"INTEGRATION_TEST_SENDER_{i+1:03d}",
                receiver_id=f"INTEGRATION_TEST_RECEIVER_{i+1:03d}",
                file_type="json" if i % 2 == 0 else "xml"
            )
        info(f"Pre-seeded {args.seed} test file(s) into mock connector")
        tester._seeded_connector = mock

    success = await tester.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
