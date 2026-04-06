"""
SANKƆFA-BRIDGE — Main Orchestrator
Wires all seven layers into one end-to-end pipeline.

Flow:
  Layer 1 (Connector) → detects file
  Layer 2 (Validation) → validates & quarantines
  Layer 3 (Transformation) → normalizes to canonical form
  Layer 6 (Compliance) → provenance & policy gate
  Layer 4 (Delivery) → delivers to receiver API
  Layer 5 (Audit) → records every step (runs throughout)

Usage:
  python main.py                   # Run the live system
  python main.py --test            # Run a mock pipeline test
  python main.py --inject 3        # Inject 3 test files and process
"""

import asyncio
import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.models import SankofaMessage, FileState
from config.settings import settings
from connectors.connector import run_ingestion_loop, get_connector
from validation.validator import validator
from transformation.pipeline import transformer, delivery_engine
from compliance.engine import compliance_engine
from compliance.exceptions import exception_manager
from audit.logger import audit, AuditEventType


class SankofaOrchestrator:
    """
    The main pipeline controller.
    Receives a SankofaMessage from Layer 1 and runs it through:
    L2 Validation → L3 Transformation → L6 Compliance → L4 Delivery
    Layer 5 (Audit) runs throughout every step.
    """

    async def process(self, message: SankofaMessage) -> SankofaMessage:
        print(f"\n{'─'*60}")
        print(f"  Processing: {message.file_name}")
        print(f"  Message ID: {message.message_id[:16]}...")
        print(f"  Hash:       {message.file_hash_sha256[:16]}...")
        print(f"{'─'*60}")

        # LAYER 2 — Validation & Quarantine
        print(f"  [L2] Validating...")
        message = validator.validate(message)
        if message.state == FileState.FAILED:
            print(f"  [L2] FAILED — {message.validation.errors}")
            return message
        print(f"  [L2] {message.validation.status.value.upper()}")
        for w in (message.validation.warnings or []):
            print(f"       ⚠  {w}")

        # LAYER 3 — Transformation
        print(f"  [L3] Transforming...")
        try:
            message = transformer.transform(message)
            print(f"  [L3] {message.file_format} → canonical payload")
        except Exception as e:
            print(f"  [L3] FAILED — {e}")
            return message

        # LAYER 6 — Compliance & Sovereignty Engine
        print(f"  [L6] Compliance screening...")
        message, compliance_report = compliance_engine.run(message)
        print(f"  [L6] {compliance_report.overall_status}", end="")
        if compliance_report.warning_flags:
            print(f" ({len(compliance_report.warning_flags)} warnings)", end="")
        print()

        if compliance_report.overall_status in ["BLOCKED", "ESCALATED"]:
            record = exception_manager.create(message, compliance_report.to_dict())
            print(f"  [L6] Exception created: {record.exception_id} — priority: {record.priority.value.upper()}")
            print(f"\n  Final state: EXCEPTION")
            print(f"  Reason: {message.exception_reason}")
            print(f"  Custody entries: {len(message.chain_of_custody)}")
            print(f"{'─'*60}\n")
            return message

        # LAYER 4 — Delivery
        print(f"  [L4] Delivering...")
        message = await delivery_engine.deliver(message)

        if message.state == FileState.DELIVERED:
            mode = (message.delivery.response_body or {}).get("mode", "")
            print(f"  [L4] ✓  delivery_id={message.delivery.delivery_id}" +
                  (f" ({mode})" if mode else ""))
        elif message.state == FileState.EXCEPTION:
            print(f"  [L4] EXCEPTION — {message.exception_reason}")
        else:
            err = message.delivery.error_message if message.delivery else "unknown"
            print(f"  [L4] FAILED — {err}")

        print(f"\n  Final state: {message.state.value.upper()}")
        print(f"  Custody entries: {len(message.chain_of_custody)}")
        print(f"{'─'*60}\n")
        return message


orchestrator = SankofaOrchestrator()


# ─────────────────────────────────────────────
# PIPELINE TEST — inject mock files
# ─────────────────────────────────────────────

async def run_pipeline_test(num_files: int = 3):
    """
    Run a complete end-to-end pipeline test using mock files.
    No real external connections required.
    """
    print(f"\n{'═'*60}")
    print(f"  SANKƆFA-BRIDGE — Pipeline Test")
    print(f"  Stage: {settings.stage}")
    print(f"  Architect: {settings.architect}")
    print(f"  Framework: {settings.framework}")
    print(f"{'═'*60}")
    print(f"\n  VPF Principle:")
    print(f"  \"{settings.principle}\"")
    print(f"\n  Injecting {num_files} test file(s)...\n")

    from connectors.connector import MockConnector
    connector = MockConnector()
    await connector.connect()

    results = []

    for i in range(num_files):
        # Alternate JSON and XML
        ftype = "json" if i % 2 == 0 else "xml"
        descriptor = connector.inject_test_file(
            sender_id=f"SENDER_TEST_{i+1:03d}",
            receiver_id=f"RECEIVER_TEST_{i+1:03d}",
            file_type=ftype,
        )
        print(f"  → Injected: {descriptor['file_name']}")

    pending = await connector.poll()
    for descriptor in pending:
        raw = await connector.download(descriptor)
        message = connector._build_message(
            file_id=descriptor["file_id"],
            file_name=descriptor["file_name"],
            raw_bytes=raw,
            sender_entity_id=descriptor.get("sender_entity_id", ""),
            metadata={"source_descriptor": {
                k: v for k, v in descriptor.items() if not k.startswith("_")
            }}
        )
        final = await orchestrator.process(message)
        results.append(final)

    # Summary
    print(f"\n{'═'*60}")
    print(f"  PIPELINE TEST SUMMARY")
    print(f"{'═'*60}")
    states = {}
    for msg in results:
        states[msg.state.value] = states.get(msg.state.value, 0) + 1
    for state, count in states.items():
        print(f"  {state.upper():<20} {count}")
    print(f"  {'─'*30}")
    print(f"  Total processed:     {len(results)}")
    print(f"\n  Audit log written to: logs/")
    print(f"{'═'*60}\n")

    return results


# ─────────────────────────────────────────────
# LIVE SYSTEM
# ─────────────────────────────────────────────

async def run_live():
    """Run the live ingestion loop."""
    print(f"\n{'═'*60}")
    print(f"  SANKƆFA-BRIDGE — Live System")
    print(f"  Connector: {settings.connector_type.value}")
    print(f"  Compliance gate cleared: {settings.compliance.gate_cleared}")
    print(f"{'═'*60}\n")

    stop = asyncio.Event()

    async def on_file(message: SankofaMessage):
        await orchestrator.process(message)

    try:
        await run_ingestion_loop(on_file, stop)
    except KeyboardInterrupt:
        stop.set()
        print("\n  System stopping...\n")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SANKƆFA-BRIDGE")
    parser.add_argument("--test", action="store_true", help="Run pipeline test")
    parser.add_argument("--inject", type=int, default=3, help="Number of test files to inject")
    args = parser.parse_args()

    if args.test:
        asyncio.run(run_pipeline_test(args.inject))
    else:
        asyncio.run(run_live())
