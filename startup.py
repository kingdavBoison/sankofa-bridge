"""
SANKƆFA-BRIDGE — Production Startup Script
Runs database initialization before the API server starts.
Used by Render, Railway, Fly.io as the pre-start hook.
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


async def startup():
    print("=== SANKƆFA-BRIDGE Production Startup ===")
    print(f"Architect: David King Boison")
    print(f"Framework: Visionary Prompt Framework (VPF)")

    # Initialize database
    from config.database import db
    await db.init_db()
    print("✓ Database initialized")

    # Verify compliance settings
    from config.settings import settings
    print(f"✓ Connector: {settings.connector_type.value}")
    print(f"✓ Compliance gate: {'CLEARED' if settings.compliance.gate_cleared else 'PENDING'}")
    print(f"✓ Jurisdiction: {settings.compliance.jurisdiction}")

    # Run quick sanity test
    from config.models import SankofaMessage
    msg = SankofaMessage(file_name="startup_test.json", file_format="json")
    assert msg.message_id, "Model initialization failed"
    print("✓ Core models operational")

    print("=== Startup complete — API server starting ===")


if __name__ == "__main__":
    asyncio.run(startup())
