"""
SANKƆFA-BRIDGE — Database Layer
Stage 2 Hardening

Persistent storage for:
  - SankofaMessage state and metadata
  - Sender/receiver registry
  - Compliance gate answers
  - Delivery receipts
  - Exception queue

Stage 2: SQLite (async) for development and testing.
Stage 5: PostgreSQL — change DATABASE_URL only. Schema is identical.

All writes are append-friendly. State transitions add rows; nothing is deleted.
The database is the durable complement to the append-only audit log.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text,
    DateTime, ForeignKey, Enum as SAEnum, Index
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.future import select

from config.models import SankofaMessage, FileState, ValidationStatus
from config.settings import settings


# ─────────────────────────────────────────────
# BASE & ENGINE
# ─────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


def _make_engine():
    url = settings.database.url
    # SQLite requires aiosqlite driver
    if url.startswith("sqlite"):
        url = url.replace("sqlite:///", "sqlite+aiosqlite:///")
    elif url.startswith("postgresql"):
        url = url.replace("postgresql://", "postgresql+asyncpg://")
    return create_async_engine(url, echo=False, future=True)


engine = _make_engine()
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


# ─────────────────────────────────────────────
# ORM MODELS
# ─────────────────────────────────────────────

class DBMessage(Base):
    """Persistent record of every SankofaMessage processed."""
    __tablename__ = "messages"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    message_id     = Column(String, unique=True, nullable=False, index=True)
    file_id        = Column(String, nullable=False)
    file_name      = Column(String, nullable=False)
    file_format    = Column(String, nullable=False)
    source_system  = Column(String, nullable=False)
    sender_entity_id   = Column(String, index=True)
    receiver_entity_id = Column(String, index=True)
    destination_system = Column(String)
    file_hash_sha256   = Column(String, unique=True, index=True)
    file_size_bytes    = Column(Integer)
    jurisdiction       = Column(String, default="GH")
    classification     = Column(String, default="restricted")
    state              = Column(SAEnum(FileState), nullable=False, index=True)
    validation_status  = Column(String)
    validation_errors  = Column(Text)       # JSON list
    compliance_flags   = Column(Text)       # JSON list
    exception_reason   = Column(Text)
    delivery_id        = Column(String)
    delivery_http_status = Column(Integer)
    delivery_attempts    = Column(Integer, default=0)
    chain_of_custody   = Column(Text)       # JSON list of CustodyEntry dicts
    metadata_json      = Column(Text)       # JSON dict
    received_at_utc    = Column(DateTime(timezone=True))
    created_at         = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at         = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                                onupdate=lambda: datetime.now(timezone.utc))


class DBSenderRegistry(Base):
    """Registered sender entities — required for entitlement checks."""
    __tablename__ = "sender_registry"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    entity_id      = Column(String, unique=True, nullable=False, index=True)
    entity_name    = Column(String, nullable=False)
    jurisdiction   = Column(String, default="GH")
    kyc_verified   = Column(Boolean, default=False)
    aml_cleared    = Column(Boolean, default=False)
    active         = Column(Boolean, default=True)
    registered_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    notes          = Column(Text)


class DBReceiverRegistry(Base):
    """Registered receiver entities."""
    __tablename__ = "receiver_registry"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    entity_id      = Column(String, unique=True, nullable=False, index=True)
    entity_name    = Column(String, nullable=False)
    api_endpoint   = Column(String)
    jurisdiction   = Column(String, default="GH")
    active         = Column(Boolean, default=True)
    registered_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DBComplianceGate(Base):
    """Records answers to the 18-question compliance gate."""
    __tablename__ = "compliance_gate"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    question_id    = Column(Integer, nullable=False)
    category       = Column(String)         # legal / technical / governance
    question_text  = Column(Text)
    answer_text    = Column(Text)
    answered_by    = Column(String)
    answered_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    verified       = Column(Boolean, default=False)


class DBException(Base):
    """Exception queue — files requiring manual compliance review."""
    __tablename__ = "exceptions"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    message_id     = Column(String, ForeignKey("messages.message_id"), index=True)
    reason         = Column(Text)
    flags          = Column(Text)           # JSON list
    assigned_to    = Column(String)
    status         = Column(String, default="open")   # open / reviewing / resolved / escalated
    resolution     = Column(Text)
    created_at     = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved_at    = Column(DateTime(timezone=True))


# ─────────────────────────────────────────────
# DATABASE SERVICE
# ─────────────────────────────────────────────

class DatabaseService:
    """
    Async database service.
    All operations use async context managers — safe for FastAPI and asyncio.
    """

    async def init_db(self):
        """Create all tables. Safe to call multiple times."""
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def save_message(self, message: SankofaMessage) -> DBMessage:
        """Upsert a SankofaMessage to the database."""
        async with AsyncSessionLocal() as session:
            # Check existing
            result = await session.execute(
                select(DBMessage).where(DBMessage.message_id == message.message_id)
            )
            db_msg = result.scalar_one_or_none()

            delivery_id = None
            delivery_status = None
            delivery_attempts = 0
            if message.delivery:
                delivery_id = message.delivery.delivery_id
                delivery_status = message.delivery.http_status
                delivery_attempts = message.delivery.attempts

            if db_msg:
                # Update existing record
                db_msg.state = message.state
                db_msg.validation_status = (
                    message.validation.status.value if message.validation else None
                )
                db_msg.validation_errors = json.dumps(
                    message.validation.errors if message.validation else []
                )
                db_msg.compliance_flags = json.dumps(message.compliance_flags)
                db_msg.exception_reason = message.exception_reason
                db_msg.delivery_id = delivery_id
                db_msg.delivery_http_status = delivery_status
                db_msg.delivery_attempts = delivery_attempts
                db_msg.chain_of_custody = json.dumps(
                    [e.to_dict() for e in message.chain_of_custody]
                )
                db_msg.sender_entity_id = message.sender_entity_id
                db_msg.receiver_entity_id = message.receiver_entity_id
                db_msg.updated_at = datetime.now(timezone.utc)
            else:
                db_msg = DBMessage(
                    message_id=message.message_id,
                    file_id=message.file_id,
                    file_name=message.file_name,
                    file_format=message.file_format,
                    source_system=message.source_system,
                    sender_entity_id=message.sender_entity_id,
                    receiver_entity_id=message.receiver_entity_id,
                    destination_system=message.destination_system,
                    file_hash_sha256=message.file_hash_sha256,
                    file_size_bytes=message.file_size_bytes,
                    jurisdiction=message.jurisdiction,
                    classification=message.classification,
                    state=message.state,
                    validation_status=(
                        message.validation.status.value if message.validation else None
                    ),
                    validation_errors=json.dumps(
                        message.validation.errors if message.validation else []
                    ),
                    compliance_flags=json.dumps(message.compliance_flags),
                    exception_reason=message.exception_reason,
                    delivery_id=delivery_id,
                    delivery_http_status=delivery_status,
                    delivery_attempts=delivery_attempts,
                    chain_of_custody=json.dumps(
                        [e.to_dict() for e in message.chain_of_custody]
                    ),
                    metadata_json=json.dumps(
                        {k: v for k, v in message.metadata.items()
                         if k != "parsed_content"}
                    ),
                    received_at_utc=message.received_at_utc,
                )
                session.add(db_msg)

            await session.commit()
            return db_msg

    async def get_message(self, message_id: str) -> Optional[DBMessage]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(DBMessage).where(DBMessage.message_id == message_id)
            )
            return result.scalar_one_or_none()

    async def list_messages(
        self,
        state: Optional[FileState] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[DBMessage]:
        async with AsyncSessionLocal() as session:
            q = select(DBMessage).order_by(DBMessage.created_at.desc())
            if state:
                q = q.where(DBMessage.state == state)
            q = q.limit(limit).offset(offset)
            result = await session.execute(q)
            return result.scalars().all()

    async def get_stats(self) -> dict:
        """Summary statistics for dashboard."""
        async with AsyncSessionLocal() as session:
            from sqlalchemy import func
            result = await session.execute(
                select(DBMessage.state, func.count(DBMessage.id))
                .group_by(DBMessage.state)
            )
            return dict(result.all())

    async def register_sender(
        self, entity_id: str, entity_name: str,
        jurisdiction: str = "GH", notes: str = ""
    ) -> DBSenderRegistry:
        async with AsyncSessionLocal() as session:
            # Upsert — idempotent registration
            result = await session.execute(
                select(DBSenderRegistry).where(DBSenderRegistry.entity_id == entity_id)
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.entity_name = entity_name
                existing.jurisdiction = jurisdiction
                existing.notes = notes
                await session.commit()
                return existing
            sender = DBSenderRegistry(
                entity_id=entity_id,
                entity_name=entity_name,
                jurisdiction=jurisdiction,
                notes=notes,
            )
            session.add(sender)
            await session.commit()
            return sender

    async def create_exception(self, message: SankofaMessage) -> DBException:
        async with AsyncSessionLocal() as session:
            exc = DBException(
                message_id=message.message_id,
                reason=message.exception_reason or "Flagged for review",
                flags=json.dumps(message.compliance_flags),
                status="open",
            )
            session.add(exc)
            await session.commit()
            return exc

    async def list_exceptions(self, status: str = "open") -> List[DBException]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(DBException)
                .where(DBException.status == status)
                .order_by(DBException.created_at.desc())
            )
            return result.scalars().all()


# Singleton
db = DatabaseService()
