"""
SANKƆFA-BRIDGE — Transformation Engine (Layer 3)
+ Delivery Engine (Layer 4)

Layer 3 — Transformation:
  Converts the validated file payload into the canonical
  SankofaMessage delivery format, ready for the receiver API.

Layer 4 — Delivery:
  Authenticated push to receiver API.
  Retries with exponential backoff.
  Circuit breaker to protect unstable endpoints.
  Idempotency enforced via Idempotency-Key header.
  Full acknowledgement tracking.
"""

import json
import asyncio
import time
from datetime import datetime, timezone
from typing import Optional
from enum import Enum

from config.models import SankofaMessage, FileState, DeliveryResult
from config.settings import settings
from audit.logger import audit, AuditEventType


# ═══════════════════════════════════════════════
# LAYER 3 — TRANSFORMATION ENGINE
# ═══════════════════════════════════════════════

class TransformationEngine:
    """
    Converts validated file content into the canonical delivery payload.

    Source format (JSON / XML / binary) is normalized into one
    standard SankofaMessage structure that the receiver API consumes.

    This layer is the "adapter" between whatever the sender uploads
    and whatever the receiver expects.
    """

    ACTOR = "TransformationEngine"

    def transform(self, message: SankofaMessage) -> SankofaMessage:
        """
        Transform the validated message into delivery-ready form.
        Returns message with .transformed_payload populated.
        """
        if message.state != FileState.VALIDATED:
            raise ValueError(
                f"Cannot transform message in state {message.state} — "
                f"must be VALIDATED first"
            )

        message.transition(
            FileState.TRANSFORMING,
            actor=self.ACTOR,
            action="transformation_started",
        )

        try:
            if message.file_format == "json":
                transformed = self._transform_json(message)
            elif message.file_format == "xml":
                transformed = self._transform_xml(message)
            else:
                transformed = self._transform_binary(message)

            # Set receiver entity from payload if not set
            if not message.receiver_entity_id and "receiver_entity_id" in transformed:
                message.receiver_entity_id = transformed["receiver_entity_id"]

            if not message.destination_system:
                message.destination_system = settings.receiver.endpoint

            # Build final delivery payload
            message.transformed_payload = {
                # Envelope (always present)
                "message_id": message.message_id,
                "source_system": message.source_system,
                "destination_system": message.destination_system,
                "sender_entity_id": message.sender_entity_id,
                "receiver_entity_id": message.receiver_entity_id,
                "file_hash_sha256": message.file_hash_sha256,
                "payload_version": message.payload_version,
                "jurisdiction": message.jurisdiction,
                "classification": message.classification,
                "received_at_utc": (
                    message.received_at_utc.isoformat()
                    if message.received_at_utc else None
                ),
                # Normalized content
                "payload": transformed,
                # Metadata
                "metadata": {
                    k: v for k, v in message.metadata.items()
                    if k != "parsed_content"  # Don't re-send raw parsed bytes
                },
            }

            message.transition(
                FileState.TRANSFORMED,
                actor=self.ACTOR,
                action="transformation_complete",
                notes=f"Format {message.file_format} → canonical payload",
            )

            return message

        except Exception as e:
            message.transition(
                FileState.FAILED,
                actor=self.ACTOR,
                action="transformation_failed",
                notes=str(e),
            )
            raise

    def _transform_json(self, message: SankofaMessage) -> dict:
        """
        Normalize a JSON payload.
        Maps source fields to canonical field names.
        """
        parsed = message.metadata.get("parsed_content", {})

        if isinstance(parsed, str):
            parsed = json.loads(parsed)

        # Canonical field mapping
        # Extend this mapping as receiver API contract is confirmed
        canonical = {
            "transaction_reference": (
                parsed.get("transaction_reference")
                or parsed.get("txn_ref")
                or parsed.get("reference")
                or message.file_id
            ),
            "sender_entity_id": (
                parsed.get("sender_entity_id")
                or parsed.get("sender_id")
                or message.sender_entity_id
            ),
            "receiver_entity_id": (
                parsed.get("receiver_entity_id")
                or parsed.get("receiver_id")
                or message.receiver_entity_id
            ),
            "instruction_type": parsed.get("instruction_type", "transfer_instruction"),
            "currency": parsed.get("currency", "GHS"),
            "jurisdiction": parsed.get("jurisdiction", message.jurisdiction),
            "original_fields": parsed,   # Preserve original for traceability
        }

        # Update sender if found in payload
        if canonical["sender_entity_id"]:
            message.sender_entity_id = canonical["sender_entity_id"]

        return canonical

    def _transform_xml(self, message: SankofaMessage) -> dict:
        """
        Normalize an XML payload.
        Converts XML tree to canonical dict.
        """
        import xml.etree.ElementTree as ET
        root = ET.fromstring(message.raw_payload)

        def xml_to_dict(element) -> dict:
            result = {}
            for child in element:
                tag = child.tag.lower().replace("-", "_")
                if len(child):
                    result[tag] = xml_to_dict(child)
                else:
                    result[tag] = child.text
            return result

        parsed = xml_to_dict(root)

        canonical = {
            "transaction_reference": (
                parsed.get("transactionreference")
                or parsed.get("transaction_reference")
                or message.file_id
            ),
            "sender_entity_id": (
                parsed.get("senderentityid")
                or parsed.get("sender_entity_id")
                or message.sender_entity_id
            ),
            "receiver_entity_id": (
                parsed.get("receiverentityid")
                or parsed.get("receiver_entity_id")
                or message.receiver_entity_id
            ),
            "instruction_type": parsed.get("instructiontype", "transfer_instruction"),
            "currency": parsed.get("currency", "GHS"),
            "jurisdiction": parsed.get("jurisdiction", message.jurisdiction),
            "original_fields": parsed,
        }

        if canonical["sender_entity_id"]:
            message.sender_entity_id = canonical["sender_entity_id"]

        return canonical

    def _transform_binary(self, message: SankofaMessage) -> dict:
        """
        Binary file — wrap as-is with metadata.
        Cannot parse content; deliver as base64 envelope.
        """
        import base64
        return {
            "format": "binary",
            "content_base64": base64.b64encode(message.raw_payload).decode("utf-8"),
            "size_bytes": message.file_size_bytes,
        }


# ═══════════════════════════════════════════════
# LAYER 4 — DELIVERY ENGINE
# ═══════════════════════════════════════════════

class CircuitBreakerState(str, Enum):
    CLOSED   = "closed"    # Normal — requests pass through
    OPEN     = "open"      # Tripped — requests blocked
    HALF_OPEN = "half_open" # Testing — one request allowed through


class CircuitBreaker:
    """
    Prevents hammering an unstable receiver API.
    Opens after N consecutive failures.
    Half-opens after reset timeout for test request.
    """

    def __init__(self, threshold: int = 5, reset_seconds: int = 60):
        self.threshold = threshold
        self.reset_seconds = reset_seconds
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None

    def record_success(self):
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.threshold:
            if self.state != CircuitBreakerState.OPEN:
                self.state = CircuitBreakerState.OPEN
                audit.log(
                    AuditEventType.CIRCUIT_BREAKER_OPEN,
                    "CircuitBreaker",
                    {"failures": self.failure_count, "threshold": self.threshold}
                )

    def is_open(self) -> bool:
        if self.state == CircuitBreakerState.OPEN:
            if time.time() - (self.last_failure_time or 0) > self.reset_seconds:
                self.state = CircuitBreakerState.HALF_OPEN
                return False
            return True
        return False


class DeliveryEngine:
    """
    Layer 4 — Authenticated delivery to receiver API.

    Features:
    - Bearer token authentication
    - Idempotency-Key header (safe to retry)
    - Exponential backoff retry
    - Circuit breaker
    - Full acknowledgement tracking
    """

    ACTOR = "DeliveryEngine"

    def __init__(self):
        self.circuit_breaker = CircuitBreaker(
            threshold=settings.receiver.circuit_breaker_threshold,
            reset_seconds=settings.receiver.circuit_breaker_reset_seconds,
        )

    async def deliver(self, message: SankofaMessage) -> SankofaMessage:
        """
        Deliver a transformed message to the receiver API.
        """
        if message.state != FileState.TRANSFORMED:
            raise ValueError(
                f"Cannot deliver message in state {message.state} — "
                f"must be TRANSFORMED first"
            )

        # VPF Provenance Gate — final check before delivery
        has_prov, missing = message.has_provenance()
        if not has_prov:
            message.compliance_flags.append("PROVENANCE_INCOMPLETE")
            message.exception_reason = f"Provenance incomplete: {missing}"
            message.transition(
                FileState.EXCEPTION,
                actor=self.ACTOR,
                action="delivery_blocked_no_provenance",
                notes=f"Missing: {missing}",
            )
            audit.log(
                AuditEventType.PROVENANCE_CHECK_FAILED,
                self.ACTOR,
                {"missing_fields": missing, "message_id": message.message_id},
                message_id=message.message_id,
                file_name=message.file_name,
                level="ERROR"
            )
            return message

        # Compliance gate check
        if settings.compliance.block_on_uncleared_gate and not settings.compliance.gate_cleared:
            message.compliance_flags.append("COMPLIANCE_GATE_NOT_CLEARED")
            message.exception_reason = "Compliance gate has not been cleared — delivery blocked"
            message.transition(
                FileState.EXCEPTION,
                actor=self.ACTOR,
                action="delivery_blocked_compliance_gate",
                notes="Compliance gate not cleared — update settings.compliance.gate_cleared",
            )
            audit.log(
                AuditEventType.COMPLIANCE_GATE_CHECK,
                self.ACTOR,
                {"result": "BLOCKED", "reason": "gate_not_cleared"},
                message_id=message.message_id,
                level="WARNING"
            )
            return message

        # Circuit breaker check
        if self.circuit_breaker.is_open():
            message.compliance_flags.append("CIRCUIT_BREAKER_OPEN")
            message.exception_reason = "Receiver API circuit breaker is open — delivery queued"
            message.transition(
                FileState.EXCEPTION,
                actor=self.ACTOR,
                action="delivery_blocked_circuit_breaker",
            )
            return message

        # Receiver API not configured
        if not settings.receiver.base_url:
            # In dev mode: simulate successful delivery
            return self._simulate_delivery(message)

        # Attempt delivery with retries
        message.transition(
            FileState.DELIVERING,
            actor=self.ACTOR,
            action="delivery_started",
        )

        result = await self._deliver_with_retry(message)
        message.delivery = result

        if result.success:
            message.transition(
                FileState.DELIVERED,
                actor=self.ACTOR,
                action="delivered_to_receiver",
                notes=f"delivery_id={result.delivery_id} http_status={result.http_status}",
            )
            audit.log_file_event(
                AuditEventType.FILE_DELIVERED,
                message,
                actor=self.ACTOR,
                details={
                    "delivery_id": result.delivery_id,
                    "http_status": result.http_status,
                    "attempts": result.attempts,
                }
            )
        else:
            message.transition(
                FileState.FAILED,
                actor=self.ACTOR,
                action="delivery_failed",
                notes=result.error_message,
            )
            audit.log_file_event(
                AuditEventType.FILE_DELIVERY_FAILED,
                message,
                actor=self.ACTOR,
                details={
                    "error": result.error_message,
                    "attempts": result.attempts,
                }
            )

        return message

    async def _deliver_with_retry(self, message: SankofaMessage) -> DeliveryResult:
        """Attempt delivery up to max_retries times with exponential backoff."""
        max_attempts = settings.receiver.max_retries + 1
        backoff = settings.receiver.retry_backoff_seconds
        last_error = ""

        for attempt in range(1, max_attempts + 1):
            try:
                result = await self._post_to_receiver(message, attempt)
                if result.success:
                    self.circuit_breaker.record_success()
                    return result
                last_error = result.error_message or ""

            except Exception as e:
                last_error = str(e)
                self.circuit_breaker.record_failure()

            if attempt < max_attempts:
                wait = backoff * (2 ** (attempt - 1))
                audit.log(
                    AuditEventType.DELIVERY_RETRY,
                    self.ACTOR,
                    {"attempt": attempt, "wait_seconds": wait, "error": last_error},
                    message_id=message.message_id,
                )
                await asyncio.sleep(wait)

        return DeliveryResult(
            success=False,
            attempts=max_attempts,
            error_message=f"All {max_attempts} delivery attempts failed. Last error: {last_error}",
        )

    async def _post_to_receiver(self, message: SankofaMessage, attempt: int) -> DeliveryResult:
        """Single HTTP POST attempt to the receiver API."""
        import aiohttp
        url = f"{settings.receiver.base_url}{settings.receiver.endpoint}"
        headers = {
            "Authorization": f"Bearer {settings.receiver.api_key}",
            "Content-Type": "application/json",
            "Idempotency-Key": message.idempotency_key,
            "X-SANKOFA-Message-ID": message.message_id,
            "X-SANKOFA-Sender": message.sender_entity_id,
        }
        payload = message.to_delivery_payload()

        audit.log(
            AuditEventType.DELIVERY_ATTEMPT,
            self.ACTOR,
            {"attempt": attempt, "url": url},
            message_id=message.message_id,
        )

        timeout = aiohttp.ClientTimeout(total=settings.receiver.timeout_seconds)
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=timeout) as resp:
                body = await resp.json() if resp.content_type == "application/json" else {}
                success = 200 <= resp.status < 300

                if not success:
                    self.circuit_breaker.record_failure()

                return DeliveryResult(
                    success=success,
                    delivery_id=body.get("delivery_id"),
                    http_status=resp.status,
                    response_body=body,
                    attempts=attempt,
                    delivered_at=datetime.now(timezone.utc) if success else None,
                    error_message=None if success else f"HTTP {resp.status}: {body}",
                )

    def _simulate_delivery(self, message: SankofaMessage) -> SankofaMessage:
        """
        Simulate delivery for dev/testing when receiver URL is not configured.
        Records the same audit trail as a real delivery.
        """
        import uuid
        result = DeliveryResult(
            success=True,
            delivery_id=f"SIM-{str(uuid.uuid4())[:8].upper()}",
            http_status=202,
            response_body={"status": "accepted", "mode": "simulation"},
            attempts=1,
            delivered_at=datetime.now(timezone.utc),
        )
        message.delivery = result
        message.transition(
            FileState.DELIVERED,
            actor=self.ACTOR,
            action="simulated_delivery",
            notes=f"SIMULATION MODE — delivery_id={result.delivery_id}. Set RECEIVER_API_URL to enable real delivery.",
        )
        audit.log_file_event(
            AuditEventType.FILE_DELIVERED,
            message,
            actor=self.ACTOR,
            details={
                "mode": "SIMULATION",
                "delivery_id": result.delivery_id,
                "note": "Set RECEIVER_API_URL in environment to enable real delivery",
            }
        )
        return message


# Singletons
transformer = TransformationEngine()
delivery_engine = DeliveryEngine()
