"""
SANKƆFA-BRIDGE — Connector Layer (Layer 1)
Modular source adapters: S3 / SFTP / REST API / Azure Blob / Mock

The connector's ONLY job:
  1. Authenticate to the source system
  2. Detect new files
  3. Download them securely into the quarantine zone
  4. Hand a SankofaMessage to Layer 2 (Validation)

The connector does NOT validate, transform, or deliver.
It does NOT interpret file contents.
It records every action in the audit log.

When counterparty confirms their system type,
change ACTIVE_CONNECTOR in config/settings.py.
The rest of the system is unaffected.
"""

import os
import io
import json
import uuid
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Callable

from config.models import SankofaMessage, FileState
from config.settings import settings, ConnectorType
from audit.logger import audit, AuditEventType


# ─────────────────────────────────────────────
# BASE CONNECTOR
# ─────────────────────────────────────────────

class BaseConnector(ABC):
    """
    Abstract base for all connectors.
    All connectors must implement: connect(), poll(), download(), disconnect()
    """

    def __init__(self):
        self.connected = False
        self.connector_name = self.__class__.__name__

    @abstractmethod
    async def connect(self) -> bool:
        """Authenticate to the source system."""
        pass

    @abstractmethod
    async def poll(self) -> List[dict]:
        """
        Check for new files.
        Returns list of file descriptors: [{file_id, file_name, size, ...}]
        """
        pass

    @abstractmethod
    async def download(self, file_descriptor: dict) -> bytes:
        """
        Download a specific file.
        Returns raw bytes — no interpretation.
        """
        pass

    @abstractmethod
    async def disconnect(self):
        pass

    def _build_message(
        self,
        file_id: str,
        file_name: str,
        raw_bytes: bytes,
        sender_entity_id: str = "",
        metadata: dict = None
    ) -> SankofaMessage:
        """
        Build a SankofaMessage from downloaded file bytes.
        This is where provenance is first established.
        """
        now = datetime.now(timezone.utc)
        msg = SankofaMessage(
            message_id=str(uuid.uuid4()),
            file_id=file_id or str(uuid.uuid4()),
            file_name=file_name,
            file_format=self._detect_format(file_name, raw_bytes),
            source_system=self.connector_name,
            sender_entity_id=sender_entity_id,
            received_at_utc=now,
            jurisdiction=settings.compliance.jurisdiction,
            classification="restricted",
            raw_payload=raw_bytes,
            file_size_bytes=len(raw_bytes),
            metadata=metadata or {},
        )
        msg.compute_hash()
        msg.transition(
            new_state=FileState.QUARANTINED,
            actor=self.connector_name,
            action="downloaded_to_quarantine",
            notes=f"File received from {self.connector_name}, hash computed, quarantine entry recorded",
        )
        return msg

    def _detect_format(self, file_name: str, raw_bytes: bytes) -> str:
        ext = Path(file_name).suffix.lower()
        if ext in [".json"]:
            return "json"
        elif ext in [".xml"]:
            return "xml"
        # Sniff the content
        head = raw_bytes[:20].strip()
        if head.startswith(b"{") or head.startswith(b"["):
            return "json"
        if head.startswith(b"<"):
            return "xml"
        return "binary"


# ─────────────────────────────────────────────
# S3 CONNECTOR
# ─────────────────────────────────────────────

class S3Connector(BaseConnector):
    """
    AWS S3 connector.
    Polls a bucket prefix for new objects.
    Uses boto3 with explicit credentials — no ambient IAM assumed.
    """

    def __init__(self):
        super().__init__()
        self.config = settings.s3
        self._client = None
        self._seen_keys: set = set()

    async def connect(self) -> bool:
        try:
            import boto3
            self._client = boto3.client(
                "s3",
                region_name=self.config.region,
                aws_access_key_id=self.config.access_key_id,
                aws_secret_access_key=self.config.secret_access_key,
            )
            # Verify access
            self._client.head_bucket(Bucket=self.config.bucket_name)
            self.connected = True
            audit.log(AuditEventType.CONNECTOR_CONNECTED, "S3Connector", {
                "bucket": self.config.bucket_name,
                "region": self.config.region,
                "prefix": self.config.prefix,
            })
            return True
        except Exception as e:
            audit.log(AuditEventType.CONNECTOR_ERROR, "S3Connector", {
                "error": str(e), "bucket": self.config.bucket_name
            }, level="ERROR")
            return False

    async def poll(self) -> List[dict]:
        if not self.connected or not self._client:
            return []
        try:
            response = self._client.list_objects_v2(
                Bucket=self.config.bucket_name,
                Prefix=self.config.prefix,
            )
            files = []
            for obj in response.get("Contents", []):
                key = obj["Key"]
                if key in self._seen_keys:
                    continue
                if key.endswith("/"):  # Skip directory markers
                    continue
                files.append({
                    "file_id": key,
                    "file_name": Path(key).name,
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                    "s3_key": key,
                })
            audit.log(AuditEventType.CONNECTOR_POLL, "S3Connector", {
                "new_files_found": len(files),
                "bucket": self.config.bucket_name
            })
            return files
        except Exception as e:
            audit.log(AuditEventType.CONNECTOR_ERROR, "S3Connector",
                {"error": str(e)}, level="ERROR")
            return []

    async def download(self, file_descriptor: dict) -> bytes:
        key = file_descriptor["s3_key"]
        response = self._client.get_object(
            Bucket=self.config.bucket_name, Key=key
        )
        raw_bytes = response["Body"].read()
        self._seen_keys.add(key)
        return raw_bytes

    async def disconnect(self):
        self._client = None
        self.connected = False


# ─────────────────────────────────────────────
# SFTP CONNECTOR
# ─────────────────────────────────────────────

class SFTPConnector(BaseConnector):
    """
    SSH/SFTP connector.
    Uses key-based authentication only — no password auth permitted.
    """

    def __init__(self):
        super().__init__()
        self.config = settings.sftp
        self._ssh = None
        self._sftp = None
        self._seen_files: set = set()

    async def connect(self) -> bool:
        try:
            import paramiko
            self._ssh = paramiko.SSHClient()
            self._ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            self._ssh.connect(
                hostname=self.config.host,
                port=self.config.port,
                username=self.config.username,
                key_filename=self.config.private_key_path,
                timeout=30,
            )
            self._sftp = self._ssh.open_sftp()
            self.connected = True
            audit.log(AuditEventType.CONNECTOR_CONNECTED, "SFTPConnector", {
                "host": self.config.host,
                "port": self.config.port,
                "remote_path": self.config.remote_path,
            })
            return True
        except Exception as e:
            audit.log(AuditEventType.CONNECTOR_ERROR, "SFTPConnector", {
                "error": str(e), "host": self.config.host
            }, level="ERROR")
            return False

    async def poll(self) -> List[dict]:
        if not self.connected or not self._sftp:
            return []
        try:
            entries = self._sftp.listdir_attr(self.config.remote_path)
            files = []
            for entry in entries:
                fname = entry.filename
                if fname in self._seen_files:
                    continue
                fpath = f"{self.config.remote_path}/{fname}"
                files.append({
                    "file_id": fpath,
                    "file_name": fname,
                    "size": entry.st_size,
                    "remote_path": fpath,
                })
            return files
        except Exception as e:
            audit.log(AuditEventType.CONNECTOR_ERROR, "SFTPConnector",
                {"error": str(e)}, level="ERROR")
            return []

    async def download(self, file_descriptor: dict) -> bytes:
        buf = io.BytesIO()
        self._sftp.getfo(file_descriptor["remote_path"], buf)
        self._seen_files.add(file_descriptor["file_name"])
        return buf.getvalue()

    async def disconnect(self):
        if self._sftp:
            self._sftp.close()
        if self._ssh:
            self._ssh.close()
        self.connected = False


# ─────────────────────────────────────────────
# REST API CONNECTOR
# ─────────────────────────────────────────────

class RestAPIConnector(BaseConnector):
    """
    REST API source connector.
    Polls an endpoint for pending files and downloads each one.
    """

    def __init__(self):
        super().__init__()
        self.config = settings.rest_api
        self._session = None
        self._seen_ids: set = set()

    async def connect(self) -> bool:
        try:
            import aiohttp
            self._session = aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.config.api_key}",
                         "Accept": "application/json"}
            )
            # Health check
            async with self._session.get(
                f"{self.config.base_url}/health", timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                r.raise_for_status()
            self.connected = True
            audit.log(AuditEventType.CONNECTOR_CONNECTED, "RestAPIConnector", {
                "base_url": self.config.base_url
            })
            return True
        except Exception as e:
            audit.log(AuditEventType.CONNECTOR_ERROR, "RestAPIConnector",
                {"error": str(e)}, level="ERROR")
            return False

    async def poll(self) -> List[dict]:
        if not self.connected or not self._session:
            return []
        try:
            import aiohttp
            url = f"{self.config.base_url}{self.config.endpoint_files}"
            async with self._session.get(url) as r:
                r.raise_for_status()
                data = await r.json()
            files = [
                f for f in data.get("files", [])
                if f["file_id"] not in self._seen_ids
            ]
            return files
        except Exception as e:
            audit.log(AuditEventType.CONNECTOR_ERROR, "RestAPIConnector",
                {"error": str(e)}, level="ERROR")
            return []

    async def download(self, file_descriptor: dict) -> bytes:
        import aiohttp
        file_id = file_descriptor["file_id"]
        url = (f"{self.config.base_url}"
               f"{self.config.endpoint_download.format(file_id=file_id)}")
        async with self._session.get(url) as r:
            r.raise_for_status()
            raw = await r.read()
        self._seen_ids.add(file_id)
        return raw

    async def disconnect(self):
        if self._session:
            await self._session.close()
        self.connected = False


# ─────────────────────────────────────────────
# MOCK CONNECTOR — for testing and development
# ─────────────────────────────────────────────

class MockConnector(BaseConnector):
    """
    Mock connector for testing when source system is not yet defined.
    Generates realistic synthetic files that exercise the full pipeline.
    """

    def __init__(self):
        super().__init__()
        self._file_counter = 0
        self._injected: List[dict] = []

    async def connect(self) -> bool:
        self.connected = True
        audit.log(AuditEventType.CONNECTOR_CONNECTED, "MockConnector", {
            "mode": "MOCK — source system not yet configured",
            "note": "Replace with real connector once counterparty confirms system type"
        })
        return True

    async def poll(self) -> List[dict]:
        return [f for f in self._injected if not f.get("_downloaded")]

    async def download(self, file_descriptor: dict) -> bytes:
        file_descriptor["_downloaded"] = True
        return file_descriptor["_raw_bytes"]

    async def disconnect(self):
        self.connected = False

    def inject_test_file(
        self,
        sender_id: str = "SENDER_TEST_001",
        receiver_id: str = "RECEIVER_TEST_001",
        file_type: str = "json"
    ) -> dict:
        """Inject a synthetic test file into the mock queue."""
        self._file_counter += 1
        fid = f"MOCK-FILE-{self._file_counter:04d}"

        if file_type == "json":
            payload = {
                "transaction_reference": f"TXN-{self._file_counter:06d}",
                "sender_entity_id": sender_id,
                "receiver_entity_id": receiver_id,
                "amount": round(1000 * self._file_counter, 2),
                "currency": "GHS",
                "instruction_type": "transfer_instruction",
                "jurisdiction": "GH",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "source": "mock_generator",
                    "test_run": True,
                }
            }
            raw = json.dumps(payload).encode("utf-8")
            fname = f"instruction_{fid}.json"
        else:
            raw = f"""<?xml version="1.0" encoding="UTF-8"?>
<TransferInstruction>
  <TransactionReference>TXN-{self._file_counter:06d}</TransactionReference>
  <SenderEntityId>{sender_id}</SenderEntityId>
  <ReceiverEntityId>{receiver_id}</ReceiverEntityId>
  <Currency>GHS</Currency>
  <Jurisdiction>GH</Jurisdiction>
  <Timestamp>{datetime.now(timezone.utc).isoformat()}</Timestamp>
</TransferInstruction>""".encode("utf-8")
            fname = f"instruction_{fid}.xml"

        descriptor = {
            "file_id": fid,
            "file_name": fname,
            "size": len(raw),
            "sender_entity_id": sender_id,
            "receiver_entity_id": receiver_id,
            "_raw_bytes": raw,
        }
        self._injected.append(descriptor)
        return descriptor


# ─────────────────────────────────────────────
# CONNECTOR FACTORY
# ─────────────────────────────────────────────

def get_connector() -> BaseConnector:
    """
    Return the active connector based on configuration.
    Change settings.connector_type to switch adapters.
    """
    connectors = {
        ConnectorType.S3: S3Connector,
        ConnectorType.SFTP: SFTPConnector,
        ConnectorType.REST_API: RestAPIConnector,
        ConnectorType.MOCK: MockConnector,
    }
    cls = connectors.get(settings.connector_type)
    if not cls:
        raise ValueError(f"Unknown connector type: {settings.connector_type}")
    return cls()


# ─────────────────────────────────────────────
# INGESTION LOOP
# ─────────────────────────────────────────────

async def run_ingestion_loop(
    on_file_received: Callable[[SankofaMessage], None],
    stop_event: asyncio.Event = None
):
    """
    Main connector polling loop.
    Calls on_file_received(message) for each new file detected.
    Runs until stop_event is set or KeyboardInterrupt.
    """
    connector = get_connector()
    connected = await connector.connect()

    if not connected:
        audit.log(AuditEventType.CONNECTOR_ERROR, "IngestionLoop", {
            "error": "Failed to connect — ingestion loop not started"
        }, level="ERROR")
        return

    poll_interval = getattr(
        getattr(settings, settings.connector_type.value, settings.mock),
        "poll_interval_seconds", 30
    )

    audit.log(AuditEventType.SYSTEM_START, "IngestionLoop", {
        "connector": settings.connector_type.value,
        "poll_interval_seconds": poll_interval,
    })

    try:
        while True:
            if stop_event and stop_event.is_set():
                break

            pending = await connector.poll()

            for descriptor in pending:
                try:
                    raw_bytes = await connector.download(descriptor)
                    message = connector._build_message(
                        file_id=descriptor.get("file_id", ""),
                        file_name=descriptor.get("file_name", "unknown"),
                        raw_bytes=raw_bytes,
                        sender_entity_id=descriptor.get("sender_entity_id", ""),
                        metadata={
                            "source_descriptor": {
                                k: v for k, v in descriptor.items()
                                if not k.startswith("_")
                            }
                        }
                    )
                    audit.log_file_event(
                        AuditEventType.FILE_QUARANTINED,
                        message,
                        actor="IngestionLoop",
                        details={"file_size_bytes": len(raw_bytes)}
                    )
                    await on_file_received(message)

                except Exception as e:
                    audit.log(AuditEventType.CONNECTOR_ERROR, "IngestionLoop", {
                        "error": str(e),
                        "file": descriptor.get("file_name", "unknown")
                    }, level="ERROR")

            await asyncio.sleep(poll_interval)

    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await connector.disconnect()
        audit.log(AuditEventType.SYSTEM_STOP, "IngestionLoop", {
            "connector": settings.connector_type.value
        })
