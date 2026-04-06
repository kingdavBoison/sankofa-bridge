-- SANKƆFA-BRIDGE — PostgreSQL Production Schema
-- Stage 5 — African Corridor Scale
--
-- This script runs once when the PostgreSQL container is first created.
-- SQLAlchemy will also create tables via init_db() — this adds
-- production-grade indexes and constraints on top.
--
-- Run manually: psql -U sankofa -d sankofa_bridge -f init.sql

-- ── Extensions ──────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- Trigram indexes for text search

-- ── Performance indexes (beyond SQLAlchemy defaults) ────────────────────────

-- Messages: frequent query patterns
CREATE INDEX IF NOT EXISTS idx_messages_state_created
  ON messages (state, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_sender_created
  ON messages (sender_entity_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_jurisdiction
  ON messages (jurisdiction, state);

-- Compliance flags text search (for bulk flag queries)
CREATE INDEX IF NOT EXISTS idx_messages_flags_gin
  ON messages USING gin (compliance_flags gin_trgm_ops);

-- Exceptions: open queue queries
CREATE INDEX IF NOT EXISTS idx_exceptions_status_created
  ON exceptions (status, created_at DESC);

-- Sender registry: jurisdiction lookups
CREATE INDEX IF NOT EXISTS idx_sender_jurisdiction
  ON sender_registry (jurisdiction, active);

-- ── Row-level security for multi-tenant isolation ───────────────────────────
-- Enable RLS on messages table (uncomment when multi-tenant is required)
-- ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation ON messages
--   USING (jurisdiction = current_setting('app.current_jurisdiction'));

-- ── Audit function — prevent row deletion ────────────────────────────────────
-- The audit ledger is append-only. This rule enforces it at DB level.
CREATE OR REPLACE RULE no_delete_messages AS
  ON DELETE TO messages DO INSTEAD NOTHING;

-- ── Notification function for real-time pipeline events ─────────────────────
CREATE OR REPLACE FUNCTION notify_file_state_change()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify(
    'file_state_change',
    json_build_object(
      'message_id', NEW.message_id,
      'old_state', OLD.state,
      'new_state', NEW.state,
      'file_name', NEW.file_name,
      'updated_at', NEW.updated_at
    )::text
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER file_state_change_trigger
  AFTER UPDATE OF state ON messages
  FOR EACH ROW
  WHEN (OLD.state IS DISTINCT FROM NEW.state)
  EXECUTE FUNCTION notify_file_state_change();

-- ── Initial data: compliance gate questions ──────────────────────────────────
INSERT INTO compliance_gate (id, question_id, category, question_text)
VALUES
  (gen_random_uuid(), 1,  'legal',      'Who are the legally recognized parties — sender, receiver, and platform?'),
  (gen_random_uuid(), 2,  'legal',      'What licenses or regulatory approvals cover this in each jurisdiction?'),
  (gen_random_uuid(), 3,  'legal',      'What is the legal classification — remittance, digital asset, or settlement clearing?'),
  (gen_random_uuid(), 4,  'legal',      'Who is legally responsible for the movement of funds at each stage?'),
  (gen_random_uuid(), 5,  'legal',      'Has AML/KYC been completed on sender and receiver? By whom?'),
  (gen_random_uuid(), 6,  'legal',      'Who is responsible for sanctions screening? Against which lists?'),
  (gen_random_uuid(), 7,  'legal',      'Is tokenization legally permitted in each jurisdiction?'),
  (gen_random_uuid(), 8,  'technical',  'What is the exact type of the source system — S3, SFTP, or REST API?'),
  (gen_random_uuid(), 9,  'technical',  'Who owns and controls the source system?'),
  (gen_random_uuid(), 10, 'technical',  'What is the exact file format — JSON, XML, or binary?'),
  (gen_random_uuid(), 11, 'technical',  'What is the exact receiver API contract?'),
  (gen_random_uuid(), 12, 'technical',  'Is there a sandbox/test environment available?'),
  (gen_random_uuid(), 13, 'technical',  'What integrity verification method is used?'),
  (gen_random_uuid(), 14, 'governance', 'Is there a formal contract governing the system operator?'),
  (gen_random_uuid(), 15, 'governance', 'What is the compensation model — fixed fee, retainer, or milestone?'),
  (gen_random_uuid(), 16, 'governance', 'Who has final settlement authority?'),
  (gen_random_uuid(), 17, 'governance', 'What incident response procedure exists?'),
  (gen_random_uuid(), 18, 'governance', 'What data retention and deletion policy applies?')
ON CONFLICT DO NOTHING;
