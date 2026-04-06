#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# SANKƆFA-BRIDGE — Production Operations Script
# Stage 5 — African Corridor Scale
#
# Usage:
#   ./scripts/ops.sh deploy        — Full production deployment
#   ./scripts/ops.sh start         — Start all services
#   ./scripts/ops.sh stop          — Graceful shutdown
#   ./scripts/ops.sh status        — Service and compliance status
#   ./scripts/ops.sh test          — Run full test suite
#   ./scripts/ops.sh rotate-key    — Rotate API key
#   ./scripts/ops.sh audit-export  — Export audit log
#   ./scripts/ops.sh backup-db     — Backup database
#   ./scripts/ops.sh logs [svc]    — Tail service logs
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

SYSTEM="SANKƆFA-BRIDGE"
VERSION="1.0.0"
STAGE="Stage 5 — African Corridor Scale"
ARCHITECT="David King Boison"
VPF="Visionary Prompt Framework (VPF)"

GOLD='\033[38;5;214m'
GREEN='\033[0;32m'
AMBER='\033[38;5;214m'
RED='\033[0;31m'
DIM='\033[2m'
RESET='\033[0m'
BOLD='\033[1m'

# ── Header ─────────────────────────────────────────────────────────────────

header() {
  echo ""
  echo -e "${GOLD}${BOLD}${SYSTEM}${RESET} ${DIM}v${VERSION}${RESET}"
  echo -e "${DIM}${STAGE}${RESET}"
  echo -e "${DIM}Architect: ${ARCHITECT} | ${VPF}${RESET}"
  echo -e "${DIM}─────────────────────────────────────────────────────────${RESET}"
}

ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
warn() { echo -e "  ${AMBER}⚠${RESET} $1"; }
fail() { echo -e "  ${RED}✗${RESET} $1"; exit 1; }
info() { echo -e "  ${DIM}→${RESET} $1"; }

# ── Pre-flight checks ───────────────────────────────────────────────────────

preflight() {
  echo -e "\n${BOLD}Pre-flight checks${RESET}"
  
  command -v python3 >/dev/null || fail "python3 not found"
  ok "Python 3 found ($(python3 --version))"

  [ -f ".env" ] || { warn ".env not found — copying from .env.template"; cp .env.template .env; warn "Edit .env before proceeding to production"; }
  
  source .env 2>/dev/null || true

  [ "${SANKOFA_API_KEY:-}" != "skb_REPLACE_WITH_SECURE_KEY" ] || warn "API key is still the template value — replace before production"
  [ "${SANKOFA_SECRET_SEED:-}" != "REPLACE_WITH_LONG_RANDOM_STRING_MIN_32_CHARS" ] || warn "Secret seed is still the template value — replace before production"
  [ "${COMPLIANCE_GATE_CLEARED:-false}" = "true" ] && ok "Compliance gate: CLEARED" || warn "Compliance gate: NOT CLEARED — live delivery blocked"

  python3 -m pytest tests/ -q --tb=no 2>&1 | tail -1 | grep -q "passed" && ok "All tests passing" || fail "Tests failing — do not deploy"
}

# ── Deploy ──────────────────────────────────────────────────────────────────

deploy() {
  header
  echo -e "\n${BOLD}Deployment${RESET}"
  preflight

  info "Initialising database..."
  python3 -c "import asyncio; from config.database import db; asyncio.run(db.init_db())"
  ok "Database initialised"

  if command -v docker-compose >/dev/null 2>&1 || command -v docker >/dev/null 2>&1; then
    info "Starting Docker stack..."
    docker-compose up -d --build
    ok "Docker stack started"
  else
    info "Docker not available — starting API server directly..."
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --workers 2 &
    ok "API server started (PID $!)"
  fi

  echo ""
  status
}

# ── Start / Stop ────────────────────────────────────────────────────────────

start() {
  header
  echo -e "\n${BOLD}Starting services${RESET}"
  preflight
  python3 -c "import asyncio; from config.database import db; asyncio.run(db.init_db())"
  ok "Database ready"
  uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload &
  ok "API server started — http://localhost:8000"
  info "API docs: http://localhost:8000/docs"
  info "Operator console: open ui/console.html"
}

stop() {
  header
  echo -e "\n${BOLD}Stopping services${RESET}"
  pkill -f "uvicorn api.server" 2>/dev/null && ok "API server stopped" || info "API server not running"
  pkill -f "python main.py" 2>/dev/null && ok "Worker stopped" || info "Worker not running"
}

# ── Status ──────────────────────────────────────────────────────────────────

status() {
  header
  echo -e "\n${BOLD}System status${RESET}"

  # API health check
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    ok "API server: ONLINE (http://localhost:8000)"
  else
    warn "API server: OFFLINE"
  fi

  # Compliance gate
  source .env 2>/dev/null || true
  if [ "${COMPLIANCE_GATE_CLEARED:-false}" = "true" ]; then
    ok "Compliance gate: CLEARED"
  else
    warn "Compliance gate: PENDING"
  fi

  # Connector type
  info "Active connector: ${ACTIVE_CONNECTOR:-mock}"

  # Receiver
  if [ -n "${RECEIVER_API_URL:-}" ]; then
    ok "Receiver API: configured"
  else
    warn "Receiver API: not configured (simulation mode)"
  fi

  # Test suite
  if python3 -m pytest tests/ -q --tb=no 2>/dev/null | tail -1 | grep -q "passed"; then
    ok "Test suite: all passing"
  else
    fail "Test suite: failures detected"
  fi

  echo ""
  echo -e "${DIM}VPF Principle: No data moves without provenance.${RESET}"
  echo -e "${DIM}No value moves without custodianship.${RESET}"
  echo -e "${DIM}No system operates without auditability.${RESET}"
  echo ""
}

# ── Test ────────────────────────────────────────────────────────────────────

run_tests() {
  header
  echo -e "\n${BOLD}Running test suite${RESET}"
  python3 -m pytest tests/ -v --tb=short
}

# ── Key rotation ────────────────────────────────────────────────────────────

rotate_key() {
  header
  echo -e "\n${BOLD}API Key Rotation${RESET}"
  NEW_KEY=$(python3 -c "import secrets; print(f'skb_{secrets.token_urlsafe(32)}')")
  echo ""
  echo -e "  New API key: ${GOLD}${NEW_KEY}${RESET}"
  echo ""
  warn "Update SANKOFA_API_KEY in .env and restart the API server."
  warn "Update all clients using the old key before restart."
  echo ""
  read -p "  Update .env now? [y/N] " CONFIRM
  if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
    sed -i "s|^SANKOFA_API_KEY=.*|SANKOFA_API_KEY=${NEW_KEY}|" .env
    ok ".env updated"
    warn "Restart the API server to activate the new key"
  else
    info "Key not saved — copy it manually"
  fi
}

# ── Audit export ────────────────────────────────────────────────────────────

audit_export() {
  header
  echo -e "\n${BOLD}Audit Log Export${RESET}"
  EXPORT_FILE="audit_export_$(date +%Y%m%d_%H%M%S).jsonl"
  if [ -f "logs/sankofa_audit_$(date +%Y%m%d).jsonl" ]; then
    cp "logs/sankofa_audit_$(date +%Y%m%d).jsonl" "$EXPORT_FILE"
    ok "Audit log exported: $EXPORT_FILE"
    info "$(wc -l < "$EXPORT_FILE") events"
  else
    warn "No audit log found for today"
  fi
}

# ── Database backup ─────────────────────────────────────────────────────────

backup_db() {
  header
  echo -e "\n${BOLD}Database Backup${RESET}"
  BACKUP_FILE="backups/sankofa_db_$(date +%Y%m%d_%H%M%S).sql"
  mkdir -p backups

  source .env 2>/dev/null || true
  if echo "${DATABASE_URL:-}" | grep -q "postgresql"; then
    pg_dump "${DATABASE_URL}" > "$BACKUP_FILE"
    ok "PostgreSQL backup: $BACKUP_FILE"
  elif [ -f "sankofa_bridge.db" ]; then
    cp sankofa_bridge.db "$BACKUP_FILE.db"
    ok "SQLite backup: $BACKUP_FILE.db"
  else
    warn "No database file found"
  fi
}

# ── Logs ────────────────────────────────────────────────────────────────────

show_logs() {
  SERVICE="${2:-api}"
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose logs -f --tail=50 "$SERVICE"
  else
    tail -f "logs/sankofa_audit_$(date +%Y%m%d).jsonl" | python3 -c "
import sys, json
for line in sys.stdin:
  try:
    e = json.loads(line)
    print(f\"{e['timestamp'][11:19]} | {e['event_type']:<35} | {e['actor']}\")
  except: pass
"
  fi
}

# ── Production readiness check ──────────────────────────────────────────────

readiness_check() {
  header
  echo -e "\n${BOLD}Production Readiness Check${RESET}"
  echo ""

  source .env 2>/dev/null || true
  READY=true

  # Security
  echo -e "  ${BOLD}Security${RESET}"
  [ "${SANKOFA_API_KEY:-}" != "skb_REPLACE_WITH_SECURE_KEY" ] && ok "API key changed" || { warn "API key is default — MUST change"; READY=false; }
  [ "${SANKOFA_SECRET_SEED:-}" != "REPLACE_WITH_LONG_RANDOM_STRING_MIN_32_CHARS" ] && ok "Secret seed changed" || { warn "Secret seed is default — MUST change"; READY=false; }
  [ "${DEBUG:-true}" = "false" ] && ok "Debug mode disabled" || warn "Debug mode is ON — disable for production"

  # Compliance
  echo ""
  echo -e "  ${BOLD}Compliance${RESET}"
  [ "${COMPLIANCE_GATE_CLEARED:-false}" = "true" ] && ok "Compliance gate cleared" || { warn "Compliance gate NOT cleared"; READY=false; }

  # Connector
  echo ""
  echo -e "  ${BOLD}Connector${RESET}"
  CONN="${ACTIVE_CONNECTOR:-mock}"
  if [ "$CONN" = "mock" ]; then
    warn "Connector is MOCK — replace with real source before production"
    READY=false
  else
    ok "Connector: $CONN"
  fi

  # Receiver
  echo ""
  echo -e "  ${BOLD}Delivery${RESET}"
  [ -n "${RECEIVER_API_URL:-}" ] && ok "Receiver API URL configured" || { warn "Receiver API URL not set"; READY=false; }
  [ -n "${RECEIVER_API_KEY:-}" ] && ok "Receiver API key configured" || { warn "Receiver API key not set"; READY=false; }

  # Database
  echo ""
  echo -e "  ${BOLD}Database${RESET}"
  echo "${DATABASE_URL:-sqlite}" | grep -q "postgresql" && ok "PostgreSQL configured" || warn "Using SQLite — use PostgreSQL for production"

  # Tests
  echo ""
  echo -e "  ${BOLD}Test Suite${RESET}"
  if python3 -m pytest tests/ -q --tb=no 2>/dev/null | tail -1 | grep -q "passed"; then
    ok "All tests passing"
  else
    fail "Tests failing — do not deploy"
  fi

  echo ""
  echo -e "${DIM}─────────────────────────────────────────────────────────${RESET}"
  if $READY; then
    echo -e "  ${GREEN}${BOLD}PRODUCTION READY${RESET}"
  else
    echo -e "  ${AMBER}${BOLD}NOT READY — resolve warnings above before deploying${RESET}"
  fi
  echo ""
}

# ── Dispatcher ─────────────────────────────────────────────────────────────

COMMAND="${1:-help}"

case "$COMMAND" in
  deploy)         deploy ;;
  start)          start ;;
  stop)           stop ;;
  status)         status ;;
  test)           run_tests ;;
  rotate-key)     rotate_key ;;
  audit-export)   audit_export ;;
  backup-db)      backup_db ;;
  logs)           show_logs "$@" ;;
  ready)          readiness_check ;;
  *)
    header
    echo ""
    echo "  Usage: ./scripts/ops.sh <command>"
    echo ""
    echo "  Commands:"
    echo "    deploy        Full deployment (preflight + DB init + start)"
    echo "    start         Start API server"
    echo "    stop          Stop all services"
    echo "    status        Service and compliance status"
    echo "    test          Run full test suite"
    echo "    rotate-key    Rotate API authentication key"
    echo "    audit-export  Export today's audit log"
    echo "    backup-db     Backup the database"
    echo "    logs [svc]    Tail service logs"
    echo "    ready         Production readiness check"
    echo ""
    ;;
esac
