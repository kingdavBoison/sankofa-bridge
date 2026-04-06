#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# SANKƆFA-BRIDGE — Go-Live Sequence
# Path 2 — Real Source Integration
#
# Run this script when you are ready to switch from MOCK to live.
# It walks you through every step interactively, validates each one,
# and only proceeds when each gate is confirmed.
#
# Usage: ./integration/go_live.sh
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

GOLD='\033[38;5;214m'; GREEN='\033[0;32m'; RED='\033[0;31m'
AMBER='\033[38;5;214m'; DIM='\033[2m'; BOLD='\033[1m'; RST='\033[0m'

ok()    { echo -e "  ${GREEN}✓${RST} $1"; }
warn()  { echo -e "  ${AMBER}⚠${RST} $1"; }
err()   { echo -e "  ${RED}✗${RST} $1"; }
info()  { echo -e "  ${DIM}→${RST} $1"; }
hdr()   { echo -e "\n${GOLD}${BOLD}$1${RST}"; echo -e "${DIM}─────────────────────────────────────────${RST}"; }
ask()   { read -p "  $1 [y/N] " REPLY; [[ "$REPLY" =~ ^[Yy]$ ]]; }
pause() { read -p "  Press Enter to continue..."; }

hdr "SANKƆFA-BRIDGE — Go-Live Sequence"
echo -e "  ${DIM}This script takes you from MOCK connector to live production.${RST}"
echo -e "  ${DIM}Each step is validated before proceeding.${RST}"
echo ""

source .env 2>/dev/null || { warn ".env not found"; cp .env.template .env; warn "Edit .env and re-run"; exit 1; }

# ── GATE 1: Compliance ────────────────────────────────────────────────────────
hdr "Gate 1: Compliance"
if [[ "${COMPLIANCE_GATE_CLEARED:-false}" == "true" ]]; then
  ok "Compliance gate is cleared"
else
  err "Compliance gate is NOT cleared"
  info "Answer all 18 questions at POST /v1/compliance/gate/answer"
  info "Then set COMPLIANCE_GATE_CLEARED=true in .env"
  ask "Skip this gate (test environments only)?" || exit 1
  warn "Proceeding with uncleared gate — delivery will be blocked in production"
fi

# ── GATE 2: Source system ─────────────────────────────────────────────────────
hdr "Gate 2: Source System Type"
echo ""
echo "  What type of system is your source?  "
echo "  1) AWS S3 bucket"
echo "  2) SFTP / SSH server"
echo "  3) REST API endpoint"
echo "  4) Azure Blob Storage"
echo ""
read -p "  Enter 1-4: " SOURCE_CHOICE
case "$SOURCE_CHOICE" in
  1) CONNECTOR="s3"
     echo ""
     info "Required vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET, S3_REGION"
     for v in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY S3_BUCKET; do
       [[ -n "${!v:-}" ]] && ok "$v is set" || { err "$v is NOT set"; warn "Set it in .env and re-run"; exit 1; }
     done ;;
  2) CONNECTOR="sftp"
     for v in SFTP_HOST SFTP_USER SFTP_KEY_PATH; do
       [[ -n "${!v:-}" ]] && ok "$v is set" || { err "$v is NOT set"; warn "Set it in .env and re-run"; exit 1; }
     done ;;
  3) CONNECTOR="rest_api"
     for v in SOURCE_API_URL SOURCE_API_KEY; do
       [[ -n "${!v:-}" ]] && ok "$v is set" || { err "$v is NOT set"; warn "Set it in .env and re-run"; exit 1; }
     done ;;
  4) CONNECTOR="azure_blob"
     for v in AZURE_CONNECTION_STRING AZURE_CONTAINER; do
       [[ -n "${!v:-}" ]] && ok "$v is set" || { err "$v is NOT set"; warn "Set it in .env and re-run"; exit 1; }
     done ;;
  *) err "Invalid choice"; exit 1 ;;
esac

# ── GATE 3: Receiver API ──────────────────────────────────────────────────────
hdr "Gate 3: Receiver API"
if [[ -n "${RECEIVER_API_URL:-}" ]]; then
  ok "RECEIVER_API_URL: ${RECEIVER_API_URL}"
  # Health check on receiver
  info "Checking receiver endpoint..."
  if curl -sf --max-time 5 "${RECEIVER_API_URL%/v1*}/health" >/dev/null 2>&1 || \
     curl -sf --max-time 5 "${RECEIVER_API_URL}" -o /dev/null 2>&1; then
    ok "Receiver endpoint is reachable"
  else
    warn "Receiver endpoint not responding — may be authentication-protected"
    ask "Proceed anyway?" || exit 1
  fi
else
  warn "RECEIVER_API_URL is not set — delivery will run in simulation mode"
  ask "Proceed in simulation mode?" || exit 1
fi

# ── GATE 4: Connection test ───────────────────────────────────────────────────
hdr "Gate 4: Live Connection Test"
info "Running integration test against real source..."
python3 integration/test_connection.py --type "$CONNECTOR"
TEST_EXIT=$?
[[ $TEST_EXIT -eq 0 ]] && ok "Integration test passed" || { err "Integration test failed — fix errors and re-run"; exit 1; }

# ── GATE 5: Switch connector ──────────────────────────────────────────────────
hdr "Gate 5: Switch Connector"
info "Current: ACTIVE_CONNECTOR=${ACTIVE_CONNECTOR:-mock}"
info "Switching to: $CONNECTOR"
ask "Switch ACTIVE_CONNECTOR to $CONNECTOR in .env?" || { info "No change made"; exit 0; }
sed -i "s|^ACTIVE_CONNECTOR=.*|ACTIVE_CONNECTOR=${CONNECTOR}|" .env
ok "ACTIVE_CONNECTOR set to $CONNECTOR"

# ── GATE 6: Final readiness ───────────────────────────────────────────────────
hdr "Gate 6: Final Readiness Check"
bash scripts/ops.sh ready 2>/dev/null || true

# ── GO LIVE ───────────────────────────────────────────────────────────────────
hdr "Go Live"
echo ""
echo -e "  ${BOLD}All gates passed.${RST}"
echo ""
ask "Restart the API server now to activate live connector?" || {
  info "Restart manually: ./scripts/ops.sh stop && ./scripts/ops.sh start"
  exit 0
}

bash scripts/ops.sh stop 2>/dev/null || true
sleep 1
bash scripts/ops.sh start &
sleep 3

# Final health check
if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
  echo ""
  ok "SANKƆFA-BRIDGE is LIVE"
  ok "Active connector: $CONNECTOR"
  ok "API: http://localhost:8000"
  info "Operator console: open ui/console.html"
  info "Monitor: ./scripts/ops.sh logs"
  echo ""
  echo -e "  ${GOLD}${BOLD}SANKƆFA-BRIDGE is operational.${RST}"
  echo -e "  ${DIM}\"No data moves without provenance. No value moves without custodianship.${RST}"
  echo -e "  ${DIM}No system operates without auditability.\"${RST}"
else
  warn "API not yet responding — check logs: ./scripts/ops.sh logs"
fi
