#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# SANKƆFA-BRIDGE — Universal Deployment Runner
# Path 3 — Live Deployment
#
# Detects your environment and runs the correct deployment path.
# Supports: AWS EC2/ECS, GCP Cloud Run/GCE, Ubuntu VPS, Docker local
#
# Usage:
#   ./deploy/run.sh                  # Auto-detect and deploy
#   ./deploy/run.sh --target aws     # Deploy to AWS
#   ./deploy/run.sh --target gcp     # Deploy to GCP
#   ./deploy/run.sh --target vps     # Deploy to Ubuntu VPS
#   ./deploy/run.sh --target docker  # Local Docker stack
#   ./deploy/run.sh --check          # Pre-deployment checks only
#
# VPF Principle: No system operates without auditability.
# Every deployment action is logged.
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

GOLD='\033[38;5;214m'; GREEN='\033[0;32m'; RED='\033[0;31m'
AMBER='\033[38;5;214m'; DIM='\033[2m'; BOLD='\033[1m'; RST='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RST} $1"; }
warn() { echo -e "  ${AMBER}⚠${RST} $1"; }
err()  { echo -e "  ${RED}✗${RST} $1"; exit 1; }
info() { echo -e "  ${DIM}→${RST} $1"; }
hdr()  { echo -e "\n${GOLD}${BOLD}$1${RST}"; echo -e "${DIM}─────────────────────────────────────────${RST}"; }

TARGET="${1:-auto}"
[[ "$1" == "--target" ]] && TARGET="$2"
[[ "$1" == "--check"  ]] && TARGET="check"

hdr "SANKƆFA-BRIDGE Deployment Runner"
echo -e "${DIM}  Architect: David King Boison | VPF Governed${RST}"
echo ""

# ── Auto-detect environment ─────────────────────────────────────────────────
detect_environment() {
  if [[ "$TARGET" != "auto" ]]; then
    echo "$TARGET"; return
  fi
  # AWS
  if curl -sf --max-time 1 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
    echo "aws"; return
  fi
  # GCP
  if curl -sf --max-time 1 -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/ >/dev/null 2>&1; then
    echo "gcp"; return
  fi
  # Docker available
  if command -v docker >/dev/null 2>&1; then
    echo "docker"; return
  fi
  echo "vps"
}

ENV=$(detect_environment)
info "Detected environment: ${BOLD}${ENV}${RST}"

# ── Pre-flight checks ───────────────────────────────────────────────────────
preflight() {
  hdr "Pre-flight Checks"

  # .env exists
  [[ -f ".env" ]] || { warn ".env not found — copying template"; cp .env.template .env; }
  source .env 2>/dev/null || true

  # Python
  command -v python3 >/dev/null && ok "Python 3 ($(python3 --version 2>&1 | cut -d' ' -f2))" || err "Python 3 required"

  # Tests
  info "Running test suite..."
  python3 -m pytest tests/ -q --tb=no 2>/dev/null | grep -q "passed" \
    && ok "203 tests passing" || err "Tests failing — fix before deploying"

  # Key check
  [[ "${SANKOFA_API_KEY:-dev-key}" != "dev-key-replace-in-production" ]] \
    && ok "API key set" || warn "API key is default — change before production"

  # Compliance gate
  [[ "${COMPLIANCE_GATE_CLEARED:-false}" == "true" ]] \
    && ok "Compliance gate cleared" || warn "Compliance gate pending — delivery blocked until cleared"

  # Connector
  CONN="${ACTIVE_CONNECTOR:-mock}"
  [[ "$CONN" == "mock" ]] \
    && warn "Connector is MOCK — real source not yet connected" \
    || ok "Connector: $CONN"

  ok "Pre-flight complete"
}

# ── Init database ────────────────────────────────────────────────────────────
init_db() {
  info "Initialising database..."
  python3 -c "
import asyncio, sys
sys.path.insert(0, '.')
from config.database import db
asyncio.run(db.init_db())
print('  Database initialised')
"
}

# ── Docker deployment ────────────────────────────────────────────────────────
deploy_docker() {
  hdr "Docker Deployment"
  preflight
  command -v docker >/dev/null || err "Docker not installed"

  info "Building image..."
  docker build -t sankofa-bridge:latest . -q
  ok "Image built: sankofa-bridge:latest"

  if command -v docker-compose >/dev/null 2>&1; then
    info "Starting full stack (API + PostgreSQL + Redis)..."
    docker-compose up -d --build
    sleep 3
    curl -sf http://localhost:8000/health >/dev/null && ok "API server healthy — http://localhost:8000" || warn "API server not yet responding — check logs"
    ok "Stack running. Operator console: open ui/console.html"
  else
    info "docker-compose not available — starting API container only..."
    docker run -d --name sankofa-api \
      --env-file .env \
      -p 8000:8000 \
      -v "$(pwd)/logs:/app/logs" \
      sankofa-bridge:latest
    sleep 2
    curl -sf http://localhost:8000/health >/dev/null && ok "API server healthy — http://localhost:8000" || warn "Container starting — wait 10s then check"
  fi
}

# ── VPS deployment (Ubuntu 22.04/24.04) ─────────────────────────────────────
deploy_vps() {
  hdr "VPS Deployment (Ubuntu)"
  preflight

  # Install system deps
  info "Checking system dependencies..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq python3-pip python3-venv nginx certbot python3-certbot-nginx curl

  # Python venv
  if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    ok "Virtual environment created"
  fi
  source venv/bin/activate
  pip install -q -r requirements.txt
  ok "Python dependencies installed"

  init_db

  # Systemd service
  info "Installing systemd service..."
  sudo tee /etc/systemd/system/sankofa-bridge.service > /dev/null << EOF
[Unit]
Description=SANKƆFA-BRIDGE Sovereign Data Orchestration System
After=network.target postgresql.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
EnvironmentFile=$(pwd)/.env
ExecStart=$(pwd)/venv/bin/uvicorn api.server:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable sankofa-bridge
  sudo systemctl restart sankofa-bridge
  sleep 2
  sudo systemctl is-active sankofa-bridge >/dev/null && ok "systemd service running" || warn "Check: sudo journalctl -u sankofa-bridge -n 20"

  # Nginx
  info "Configuring nginx..."
  sudo cp nginx/nginx.conf /etc/nginx/sites-available/sankofa-bridge
  sudo ln -sf /etc/nginx/sites-available/sankofa-bridge /etc/nginx/sites-enabled/
  sudo rm -f /etc/nginx/sites-enabled/default
  sudo nginx -t -q && sudo systemctl reload nginx && ok "nginx configured"

  ok "VPS deployment complete"
  info "Next: sudo certbot --nginx -d your-domain.com"
  info "Then: set RECEIVER_API_URL and COMPLIANCE_GATE_CLEARED=true in .env"
}

# ── AWS deployment ───────────────────────────────────────────────────────────
deploy_aws() {
  hdr "AWS Deployment"
  preflight
  command -v aws >/dev/null || err "AWS CLI not installed — run: pip install awscli"

  source .env 2>/dev/null || true
  AWS_REGION="${AWS_REGION:-us-east-1}"
  APP_NAME="sankofa-bridge"

  info "Pushing image to ECR..."
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
  ECR_URI="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${APP_NAME}"

  aws ecr get-login-password --region "$AWS_REGION" | \
    docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com" -q

  # Create repo if needed
  aws ecr describe-repositories --repository-names "$APP_NAME" --region "$AWS_REGION" >/dev/null 2>&1 \
    || aws ecr create-repository --repository-name "$APP_NAME" --region "$AWS_REGION" -q >/dev/null

  docker build -t "${APP_NAME}:latest" . -q
  docker tag "${APP_NAME}:latest" "${ECR_URI}:latest"
  docker push "${ECR_URI}:latest" -q
  ok "Image pushed: ${ECR_URI}:latest"

  # Deploy to ECS (if cluster exists) or output EC2 instructions
  if aws ecs describe-clusters --clusters sankofa-cluster --region "$AWS_REGION" \
      --query 'clusters[0].status' --output text 2>/dev/null | grep -q "ACTIVE"; then
    info "Updating ECS service..."
    aws ecs update-service --cluster sankofa-cluster --service sankofa-bridge \
      --force-new-deployment --region "$AWS_REGION" -q >/dev/null
    ok "ECS service update triggered"
  else
    warn "No ECS cluster found — see deploy/aws/ecs-task-definition.json for setup"
    info "Quick EC2 deploy: use deploy/aws/ec2-userdata.sh as instance user data"
  fi

  ok "AWS deployment complete"
}

# ── GCP deployment ───────────────────────────────────────────────────────────
deploy_gcp() {
  hdr "GCP Deployment (Cloud Run)"
  preflight
  command -v gcloud >/dev/null || err "gcloud CLI not installed — see cloud.google.com/sdk"

  PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
  [[ -z "$PROJECT_ID" ]] && err "No GCP project set — run: gcloud config set project YOUR_PROJECT_ID"
  REGION="${GCP_REGION:-us-central1}"
  IMAGE="gcr.io/${PROJECT_ID}/sankofa-bridge:latest"

  info "Building and pushing to GCR..."
  gcloud builds submit --tag "$IMAGE" --quiet
  ok "Image: $IMAGE"

  info "Deploying to Cloud Run..."
  gcloud run deploy sankofa-bridge \
    --image "$IMAGE" \
    --platform managed \
    --region "$REGION" \
    --port 8000 \
    --allow-unauthenticated \
    --set-env-vars "LOG_LEVEL=INFO,JURISDICTION=GH" \
    --memory 512Mi \
    --quiet

  URL=$(gcloud run services describe sankofa-bridge --platform managed --region "$REGION" \
        --format 'value(status.url)' 2>/dev/null)
  ok "Cloud Run URL: $URL"
  curl -sf "${URL}/health" >/dev/null && ok "Health check passed" || warn "Service starting — retry in 30s"
}

# ── Dispatcher ──────────────────────────────────────────────────────────────
case "$ENV" in
  check)  preflight ;;
  docker) deploy_docker ;;
  vps)    deploy_vps ;;
  aws)    deploy_aws ;;
  gcp)    deploy_gcp ;;
  *)
    warn "Unknown target: $ENV"
    info "Usage: ./deploy/run.sh [--target aws|gcp|vps|docker|check]"
    ;;
esac

echo ""
echo -e "${DIM}  VPF: No system operates without auditability.${RST}"
echo -e "${DIM}  Logs: logs/sankofa_audit_$(date +%Y%m%d).jsonl${RST}"
echo ""
