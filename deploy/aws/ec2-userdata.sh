#!/bin/bash
# SANKƆFA-BRIDGE — AWS EC2 User Data Script
# Bootstraps a fresh Ubuntu 24.04 instance to run SANKƆFA-BRIDGE
# Run as EC2 user data OR manually on a fresh server

set -euo pipefail
exec > >(tee /var/log/sankofa-bootstrap.log) 2>&1

echo "=== SANKƆFA-BRIDGE Bootstrap starting ==="

# System update
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
  python3.12 python3.12-venv python3-pip \
  nginx certbot python3-certbot-nginx \
  postgresql-client \
  docker.io docker-compose-v2 \
  git curl unzip awscli jq

# Docker group
usermod -aG docker ubuntu || true
systemctl enable docker
systemctl start docker

# Application directory
mkdir -p /opt/sankofa-bridge
cd /opt/sankofa-bridge

# Pull code from S3 (replace with your actual bucket/key)
# aws s3 cp s3://YOUR_BUCKET/sankofa-bridge.zip . && unzip -q sankofa-bridge.zip

# OR clone from git (replace with your repo)
# git clone https://YOUR_REPO/sankofa-bridge.git .

# Pull secrets from SSM Parameter Store
echo "Fetching secrets from SSM..."
SANKOFA_API_KEY=$(aws ssm get-parameter --name /sankofa/api-key --with-decryption --query Parameter.Value --output text 2>/dev/null || echo "")
SANKOFA_SECRET_SEED=$(aws ssm get-parameter --name /sankofa/secret-seed --with-decryption --query Parameter.Value --output text 2>/dev/null || echo "")
DATABASE_URL=$(aws ssm get-parameter --name /sankofa/database-url --with-decryption --query Parameter.Value --output text 2>/dev/null || echo "sqlite:///sankofa_bridge.db")
RECEIVER_API_URL=$(aws ssm get-parameter --name /sankofa/receiver-api-url --with-decryption --query Parameter.Value --output text 2>/dev/null || echo "")
RECEIVER_API_KEY=$(aws ssm get-parameter --name /sankofa/receiver-api-key --with-decryption --query Parameter.Value --output text 2>/dev/null || echo "")

# Write .env
cat > .env << ENVFILE
SANKOFA_API_KEY=${SANKOFA_API_KEY}
SANKOFA_SECRET_SEED=${SANKOFA_SECRET_SEED}
DATABASE_URL=${DATABASE_URL}
RECEIVER_API_URL=${RECEIVER_API_URL}
RECEIVER_API_KEY=${RECEIVER_API_KEY}
ACTIVE_CONNECTOR=mock
LOG_LEVEL=INFO
DEBUG=false
JURISDICTION=GH
ENVFILE

# Python environment
python3.12 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt

# Initialise database
python3 -c "
import asyncio, sys; sys.path.insert(0, '.')
from config.database import db
asyncio.run(db.init_db())
print('Database ready')
"

# Systemd service
cat > /etc/systemd/system/sankofa-bridge.service << SERVICE
[Unit]
Description=SANKƆFA-BRIDGE
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/sankofa-bridge
EnvironmentFile=/opt/sankofa-bridge/.env
ExecStart=/opt/sankofa-bridge/venv/bin/uvicorn api.server:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable sankofa-bridge
systemctl start sankofa-bridge

# Nginx
cat > /etc/nginx/sites-available/sankofa-bridge << 'NGINX'
server {
    listen 80;
    server_name _;

    location /health { proxy_pass http://localhost:8000; access_log off; }
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/sankofa-bridge /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

sleep 3
curl -sf http://localhost/health && echo "HEALTH CHECK PASSED" || echo "WARNING: health check failed"

echo "=== SANKƆFA-BRIDGE Bootstrap complete ==="
echo "API: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)/health"
echo "Next: ./scripts/ops.sh ready"
