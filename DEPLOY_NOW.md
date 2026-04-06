# SANKƆFA-BRIDGE — Deploy to Production
# Live URL in under 10 minutes

**Architect:** David King Boison  
**Framework:** Visionary Prompt Framework (VPF)  
**Target:** https://sankofa-bridge.onrender.com (free, live, public)

---

## What you need

- A GitHub account (free) — github.com
- A Render account (free) — render.com
- This codebase (SANKOFA-BRIDGE-v1.2-Deploy-Integration.zip)
- 10 minutes

No credit card. No server. No DevOps knowledge required.

---

## Step 1 — Prepare the code (2 minutes)

**On your computer, open Terminal (Mac/Linux) or Command Prompt (Windows):**

```bash
# Unzip the codebase
unzip SANKOFA-BRIDGE-v1.2-Deploy-Integration.zip -d sankofa-bridge
cd sankofa-bridge

# Create a .env file with your settings
cp .env.template .env
```

**Edit .env — change these three lines:**
```
SANKOFA_API_KEY=skb_<generate a random string here>
SANKOFA_SECRET_SEED=<any long random phrase — at least 32 characters>
ACTIVE_CONNECTOR=mock
```

Generate a random API key: run `python3 -c "import secrets; print('skb_' + secrets.token_urlsafe(32))"`

---

## Step 2 — Push to GitHub (3 minutes)

```bash
# Initialize git repository
git init
git add .
git commit -m "SANKƆFA-BRIDGE v1.0 — Initial deployment"

# Create a new repo on GitHub
# Go to github.com → New repository → name it "sankofa-bridge" → Create

# Connect and push (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/sankofa-bridge.git
git branch -M main
git push -u origin main
```

---

## Step 3 — Deploy on Render (5 minutes)

1. Go to **render.com** → Sign up / Log in
2. Click **New +** → **Web Service**
3. Click **Connect a repository** → Select `sankofa-bridge`
4. Render will detect `render.yaml` automatically
5. Click **Apply** — Render creates the database and web service

**That's it. Render handles everything else.**

You'll see the build log. When it shows:
```
==> Your service is live at https://sankofa-bridge.onrender.com
```

Your system is running.

---

## Step 4 — Verify it's live (1 minute)

Open your browser and go to:

```
https://sankofa-bridge.onrender.com/health
```

You should see:
```json
{"status": "ok", "system": "SANKƆFA-BRIDGE", "version": "1.0.0"}
```

**API documentation** (full interactive docs):
```
https://sankofa-bridge.onrender.com/docs
```

---

## Step 5 — Set your API key in Render

1. Go to Render dashboard → Your service → **Environment**
2. Find `SANKOFA_API_KEY` — copy its auto-generated value
3. This is your key for all API calls

**Test authentication:**
```bash
curl https://sankofa-bridge.onrender.com/v1/status \
  -H "X-SANKOFA-API-Key: YOUR_KEY_HERE"
```

---

## Step 6 — Open the Operator Console

Open `ui/console.html` from the codebase in your browser.

At the top of the file, set:
```javascript
const API = 'https://sankofa-bridge.onrender.com';
const API_KEY = 'YOUR_KEY_HERE';
```

Save and open in browser. Your full operator dashboard is live.

---

## After deployment — your next actions

### Enable live delivery (when receiver API is confirmed)
In Render → Environment, set:
```
RECEIVER_API_URL = https://receiver-system.example.com/v1/receive
RECEIVER_API_KEY = receiver-api-key-here
```

### Enable live Claude intelligence (Copilot)
In Render → Environment, set:
```
ANTHROPIC_API_KEY = your-anthropic-api-key
```
Then use `POST /v1/copilot/live-query` for full live intelligence.

### Enable live delivery (compliance gate)
Answer all 18 compliance gate questions via:
```bash
curl -X POST https://sankofa-bridge.onrender.com/v1/compliance/gate/answer \
  -H "X-SANKOFA-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"question_id": 1, "answer_text": "Your answer here", "answered_by": "David King Boison"}'
```
Then in Render → Environment: `COMPLIANCE_GATE_CLEARED = true`

### Connect real source (when counterparty confirms)
In Render → Environment, set:
```
ACTIVE_CONNECTOR = sftp   (or s3, rest_api, azure_blob)
SFTP_HOST = your.source.server.com
SFTP_USER = username
SFTP_KEY_PATH = /path/to/private/key
```

---

## All live API endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Public health check |
| `GET /v1/status` | System status |
| `GET /v1/dashboard` | Dashboard metrics |
| `GET /v1/files` | List processed files |
| `GET /v1/compliance/gate` | Compliance gate status |
| `POST /v1/compliance/gate/answer` | Answer gate question |
| `GET /v1/exceptions` | Open exceptions |
| `GET /v1/audit/export` | Export audit log |
| `POST /v1/copilot/query` | Rule-based copilot |
| `POST /v1/copilot/live-query` | Live Claude copilot |
| `GET /v1/copilot/regulatory-briefing` | Ghana/Africa regulatory brief |
| `POST /v1/delivery/acknowledge` | Receiver acknowledgement |
| `GET /docs` | Full interactive API docs |

---

## Alternative: Deploy on a VPS (if you have a server)

If you have a Ubuntu server (DigitalOcean, AWS EC2, etc.):

```bash
# On your server
git clone https://github.com/YOUR_USERNAME/sankofa-bridge.git
cd sankofa-bridge
cp .env.template .env
nano .env   # Fill in your values

# Run the deployment script
bash deploy/run.sh --target vps
```

Done. The script installs everything, configures systemd and nginx.

---

## VPF Principle

*"No data moves without provenance. No value moves without custodianship.  
No system operates without auditability."*

— David King Boison, SANKƆFA-BRIDGE Architect
