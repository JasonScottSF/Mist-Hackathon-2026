# Mist Automated Onboarding Assistant

A Flask web application that accelerates Juniper Mist network deployments. It guides engineers from pre-deployment planning through site creation, live rollout tracking, and ongoing health monitoring — all from a single interface backed by the Mist REST API.

---

## Features

### Plan
Pre-deployment readiness checks for your org:
- WLAN best-practice audit (security, rate sets, band steering)
- Data rate configuration review
- Golden template status (Network, WLAN, RF)
- One-click creation of HPE best-practice templates

### New Site
Provision a new Mist site and apply templates in one step:
- Set site name, address, timezone, and country code
- Assign existing Network, WLAN, Gateway, and RF templates — or create best-practice templates on the spot
- Step-by-step result log shows exactly what was applied

### Deploy
Live rollout dashboard, auto-refreshed every 30 seconds:
- Per-site GO / NO GO status with device online counts
- Infrastructure drawers: APs, Switches, WAN Edge, Mist Edges
- Client drawers: Wireless, Wired, DPC-classified, NAC
- One-click DPC → NAC rule conversion per site
- Site sign-off with optional notes (stored in browser localStorage)
- CSV export of the full deployment report

### Operate
Post-deployment health overview:
- SLE scores (Wireless, Wired, WAN) — last 24 hours
- Per-site score breakdown
- Active alarm summary

### DPC → NAC Converter
Standalone tool (also accessible from Deploy tab):
- Scans org network templates for DPC rules and wired clients
- Groups discovered devices by LLDP name prefix and MAC OUI
- Assigns port profiles to groups and writes DPC rules back to the template
- Deduplicates rules; never creates a duplicate of an existing rule

---

## Architecture

```
Browser  ──►  Flask (dpc_to_nac.py)  ──►  Mist REST API
                    │
              templates/journey.html   ← single-page app (vanilla JS)
              templates/dpc_*.html     ← login / org selection / DPC preview
```

- **Backend:** Python 3.11, Flask 3, Gunicorn, `requests` (one persistent session per logged-in user)
- **Frontend:** Vanilla JS, no build step — all rendering happens client-side in `journey.html`
- **Auth:** Mist username + password (or API key) with MFA support; sessions are in-memory with a 4-hour TTL
- **Rate limiting:** 20 login attempts per minute per IP via Flask-Limiter

---

## Quick Start (local)

### Prerequisites
- Python 3.11+
- A Juniper Mist account with org admin access

### Setup

```bash
git clone https://github.com/JasonScottSF/Mist-Hackathon-2026.git
cd Mist-Hackathon-2026

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run

```bash
# Development (single worker, auto-reloads)
flask --app dpc_to_nac run --port 5001

# Production-style (matches the Docker setup)
gunicorn -b 0.0.0.0:5001 -w 1 --threads 4 --timeout 60 dpc_to_nac:app
```

Open **http://localhost:5001** in your browser.

> **Note:** Keep `-w 1` (single worker). Sessions are stored in process memory — multiple workers will cause auth failures. Scale with `--threads` instead, or migrate session state to Redis before increasing workers.

---

## Docker

### Build and run

```bash
docker compose up --build
```

The app listens on port **5001**. A named volume (`mist-secrets`) persists the Flask secret key across restarts so existing browser sessions survive redeployments.

### docker-compose.yml summary

| Setting | Value |
|---|---|
| Port | `5001:5001` |
| Secret key storage | `/app/secrets` (mounted volume) |
| Restart policy | `unless-stopped` |
| Health check | HTTP GET `/login` every 30s |

---

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `FLASK_SECRET_DIR` | App directory | Directory where the Flask secret key file is stored |

### Mist cloud regions

The login page lets users select their Mist cloud. All regions are supported:

| Endpoint | Region |
|---|---|
| `api.mist.com` | Global 01 (US West) |
| `api.gc1.mist.com` | Global 02 (US West) |
| `api.ac2.mist.com` | Global 03 (US East) |
| `api.gc2.mist.com` | Global 04 (Canada) |
| `api.gc4.mist.com` | Global 05 (Americas) |
| `api.eu.mist.com` | EMEA 01 (Frankfurt) |
| `api.gc3.mist.com` | EMEA 02 (UK) |
| `api.ac6.mist.com` | EMEA 03 (UAE) |
| `api.gc6.mist.com` | EMEA 04 (Saudi Arabia) |
| `api.ac5.mist.com` | APAC 01 (Sydney) |
| `api.gc5.mist.com` | APAC 02 (India) |
| `api.gc7.mist.com` | APAC 03 (Japan) |

---

## API Reference

All endpoints require an active session. Unauthenticated requests return `401`. Invalid org IDs return `400`. All `org_id` values must be valid UUIDs.

### Authentication

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/login` | Login with username/password or API key; handles MFA |
| `GET` | `/logout` | Invalidate session |
| `GET/POST` | `/orgs` | List orgs and select one |

### Journey (main app)

| Method | Path | Description |
|---|---|---|
| `GET` | `/journey/<org_id>` | Load the main single-page application |

### Deploy tab

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/deploy_status/<org_id>` | Device counts and GO/NO GO per site |
| `GET` | `/api/deploy_clients/<org_id>` | Wireless, wired, NAC, and DPC-flagged clients |

### New Site tab

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/site_options/<org_id>` | Available Network, WLAN, Gateway, and RF templates |
| `POST` | `/api/create_site/<org_id>` | Create site and assign templates |

**`POST /api/create_site/<org_id>` body:**
```json
{
  "name": "Austin HQ",
  "address": "123 Main St, Austin TX 78701",
  "timezone": "America/Chicago",
  "country_code": "US",
  "network_template_id": "<uuid>",
  "wlan_template_id": "<uuid>",
  "gateway_template_id": "<uuid>",
  "rf_template_id": "<uuid>"
}
```
All template fields are optional. Omit or leave blank to skip that assignment.

### Plan tab — Best Practices

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/bestpractices/<org_id>` | WLAN audit results |
| `POST` | `/api/bestpractices/<org_id>/<wlan_id>` | Apply best-practice fixes to a WLAN |
| `GET` | `/api/datarates/<org_id>` | Data rate configuration |
| `POST` | `/api/datarates/<org_id>/<wlan_id>` | Apply high-density rate sets |
| `GET` | `/api/golden_status/<org_id>` | Check whether golden templates exist |
| `POST` | `/api/create_golden/<org_id>/<tmpl_type>` | Create a golden template (`wlan`, `network`, `rf`, `gateway`) |

### DPC → NAC Converter

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/scan/<org_id>` | Scan org for DPC rules and wired clients |
| `POST` | `/api/apply/<org_id>` | Write converted NAC rules back to Mist |
| `GET` | `/api/dpc_discover/<org_id>/<tmpl_id>` | Discover devices for smart DPC rule creation |
| `POST` | `/api/dpc_rules_batch/<org_id>/<tmpl_id>` | Write a batch of new DPC rules |
| `DELETE` | `/api/template_profile/<org_id>/<tmpl_id>/<profile_name>` | Remove a port profile from a template |

### Network / DNS / NTP

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/dnsntp/<org_id>/<tmpl_id>` | Apply DNS/NTP settings to a network template |
| `POST` | `/api/wan_dnsntp/<org_id>/<tmpl_id>` | Apply DNS/NTP settings to a gateway template |
| `POST` | `/api/rftemplate/<org_id>` | Create the Suggested Baseline RF template |
| `POST` | `/api/convert_wlan/<org_id>` | Promote a site-level WLAN to an org template |

### Operate tab — Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health/<org_id>` | SLE scores and alarm summary (last 24 hours) |

---

## Project Structure

```
Mist-Hackathon-2026/
├── dpc_to_nac.py          # Flask application — all routes and business logic
├── requirements.txt       # Python dependencies
├── Dockerfile
├── docker-compose.yml
└── templates/
    ├── journey.html        # Main single-page app (Plan / New Site / Deploy / Operate)
    ├── dpc_login.html      # Login page
    ├── dpc_orgs.html       # Org selection page
    ├── dpc_preview.html    # DPC → NAC preview & apply
    ├── site_health.html    # Per-site health detail
    ├── inventory.html      # Device inventory
    ├── troubleshoot.html   # Client troubleshooting
    ├── health.html         # Org-level health
    └── bestpractices.html  # Best practices standalone view
```

---

## Security Notes

- Session cookies are `HttpOnly`, `Secure`, and `SameSite=Lax`
- All `org_id` / `site_id` / UUID parameters are validated with a regex before use
- Login is rate-limited to 20 attempts per minute per IP
- Sessions expire after 4 hours and are lazily pruned on each request
- The Flask secret key is generated once and persisted to disk so sessions survive restarts without being stored in source control
- Mist credentials are never logged; only the user's email and remote IP are written to the audit log

---

## Development Notes

### Adding a new API call

Use the `mist_get` / `mist_post` / `mist_put` / `mist_patch` / `mist_delete` helpers — they attach the session cookie and CSRF token automatically:

```python
result  = mist_get(sid, f"/orgs/{org_id}/sites")
resp    = mist_post(sid, f"/orgs/{org_id}/sites", {"name": "New Site"})
resp    = mist_put(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}", body)
resp    = mist_patch(sid, f"/sites/{site_id}/setting", {"rftemplate_id": rf_id})
```

`mist_get` returns parsed JSON. The others return the raw `requests.Response` object — check `.ok` and call `.json()` as needed.

### Parallel Mist API calls

Use `ThreadPoolExecutor` for fan-out fetches (the pattern used throughout the app):

```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=4) as pool:
    f_a = pool.submit(mist_get, sid, "/orgs/{org_id}/sites")
    f_b = pool.submit(mist_get, sid, "/orgs/{org_id}/networktemplates")

sites     = f_a.result()
templates = f_b.result()
```

### Frontend rendering

`journey.html` is a vanilla JS single-page app. The four tabs call their respective `render*()` functions after data loads:

```
loadAll()
  ├── renderPlan()
  ├── renderCreate()
  ├── renderDeploy()
  └── renderOperate()
```

State is held in the global `state` object: `state.bp`, `state.dr`, `state.health`, `state.deploy`, `state.deployClients`, `state.siteOptions`.
