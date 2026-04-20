# Setup Instructions — Mist Automated Onboarding Assistant

Choose the installation method that fits your environment:

- [Local (Python venv)](#local-python-venv) — best for development and demos
- [Docker](#docker) — best for shared or production deployments

---

## Prerequisites

| Requirement | Minimum version | Check |
|---|---|---|
| Python | 3.11 | `python3 --version` |
| pip | 23+ | `pip --version` |
| Git | any | `git --version` |
| Docker + Compose | 24 / 2.20 | `docker --version && docker compose version` |

You also need a **Juniper Mist account** with **org admin** (or read access for read-only features). An API key can be used instead of a username and password.

---

## Local (Python venv)

### 1. Clone the repository

```bash
git clone https://github.com/JasonScottSF/Mist-Hackathon-2026.git
cd Mist-Hackathon-2026
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
```

| Platform | Activate command |
|---|---|
| macOS / Linux | `source venv/bin/activate` |
| Windows (cmd) | `venv\Scripts\activate.bat` |
| Windows (PowerShell) | `venv\Scripts\Activate.ps1` |

Your prompt will change to show `(venv)` when active.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the server

**Development** (Flask built-in server, auto-reloads on code changes):

```bash
flask --app dpc_to_nac run --port 5001
```

**Production-style** (Gunicorn, matches the Docker setup):

```bash
gunicorn -b 0.0.0.0:5001 -w 1 --threads 4 --timeout 60 dpc_to_nac:app
```

> ⚠️ **Keep `-w 1` (one worker).** Sessions are stored in process memory. Running multiple workers will cause random auth failures as requests land on workers with no knowledge of the session. Use `--threads` to handle concurrency instead.

### 5. Open the app

Navigate to **http://localhost:5001** in your browser.

---

## Docker

### 1. Clone the repository

```bash
git clone https://github.com/JasonScottSF/Mist-Hackathon-2026.git
cd Mist-Hackathon-2026
```

### 2. Build and start

```bash
docker compose up --build
```

Add `-d` to run in the background:

```bash
docker compose up --build -d
```

### 3. Open the app

Navigate to **http://localhost:5001** in your browser.

### 4. View logs

```bash
docker compose logs -f
```

### 5. Stop the app

```bash
docker compose down
```

### Data persistence

A named Docker volume (`mist-secrets`) stores the Flask secret key. This means existing browser sessions remain valid across container restarts and redeployments. The volume is created automatically on first run.

To reset the secret key (this will invalidate all active sessions):

```bash
docker compose down -v   # removes the volume
docker compose up -d
```

---

## First Login

1. Open **http://localhost:5001**
2. Select your **Mist cloud region** from the dropdown (e.g. `Global 01 (US West)` for `api.mist.com`)
3. Choose an auth method:
   - **Username / Password** — your Mist login email and password; MFA is handled automatically if enabled on your account
   - **API Key** — a Mist org API token; enter it in the password field
4. Click **Sign in**
5. Select an **organization** from the list
6. You will land on the **Journey** page for that org

### Obtaining a Mist API Key

1. Log in to [manage.mist.com](https://manage.mist.com)
2. Go to **Organization → Settings → API Tokens**
3. Click **Create Token**, copy the value
4. Paste it into the **API Key** field on the login page

---

## Upgrading

### Local

```bash
git pull
source venv/bin/activate
pip install -r requirements.txt   # pick up any new dependencies
```

Then restart the server.

### Docker

```bash
git pull
docker compose up --build -d
```

The `mist-secrets` volume is preserved so sessions stay valid.

---

## Troubleshooting

### The page loads but I get logged out immediately
The Flask secret key changed (e.g. after deleting the key file or the Docker volume). Sign in again — this is a one-time event after a reset.

### `Address already in use` on port 5001
Another process is using the port. Find and stop it:

```bash
# macOS / Linux
lsof -i :5001
kill <PID>

# Or change the port
gunicorn -b 0.0.0.0:5002 ...
```

### MFA code is rejected
Mist TOTP codes are time-sensitive (30-second window). Make sure your system clock is accurate:

```bash
# macOS
sntp -sS time.apple.com

# Linux
timedatectl status
```

### API calls return 401 after a while
Sessions expire after **4 hours**. Sign in again. If you need longer sessions, change `_SESSION_TTL` in `dpc_to_nac.py`.

### `ModuleNotFoundError` on startup
The venv is not active, or `pip install` was not run. Activate the venv and re-run `pip install -r requirements.txt`.

### Docker container exits immediately
Check the logs for the error:

```bash
docker compose logs
```

Common causes: port 5001 already in use on the host, or a Python syntax error introduced by a local edit.

### Deploy tab shows no devices
The Mist API returns devices by type separately. Confirm the org has devices claimed and that your account has at least viewer access to the sites. You can test the raw response at:

```
http://localhost:5001/api/deploy_status/<your-org-id>
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FLASK_SECRET_DIR` | Directory of `dpc_to_nac.py` | Where the `.flask_secret` key file is read/written. Set this to a persistent volume path in containerised deployments. |

Set environment variables before starting the server:

```bash
# Local
export FLASK_SECRET_DIR=/path/to/secrets
gunicorn -b 0.0.0.0:5001 -w 1 --threads 4 dpc_to_nac:app

# docker-compose.yml (already configured)
environment:
  - FLASK_SECRET_DIR=/app/secrets
```
