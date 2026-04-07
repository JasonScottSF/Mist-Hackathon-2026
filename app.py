import os
import uuid
import requests
from flask import Flask, render_template, request, session, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)

MIST_CLOUDS = {
    "api.mist.com":     "Global 01 (US West)",
    "api.gc1.mist.com": "Global 02 (US West)",
    "api.ac2.mist.com": "Global 03 (US East)",
    "api.gc2.mist.com": "Global 04 (Canada)",
    "api.gc4.mist.com": "Global 05 (Americas)",
    "api.eu.mist.com":  "EMEA 01 (Frankfurt)",
    "api.gc3.mist.com": "EMEA 02 (UK)",
    "api.ac6.mist.com": "EMEA 03 (UAE)",
    "api.gc6.mist.com": "EMEA 04 (Saudi Arabia)",
    "api.ac5.mist.com": "APAC 01 (Sydney)",
    "api.gc5.mist.com": "APAC 02 (India)",
    "api.gc7.mist.com": "APAC 03 (Japan)",
}

# Server-side store: sid -> {"requests_session": ..., "cloud_host": ..., "email": ..., "password": ...}
_sessions = {}


def mist_url(cloud_host, path):
    return f"https://{cloud_host}/api/v1{path}"


def get_requests_session(sid):
    return _sessions.get(sid, {}).get("requests_session")


def mist_get(sid, path):
    rs = get_requests_session(sid)
    cloud_host = _sessions[sid]["cloud_host"]
    r = rs.get(mist_url(cloud_host, path), timeout=15)
    r.raise_for_status()
    return r.json()


@app.route("/", methods=["GET"])
def index():
    if session.get("sid") and session["sid"] in _sessions and _sessions[session["sid"]].get("authenticated"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    # ── Step 2: MFA ──────────────────────────────────────────────────────────
    if request.method == "POST" and request.form.get("step") == "mfa":
        code = request.form.get("mfa_code", "").strip().replace(" ", "")
        sid = session.get("sid")
        store = _sessions.get(sid, {})

        if not code:
            error = "Please enter your verification code."
        elif not store:
            session.clear()
            return redirect(url_for("login"))
        else:
            try:
                rs = store["requests_session"]
                cloud_host = store["cloud_host"]
                r = rs.post(
                    mist_url(cloud_host, "/login"),
                    json={
                        "email": store["email"],
                        "password": store["password"],
                        "two_factor": code,
                    },
                    timeout=15,
                )
                if r.status_code == 200:
                    self_resp = store["requests_session"].get(
                        mist_url(store["cloud_host"], "/self"), timeout=15)
                    self_data = self_resp.json() if self_resp.ok else {}
                    store["user_name"] = self_data.get("name", store.get("email", ""))
                    store["authenticated"] = True
                    store.pop("password", None)
                    return redirect(url_for("dashboard"))
                elif r.status_code == 401:
                    error = "Invalid verification code. Please try again."
                else:
                    error = f"MFA verification failed (HTTP {r.status_code})."
            except Exception as e:
                error = f"Unexpected error: {e}"

        return render_template("login.html", step="mfa", error=error, clouds=MIST_CLOUDS)

    # Redirected here from dashboard with pending MFA
    if request.method == "GET" and request.args.get("mfa"):
        sid = session.get("sid")
        if sid and sid in _sessions and not _sessions[sid].get("authenticated"):
            return render_template("login.html", step="mfa", clouds=MIST_CLOUDS)

    # ── Step 1: Credentials ───────────────────────────────────────────────────
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        cloud_host = request.form.get("cloud", "api.mist.com")
        if cloud_host not in MIST_CLOUDS:
            cloud_host = "api.mist.com"

        if not email or not password:
            error = "Email and password are required."
        else:
            try:
                rs = requests.Session()
                r = rs.post(
                    mist_url(cloud_host, "/login"),
                    json={"email": email, "password": password},
                    timeout=15,
                )
                if r.status_code == 200:
                    sid = str(uuid.uuid4())
                    _sessions[sid] = {
                        "requests_session": rs,
                        "cloud_host": cloud_host,
                        "email": email,
                        "password": password,
                        "authenticated": False,
                    }
                    session["sid"] = sid

                    # Always check /self to get true auth state — login body may be empty
                    self_resp = rs.get(mist_url(cloud_host, "/self"), timeout=15)
                    self_data = self_resp.json() if self_resp.ok else {}
                    _sessions[sid]["user_name"] = self_data.get("name", email)

                    if self_data.get("two_factor_required") and not self_data.get("two_factor_passed"):
                        return render_template("login.html", step="mfa", clouds=MIST_CLOUDS)

                    # MFA not required (or already passed) — fully authenticated
                    _sessions[sid]["authenticated"] = True
                    _sessions[sid].pop("password", None)
                    return redirect(url_for("dashboard"))

                elif r.status_code == 401:
                    error = "Invalid email or password."
                else:
                    error = f"Login failed (HTTP {r.status_code})."
            except requests.exceptions.ConnectionError:
                error = f"Could not reach {cloud_host}."
            except requests.exceptions.Timeout:
                error = "Request timed out."
            except Exception as e:
                error = f"Unexpected error: {e}"

    return render_template("login.html", step="credentials", error=error, clouds=MIST_CLOUDS)


@app.route("/logout")
def logout():
    sid = session.pop("sid", None)
    session.clear()
    if sid and sid in _sessions:
        store = _sessions.pop(sid)
        try:
            rs = store["requests_session"]
            cloud_host = store["cloud_host"]
            rs.post(mist_url(cloud_host, "/logout"), timeout=5)
        except Exception:
            pass
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    sid = session.get("sid")
    if not sid or sid not in _sessions or not _sessions[sid].get("authenticated"):
        return redirect(url_for("login"))
    user_name = _sessions[sid].get("user_name", "")
    return render_template("dashboard.html", user_name=user_name)


@app.route("/api/network-health")
def network_health():
    sid = session.get("sid")
    if not sid or sid not in _sessions or not _sessions[sid].get("authenticated"):
        return jsonify({"error": "Not authenticated", "reauth": True}), 401

    try:
        # 1. Self / orgs
        self_data = mist_get(sid, "/self")

        if self_data.get("two_factor_required") and not self_data.get("two_factor_passed"):
            _sessions[sid]["authenticated"] = False
            return jsonify({"error": "MFA required", "mfa_required": True}), 401

        privileges = self_data.get("privileges", [])
        orgs = [p for p in privileges if p.get("scope") == "org"]

        if not orgs:
            return jsonify({"error": "No organizations found for this account."}), 404

        results = []
        for org_priv in orgs:
            org_id = org_priv.get("org_id")
            org_name = org_priv.get("name", org_id)
            org_data = {"org_id": org_id, "org_name": org_name, "sites": []}

            # 2. Org stats
            try:
                s = mist_get(sid, f"/orgs/{org_id}/stats")
                org_data["num_devices"]             = s.get("num_devices", 0)
                org_data["num_devices_connected"]   = s.get("num_devices_connected", 0)
                org_data["num_devices_disconnected"]= s.get("num_devices_disconnected", 0)
                org_data["num_clients"]             = s.get("num_clients", 0)
                org_data["num_sites"]               = s.get("num_sites", 0)
            except Exception:
                org_data.update({"num_devices": 0, "num_devices_connected": 0,
                                  "num_devices_disconnected": 0, "num_clients": 0, "num_sites": 0})

            # 3. Alarms
            try:
                alarms = mist_get(sid, f"/orgs/{org_id}/alarms/search?limit=100&resolved=false")
                alarm_list = alarms.get("results", [])
                org_data["active_alarms"] = len(alarm_list)
                org_data["alarm_details"] = [
                    {
                        "type":      a.get("type", ""),
                        "severity":  a.get("severity", ""),
                        "group":     a.get("group", ""),
                        "site_name": a.get("site_name", ""),
                        "timestamp": a.get("timestamp", 0),
                        "count":     a.get("count", 1),
                    }
                    for a in alarm_list[:10]
                ]
            except Exception:
                org_data["active_alarms"] = 0
                org_data["alarm_details"] = []

            # 4. Marvis actions
            try:
                marvis = mist_get(sid, f"/orgs/{org_id}/insights/marvis_actions")
                actions = marvis.get("results", []) if isinstance(marvis, dict) else []
                org_data["marvis_actions"] = [
                    {
                        "action":    a.get("action", ""),
                        "title":     a.get("title", a.get("action", "")),
                        "impact":    a.get("impact", ""),
                        "severity":  a.get("severity", ""),
                        "site_name": a.get("site_name", ""),
                    }
                    for a in actions[:5]
                ]
            except Exception:
                org_data["marvis_actions"] = []

            # 5. Per-site stats
            try:
                sites = mist_get(sid, f"/orgs/{org_id}/sites")
                if not isinstance(sites, list):
                    sites = []
                for site in sites[:20]:
                    site_id = site.get("id")
                    entry = {
                        "site_id": site_id,
                        "name":    site.get("name", site_id),
                        "num_ap": 0, "num_ap_connected": 0,
                        "num_clients": 0,
                        "num_switches": 0, "num_switches_connected": 0,
                        "num_gateways": 0, "num_gateways_connected": 0,
                    }
                    try:
                        ss = mist_get(sid, f"/sites/{site_id}/stats")
                        for k in entry:
                            if k not in ("site_id", "name"):
                                entry[k] = ss.get(k, 0)
                    except Exception:
                        pass
                    org_data["sites"].append(entry)
            except Exception:
                pass

            results.append(org_data)

        return jsonify({"orgs": results})

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return jsonify({"error": "Session expired.", "reauth": True}), 401
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
