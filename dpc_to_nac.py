import os
import re
import time
import uuid
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Persist secret key so Flask session cookies (and stored credentials) survive server restarts.
# In Docker the key lives in the mounted volume (FLASK_SECRET_DIR env var).
_secret_dir = os.environ.get("FLASK_SECRET_DIR", os.path.dirname(__file__))
_KEY_FILE = os.path.join(_secret_dir, ".flask_secret")
try:
    with open(_KEY_FILE, "rb") as _f:
        _secret = _f.read()
    if len(_secret) < 24:
        raise ValueError("short key")
except Exception:
    _secret = os.urandom(32)
    with open(_KEY_FILE, "wb") as _f:
        _f.write(_secret)
app.secret_key = _secret

# Session cookie hardening (TLS termination handled by reverse proxy)
app.config["SESSION_COOKIE_SECURE"]   = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Rate limiter — 20 login attempts per minute per IP
_limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# Audit log — writes to stdout/stderr, captured by gunicorn/systemd
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
_log = logging.getLogger("dpc_nac")

_SESSION_TTL = 4 * 3600  # seconds; sessions pruned lazily on each request
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
)

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

_sessions = {}  # sid → {requests_session, cloud_host, email, user_name, authenticated, created_at}


# ── Helpers ───────────────────────────────────────────────────────────────────

def valid_uuid(s):
    """Return True if s is a well-formed UUID (prevents path-traversal style abuse)."""
    return bool(_UUID_RE.match(s or ""))


def _prune_sessions():
    """Expire sessions older than SESSION_TTL. Called lazily on each request."""
    now = time.time()
    expired = [sid for sid, s in list(_sessions.items())
               if now - s.get("created_at", now) > _SESSION_TTL]
    for sid in expired:
        _sessions.pop(sid, None)


def mist_url(cloud_host, path):
    return f"https://{cloud_host}/api/v1{path}"


def mist_get(sid, path):
    store = _sessions[sid]
    r = store["requests_session"].get(mist_url(store["cloud_host"], path), timeout=20)
    r.raise_for_status()
    return r.json()


def mist_post(sid, path, body):
    store = _sessions[sid]
    rs    = store["requests_session"]
    host  = store["cloud_host"]
    csrf  = next((v for k, v in rs.cookies.items() if k.startswith("csrftoken")), None)
    headers = {"X-CSRFToken": csrf} if csrf else {}
    return rs.post(mist_url(host, path), json=body, headers=headers, timeout=20)


def mist_put(sid, path, body):
    store = _sessions[sid]
    rs    = store["requests_session"]
    host  = store["cloud_host"]
    csrf  = next((v for k, v in rs.cookies.items() if k.startswith("csrftoken")), None)
    headers = {"X-CSRFToken": csrf} if csrf else {}
    return rs.put(mist_url(host, path), json=body, headers=headers, timeout=20)


def mist_patch(sid, path, body):
    store = _sessions[sid]
    rs    = store["requests_session"]
    host  = store["cloud_host"]
    csrf  = next((v for k, v in rs.cookies.items() if k.startswith("csrftoken")), None)
    headers = {"X-CSRFToken": csrf} if csrf else {}
    return rs.patch(mist_url(host, path), json=body, headers=headers, timeout=20)


def mist_delete(sid, path):
    store = _sessions[sid]
    rs    = store["requests_session"]
    host  = store["cloud_host"]
    csrf  = next((v for k, v in rs.cookies.items() if k.startswith("csrftoken")), None)
    headers = {"X-CSRFToken": csrf} if csrf else {}
    return rs.delete(mist_url(host, path), headers=headers, timeout=20)


def authed(sid):
    return bool(sid and sid in _sessions and _sessions[sid].get("authenticated"))


def recover_session():
    """
    Re-create a Mist requests.Session from credentials stored in the (encrypted)
    Flask session cookie.  Called automatically when the in-memory _sessions dict
    is empty after a server restart.
    """
    auth_info = session.get("auth_info", {})
    if not auth_info:
        return None
    # Enforce hard 4-hour wall-clock expiry from original login time
    login_time = auth_info.get("login_time", 0)
    if time.time() - login_time > _SESSION_TTL:
        session.clear()
        return None
    cloud_host = auth_info.get("cloud_host", "api.mist.com")
    try:
        rs = requests.Session()
        if auth_info.get("auth_method") == "apikey":
            rs.headers.update({"Authorization": f"Token {auth_info['api_key']}"})
            sd = rs.get(mist_url(cloud_host, "/self"), timeout=15)
            if not sd.ok:
                return None
            self_data = sd.json()
        else:
            email    = auth_info.get("email", "")
            password = auth_info.get("password", "")
            if not email or not password:
                return None
            r = rs.post(mist_url(cloud_host, "/login"),
                        json={"email": email, "password": password}, timeout=15)
            if r.status_code != 200:
                return None
            sd        = rs.get(mist_url(cloud_host, "/self"), timeout=15)
            self_data = sd.json() if sd.ok else {}
            if self_data.get("two_factor_required") and not self_data.get("two_factor_passed"):
                return None   # MFA required — user must sign in manually

        sid = str(uuid.uuid4())
        _sessions[sid] = {
            "requests_session": rs,
            "cloud_host":       cloud_host,
            "email":            self_data.get("email", auth_info.get("email", "")),
            "user_name":        self_data.get("name",  auth_info.get("email", "User")),
            "authenticated":    True,
            "created_at":       time.time(),
        }
        session["sid"] = sid
        return sid
    except Exception:
        return None


def get_authed_sid():
    """Return an authenticated sid, transparently recovering the session if needed."""
    _prune_sessions()
    sid = session.get("sid")
    if sid and _sessions.get(sid, {}).get("authenticated"):
        return sid
    return recover_session()


def mist_list(sid, path):
    """Fetch a Mist list endpoint; handles both [] and {"results":[]} responses."""
    try:
        resp = mist_get(sid, path)
        if isinstance(resp, list):
            return resp, None
        if isinstance(resp, dict):
            return resp.get("results", []), None
        return [], f"unexpected type {type(resp).__name__}"
    except Exception as e:
        return [], str(e)



def org_allowed(org_id):
    locked = session.get("locked_org_id")
    return (not locked) or (locked == org_id)


# ── DPC → NAC Conversion ──────────────────────────────────────────────────────

def vlan_for_usage(usage_name, usage_cfg, networks):
    port_network = usage_cfg.get("port_network", "")
    if port_network and port_network != "default" and port_network in networks:
        v = networks[port_network].get("vlan_id", "")
        if v:
            return str(v)
    for net_name in usage_cfg.get("networks", []):
        if net_name in networks:
            v = networks[net_name].get("vlan_id", "")
            if v:
                return str(v)
    return ""


def scan_org_dpc(sid, org_id):
    sources = []
    try:
        templates = mist_get(sid, f"/orgs/{org_id}/networktemplates")
        if not isinstance(templates, list):
            templates = []
    except Exception:
        templates = []

    for tmpl in templates:
        tmpl_id   = tmpl.get("id")
        tmpl_name = tmpl.get("name", tmpl_id)
        try:
            detail = mist_get(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}")
        except Exception:
            continue

        port_usages = detail.get("port_usages", {})
        networks    = detail.get("networks", {})
        dpc_rules   = port_usages.get("dynamic", {}).get("rules", [])
        if not dpc_rules:
            continue

        vlan_map = {}
        for uname, ucfg in port_usages.items():
            if uname != "dynamic":
                v = vlan_for_usage(uname, ucfg, networks)
                if v:
                    vlan_map[uname] = v

        clean_rules = []
        for rule in dpc_rules:
            src    = rule.get("src", "")
            usage  = rule.get("usage", "")
            values = []
            if "equals" in rule:
                values.append(rule["equals"])
            if "equals_any" in rule:
                values.extend(rule["equals_any"])
            clean_rules.append({
                "src":        src,
                "type":       "MAC OUI" if src == "link_peermac" else "LLDP Name",
                "values":     values,
                "usage":      usage,
                "expression": rule.get("expression", ""),
            })

        sources.append({
            "template_id":   tmpl_id,
            "template_name": tmpl_name,
            "rules":         clean_rules,
            "vlan_map":      vlan_map,
        })

    return sources


def mac_to_colon(mac):
    mac = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return ":".join(mac[i:i+2] for i in range(0, len(mac), 2))


def apply_dpc_expression(subject, expression):
    try:
        inner = expression.strip("[]")
        start, end = (int(x) for x in inner.split(":"))
        return subject[start:end]
    except Exception:
        return subject


def match_dpc_rule(mac_colon, rule):
    if rule["src"] != "link_peermac":
        return False
    expr    = rule.get("expression", "[0:8]")
    subject = apply_dpc_expression(mac_colon, expr)
    return any(subject.lower() == v.lower() for v in rule["values"])


def match_lldp_rule(lldp_name, rule):
    if rule["src"] != "lldp_system_name":
        return False
    expr    = rule.get("expression", "[0:3]")
    subject = apply_dpc_expression(lldp_name, expr)
    return any(subject.lower() == v.lower() for v in rule["values"])


def _normalize_field(val):
    """Safely extract a string from a field that may be a list or None."""
    if isinstance(val, list):
        return val[0] if val else ""
    return val or ""


def scan_org_endpoints(sid, org_id, sources):
    mac_rules  = []
    lldp_rules = []
    for src in sources:
        for rule in src["rules"]:
            entry = {"rule": rule, "label": f"dpc-{rule['usage']}", "usage": rule["usage"]}
            if rule["src"] == "link_peermac":
                mac_rules.append(entry)
            elif rule["src"] == "lldp_system_name":
                lldp_rules.append(entry)

    if not mac_rules and not lldp_rules:
        return []

    try:
        resp    = mist_get(sid, f"/orgs/{org_id}/wired_clients/search?limit=1000&duration=7d")
        clients = resp.get("results", []) if isinstance(resp, dict) else []
    except Exception:
        clients = []

    # Build LLDP lookup from port stats: (switch_mac, port_id) → neighbor_system_name
    port_lldp = {}
    if lldp_rules:
        try:
            port_resp = mist_get(sid, f"/orgs/{org_id}/stats/ports/search?limit=1000")
            ports     = port_resp.get("results", []) if isinstance(port_resp, dict) else []
            for port in ports:
                lldp_name = port.get("neighbor_system_name", "").strip()
                if lldp_name:
                    key = (_normalize_field(port.get("mac")).lower(),
                           _normalize_field(port.get("port_id")))
                    port_lldp[key] = lldp_name
        except Exception:
            pass

    proposed_endpoints = {}

    for client in clients:
        client_mac = client.get("mac", "")
        if not client_mac or client_mac in proposed_endpoints:
            continue

        mac_colon  = mac_to_colon(client_mac)
        device_mac = _normalize_field(client.get("device_mac")).lower()
        port_ids   = client.get("port_id", [])
        if isinstance(port_ids, str):
            port_ids = [port_ids]

        matched = None

        # 1. MAC-OUI rules
        for entry in mac_rules:
            if match_dpc_rule(mac_colon, entry["rule"]):
                matched = {
                    "mac":         client_mac,
                    "mac_display": mac_colon,
                    "name":        client.get("manufacture", client_mac),
                    "label":       entry["label"],
                    "usage":       entry["usage"],
                    "matched_on":  apply_dpc_expression(mac_colon, entry["rule"].get("expression", "[0:8]")),
                    "match_type":  "MAC OUI",
                }
                break

        # 2. LLDP — try fields directly on the client record first
        if not matched and lldp_rules:
            for field in ("lldp_system_name", "hostname"):
                lldp_name = _normalize_field(client.get(field)).strip()
                if not lldp_name:
                    continue
                for entry in lldp_rules:
                    if match_lldp_rule(lldp_name, entry["rule"]):
                        matched = {
                            "mac":         client_mac,
                            "mac_display": mac_colon,
                            "name":        client.get("manufacture", lldp_name),
                            "label":       entry["label"],
                            "usage":       entry["usage"],
                            "matched_on":  lldp_name,
                            "match_type":  "LLDP",
                        }
                        break
                if matched:
                    break

        # 3. LLDP — fall back to port stats join
        if not matched and lldp_rules and device_mac:
            for port_id in port_ids:
                lldp_name = port_lldp.get((device_mac, _normalize_field(port_id)), "")
                if not lldp_name:
                    continue
                for entry in lldp_rules:
                    if match_lldp_rule(lldp_name, entry["rule"]):
                        matched = {
                            "mac":         client_mac,
                            "mac_display": mac_colon,
                            "name":        client.get("manufacture", lldp_name),
                            "label":       entry["label"],
                            "usage":       entry["usage"],
                            "matched_on":  lldp_name,
                            "match_type":  "LLDP",
                        }
                        break
                if matched:
                    break

        if matched:
            proposed_endpoints[client_mac] = matched

    return list(proposed_endpoints.values())


def build_conversion(sources):
    lldp_by_usage = {}
    has_mac_usage = set()
    vlan_by_usage = {}

    def dedup(lst):
        seen = set()
        return [x for x in lst if not (x in seen or seen.add(x))]

    for src in sources:
        for usage, vlan in src["vlan_map"].items():
            if usage not in vlan_by_usage and vlan:
                vlan_by_usage[usage] = vlan
        for rule in src["rules"]:
            usage = rule["usage"]
            if rule["src"] == "link_peermac":
                has_mac_usage.add(usage)
            else:
                lldp_by_usage.setdefault(usage, []).extend(rule["values"])

    all_usages     = sorted(has_mac_usage | set(lldp_by_usage))
    proposed_tags  = []
    proposed_rules = []

    for order, usage in enumerate(all_usages, 1):
        label_name      = f"dpc-{usage}"
        classifier_tags = []
        result_tags     = []

        if usage in has_mac_usage:
            proposed_tags.append({
                "tag_role": "classifier",
                "name":     f"DPC-label-{usage}",
                "type":     "match",
                "match":    "usermac_label",
                "values":   [label_name],
                "usage":    usage,
                "note":     f"Matches endpoints with label '{label_name}'",
            })
            classifier_tags.append(f"DPC-label-{usage}")

        if usage in lldp_by_usage:
            proposed_tags.append({
                "tag_role": "classifier",
                "name":     f"DPC-hostname-{usage}",
                "type":     "match",
                "match":    "hostname",
                "values":   dedup(lldp_by_usage[usage]),
                "usage":    usage,
                "note":     "Matches LLDP system name / DHCP hostname",
            })
            classifier_tags.append(f"DPC-hostname-{usage}")

        vlan = vlan_by_usage.get(usage, "")
        if vlan:
            proposed_tags.append({
                "tag_role": "result",
                "name":     f"DPC-vlan-{usage}",
                "type":     "vlan",
                "match":    None,
                "values":   [],
                "vlan":     vlan,
                "usage":    usage,
                "note":     f"VLAN {vlan} assigned on match",
            })
            result_tags.append(f"DPC-vlan-{usage}")

        proposed_rules.append({
            "name":            f"DPC-converted-{usage}",
            "order":           order,
            "action":          "allow",
            "classifier_tags": classifier_tags,
            "result_tags":     result_tags,
            "vlan":            vlan,
            "label":           label_name,
        })

    return {"proposed_tags": proposed_tags, "proposed_rules": proposed_rules}


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    sid = get_authed_sid()
    return redirect(url_for("orgs") if sid else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@_limiter.limit("20 per minute")
def login():
    error = None

    # MFA submission
    if request.method == "POST" and request.form.get("step") == "mfa":
        code  = request.form.get("mfa_code", "").strip().replace(" ", "")
        sid   = session.get("sid")
        store = _sessions.get(sid, {})
        if not code:
            error = "Please enter your verification code."
        elif not store:
            session.clear()
            return redirect(url_for("login"))
        else:
            try:
                rs   = store["requests_session"]
                host = store["cloud_host"]
                r = rs.post(mist_url(host, "/login"), json={
                    "email": store["email"], "password": store["password"], "two_factor": code,
                }, timeout=15)
                if r.status_code == 200:
                    sd = rs.get(mist_url(host, "/self"), timeout=15)
                    self_data = sd.json() if sd.ok else {}
                    store["user_name"]    = self_data.get("name", store["email"])
                    store["authenticated"] = True
                    # Keep auth_info so recovery works (without password after auth)
                    session["auth_info"] = {
                        "auth_method": "userpass",
                        "cloud_host":  host,
                        "email":       store["email"],
                        "password":    store.pop("password", ""),
                        "login_time":  time.time(),
                    }
                    return redirect(url_for("orgs"))
                elif r.status_code == 401:
                    error = "Invalid verification code."
                else:
                    error = f"MFA failed (HTTP {r.status_code})."
            except Exception as e:
                error = f"Error: {e}"
        return render_template("dpc_login.html", step="mfa", error=error, clouds=MIST_CLOUDS)

    if request.method == "GET" and request.args.get("mfa"):
        sid = session.get("sid")
        if sid and sid in _sessions and not _sessions[sid].get("authenticated"):
            return render_template("dpc_login.html", step="mfa", clouds=MIST_CLOUDS)

    # Credentials / API key submission
    if request.method == "POST":
        cloud_host = request.form.get("cloud", "api.mist.com")
        if cloud_host not in MIST_CLOUDS:
            cloud_host = "api.mist.com"

        auth_method = request.form.get("auth_method", "userpass")

        if auth_method == "apikey":
            api_key = request.form.get("api_key", "").strip()
            if not api_key:
                error = "API token is required."
            else:
                try:
                    rs = requests.Session()
                    rs.headers.update({"Authorization": f"Token {api_key}"})
                    sd = rs.get(mist_url(cloud_host, "/self"), timeout=15)
                    if sd.ok:
                        self_data = sd.json()
                        sid = str(uuid.uuid4())
                        _sessions[sid] = {
                            "requests_session": rs,
                            "cloud_host":       cloud_host,
                            "email":            self_data.get("email", ""),
                            "user_name":        self_data.get("name", "API Token User"),
                            "authenticated":    True,
                            "created_at":       time.time(),
                        }
                        session["sid"] = sid
                        session["auth_info"] = {
                            "auth_method": "apikey",
                            "cloud_host":  cloud_host,
                            "api_key":     api_key,
                            "login_time":  time.time(),
                        }
                        return redirect(url_for("orgs"))
                    else:
                        error = f"Token rejected (HTTP {sd.status_code})."
                except requests.exceptions.ConnectionError:
                    error = f"Could not reach {cloud_host}."
                except Exception as e:
                    error = f"Error: {e}"

        else:  # userpass
            email    = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            if not email or not password:
                error = "Email and password are required."
            else:
                try:
                    rs = requests.Session()
                    r  = rs.post(mist_url(cloud_host, "/login"),
                                 json={"email": email, "password": password}, timeout=15)
                    if r.status_code == 200:
                        sid = str(uuid.uuid4())
                        _sessions[sid] = {
                            "requests_session": rs, "cloud_host": cloud_host,
                            "email": email, "password": password,
                            "authenticated": False, "created_at": time.time(),
                        }
                        session["sid"] = sid
                        sd        = rs.get(mist_url(cloud_host, "/self"), timeout=15)
                        self_data = sd.json() if sd.ok else {}
                        _sessions[sid]["user_name"] = self_data.get("name", email)
                        if self_data.get("two_factor_required") and not self_data.get("two_factor_passed"):
                            return render_template("dpc_login.html", step="mfa", clouds=MIST_CLOUDS)
                        _sessions[sid]["authenticated"] = True
                        session["auth_info"] = {
                            "auth_method": "userpass",
                            "cloud_host":  cloud_host,
                            "email":       email,
                            "password":    _sessions[sid].pop("password", password),
                            "login_time":  time.time(),
                        }
                        return redirect(url_for("orgs"))
                    elif r.status_code == 401:
                        error = "Invalid email or password."
                    else:
                        error = f"Login failed (HTTP {r.status_code})."
                except requests.exceptions.ConnectionError:
                    error = f"Could not reach {cloud_host}."
                except Exception as e:
                    error = f"Error: {e}"

    return render_template("dpc_login.html", step="credentials", error=error, clouds=MIST_CLOUDS)


@app.route("/logout")
def logout():
    sid = session.pop("sid", None)
    session.clear()
    if sid and sid in _sessions:
        store = _sessions.pop(sid)
        try:
            store["requests_session"].post(mist_url(store["cloud_host"], "/logout"), timeout=5)
        except Exception:
            pass
    return redirect(url_for("login"))


# ── App routes ────────────────────────────────────────────────────────────────

@app.route("/orgs", methods=["GET", "POST"])
def orgs():
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        locked = request.form.get("locked_org_id", "").strip()
        if locked:
            session["locked_org_id"] = locked
        else:
            session.pop("locked_org_id", None)

    locked_org_id = session.get("locked_org_id")

    try:
        self_data  = mist_get(sid, "/self")
        privileges = self_data.get("privileges", [])
        org_list   = [p for p in privileges if p.get("scope") == "org"]
    except Exception:
        org_list = []

    if locked_org_id:
        org_list = [p for p in org_list if p.get("org_id") == locked_org_id]
        if not org_list:
            error = f"Org ID '{locked_org_id}' not found in your account privileges."

    return render_template("dpc_orgs.html",
                           user_name=_sessions[sid].get("user_name", ""),
                           orgs=org_list,
                           locked_org_id=locked_org_id or "",
                           error=error)


@app.route("/scan/<org_id>")
def scan(org_id):
    if not valid_uuid(org_id):
        return redirect(url_for("orgs"))
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))
    if not org_allowed(org_id):
        return redirect(url_for("orgs"))
    return render_template("dpc_preview.html",
                           org_id=org_id,
                           user_name=_sessions[sid].get("user_name", ""))


@app.route("/api/scan/<org_id>")
def api_scan(org_id):
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": f"Access denied: locked to org {session.get('locked_org_id')}"}), 403
    try:
        sources            = scan_org_dpc(sid, org_id)
        conversion         = build_conversion(sources)
        proposed_endpoints = scan_org_endpoints(sid, org_id, sources)
        return jsonify({
            "sources":            sources,
            "proposed_tags":      conversion["proposed_tags"],
            "proposed_rules":     conversion["proposed_rules"],
            "proposed_endpoints": proposed_endpoints,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/apply/<org_id>", methods=["POST"])
def api_apply(org_id):
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": f"Access denied: locked to org {session.get('locked_org_id')}"}), 403

    actor = _sessions[sid].get("email", "unknown")
    _log.info("APPLY org=%s actor=%s ip=%s", org_id, actor, request.remote_addr)

    data              = request.json or {}
    tags_payload      = data.get("tags", [])
    rules_payload     = data.get("rules", [])
    endpoints_payload = data.get("endpoints", [])
    results           = {"tags": [], "rules": [], "endpoints": [], "errors": []}

    # ── Pre-fetch existing objects (Mist silently accepts duplicate POSTs) ────
    tag_items,  tag_err  = mist_list(sid, f"/orgs/{org_id}/nactags")
    rule_items, rule_err = mist_list(sid, f"/orgs/{org_id}/nacrules")
    mac_items,  mac_err  = mist_list(sid, f"/orgs/{org_id}/usermacs/search?limit=1000")
    if not mac_items and not mac_err:
        mac_items, mac_err = mist_list(sid, f"/orgs/{org_id}/usermacs?limit=1000")

    existing_tags  = {t["name"]: t["id"] for t in tag_items  if t.get("name")}
    existing_rules = {t["name"]: t["id"] for t in rule_items if t.get("name")}
    existing_macs  = {}
    for m in mac_items:
        raw = m.get("mac", "").lower().replace(":", "").replace("-", "")
        if raw:
            existing_macs[raw] = m.get("id")


    # ── Tags ─────────────────────────────────────────────────────────────────
    tag_id_map = {}
    for tag in tags_payload:
        name = tag["name"]
        if name in existing_tags:
            tag_id_map[name] = existing_tags[name]
            results["tags"].append({"name": name, "id": existing_tags[name],
                                    "role": tag.get("tag_role", ""), "status": "exists"})
            continue

        tag_type = tag.get("type")
        if tag_type == "vlan":
            body = {"name": name, "type": "vlan", "vlan": str(tag.get("vlan", ""))}
        elif tag_type == "gbp_tag":
            body = {"name": name, "type": "gbp_tag", "gbp_tag": int(tag.get("gbp_tag", 0))}
        elif tag_type == "session_timeout":
            body = {"name": name, "type": "session_timeout", "session_timeout": int(tag.get("session_timeout", 3600))}
        elif tag_type == "username_attr":
            body = {"name": name, "type": "username_attr", "username_attr": tag.get("username_attr", "automatic")}
        elif tag_type == "egress_vlan_names":
            body = {"name": name, "type": "egress_vlan_names", "egress_vlan_names": tag.get("egress_vlan_names", [])}
        elif tag_type == "radius_attrs":
            body = {"name": name, "type": "radius_attrs", "radius_attrs": tag.get("radius_attrs", [])}
        elif tag_type == "radius_vendor_attrs":
            body = {"name": name, "type": "radius_vendor_attrs", "radius_vendor_attrs": tag.get("radius_vendor_attrs", [])}
        elif tag_type == "redirect_nacportal_id":
            body = {"name": name, "type": "redirect_nacportal_id", "redirect_nacportal_id": tag.get("redirect_nacportal_id", "")}
        else:  # match (classifier)
            body = {"name": name, "type": "match", "match": tag["match"], "values": tag.get("values", [])}
            if tag.get("match_all"):
                body["match_all"] = True
        try:
            r = mist_post(sid, f"/orgs/{org_id}/nactags", body)
            if r.status_code in (200, 201):
                tag_id = r.json().get("id")
                tag_id_map[name] = tag_id
                results["tags"].append({"name": name, "id": tag_id,
                                        "role": tag.get("tag_role", ""), "status": "created"})
            else:
                try:
                    err = r.json().get("detail", r.text[:120])
                except Exception:
                    err = r.text[:120]
                results["errors"].append(f"Tag '{name}': {err}")
                results["tags"].append({"name": name, "status": "error", "error": err})
        except Exception as e:
            results["errors"].append(f"Tag '{name}': {e}")
            results["tags"].append({"name": name, "status": "error", "error": str(e)})

    # ── Rules ────────────────────────────────────────────────────────────────
    for rule in rules_payload:
        name           = rule["name"]
        classifier_ids = [tag_id_map[n] for n in rule.get("classifier_tags", []) if n in tag_id_map]
        result_ids     = [tag_id_map[n] for n in rule.get("result_tags", [])     if n in tag_id_map]

        if name in existing_rules:
            results["rules"].append({"name": name, "id": existing_rules[name], "status": "exists"})
            continue

        if not classifier_ids:
            msg = f"Rule '{name}': no classifier tags resolved — skipping"
            results["errors"].append(msg)
            results["rules"].append({"name": name, "status": "skipped", "error": msg})
            continue

        matching = {
            "all_tags": rule.get("matching", {}).get("all_tags", False),
            "nactags":  classifier_ids,
        }
        auth_type  = rule.get("matching", {}).get("auth_type", "")
        port_types = rule.get("matching", {}).get("port_types", [])
        if auth_type:  matching["auth_type"]  = auth_type
        if port_types: matching["port_types"] = port_types

        body = {
            "name":     name,
            "enabled":  rule.get("enabled", True),
            "order":    rule.get("order", 1),
            "action":   rule.get("action", "allow"),
            "matching": matching,
        }
        if result_ids:
            body["apply_tags"] = result_ids

        try:
            r = mist_post(sid, f"/orgs/{org_id}/nacrules", body)
            if r.status_code in (200, 201):
                results["rules"].append({"name": name, "id": r.json().get("id"), "status": "created"})
            else:
                try:
                    err = r.json().get("detail", r.text[:120])
                except Exception:
                    err = r.text[:120]
                results["errors"].append(f"Rule '{name}': {err}")
                results["rules"].append({"name": name, "status": "error", "error": err})
        except Exception as e:
            results["errors"].append(f"Rule '{name}': {e}")
            results["rules"].append({"name": name, "status": "error", "error": str(e)})

    # ── Endpoints (usermacs) ─────────────────────────────────────────────────
    for ep in endpoints_payload:
        mac = ep.get("mac", "").lower().replace(":", "").replace("-", "")
        if not mac:
            continue

        if mac in existing_macs:
            results["endpoints"].append({"mac": mac, "name": ep.get("name", mac),
                                         "label": ep.get("label", ""),
                                         "status": "exists", "id": existing_macs[mac]})
            continue

        body = {
            "mac":    mac,
            "name":   ep.get("name", mac),
            "labels": [ep["label"]],
            "notes":  ep.get("notes") or f"Created by DPC→NAC converter — usage: {ep.get('usage', '')}",
        }
        if ep.get("role"):
            body["role"] = ep["role"]
        if ep.get("vlan"):
            try:
                body["vlan_id"] = int(ep["vlan"])
            except ValueError:
                body["vlan_id"] = ep["vlan"]
        try:
            r = mist_post(sid, f"/orgs/{org_id}/usermacs", body)
            if r.status_code in (200, 201):
                results["endpoints"].append({
                    "mac": mac, "name": ep.get("name", mac),
                    "label": ep["label"], "status": "created",
                    "id": r.json().get("id"),
                })
            else:
                try:
                    err = r.json().get("detail", r.text[:120])
                except Exception:
                    err = r.text[:120]
                results["errors"].append(f"Endpoint '{mac}': {err}")
                results["endpoints"].append({"mac": mac, "status": "error", "error": err})
        except Exception as e:
            results["errors"].append(f"Endpoint '{mac}': {e}")
            results["endpoints"].append({"mac": mac, "status": "error", "error": str(e)})

    return jsonify(results)



# ── Device Inventory routes ──────────────────────────────────────────────────

@app.route("/inventory/<org_id>")
def inventory(org_id):
    if not valid_uuid(org_id):
        return redirect(url_for("orgs"))
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))
    if not org_allowed(org_id):
        return redirect(url_for("orgs"))
    return render_template("inventory.html",
                           org_id=org_id,
                           user_name=_sessions[sid].get("user_name", ""))


@app.route("/api/inventory/<org_id>")
def api_inventory(org_id):
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    site_names = _fetch_site_names(sid, org_id)
    devices    = []
    for dtype in ("ap", "switch", "gateway"):
        try:
            raw     = mist_get(sid, f"/orgs/{org_id}/stats/devices?type={dtype}&fields=*&limit=1000&status=all")
            results = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
            for d in results:
                d["site_name"] = site_names.get(d.get("site_id", ""), "")
            devices.extend(results)
        except Exception as e:
            _log.warning("Inventory %s fetch failed: %s", dtype, e)

    # Available firmware versions per type for the upgrade picker
    avail_versions = {}
    for dtype in ("ap", "switch", "gateway"):
        try:
            raw = mist_get(sid, f"/orgs/{org_id}/devices/versions?type={dtype}")
            items = raw if isinstance(raw, list) else raw.get("results", [])
            avail_versions[dtype] = [
                v.get("version", v) if isinstance(v, dict) else str(v)
                for v in items if v
            ]
        except Exception:
            avail_versions[dtype] = []

    return jsonify({"devices": devices, "avail_versions": avail_versions})


@app.route("/api/upgrade/<org_id>", methods=["POST"])
def api_upgrade_devices(org_id):
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    data       = request.json or {}
    device_ids = data.get("device_ids", [])
    version    = (data.get("version") or "").strip()

    if not device_ids:
        return jsonify({"error": "No devices specified"}), 400
    if not version:
        return jsonify({"error": "No target version specified"}), 400

    actor = _sessions[sid].get("email", "unknown")
    _log.info("UPGRADE org=%s actor=%s count=%d version=%s ip=%s",
              org_id, actor, len(device_ids), version, request.remote_addr)

    try:
        r = mist_post(sid, f"/orgs/{org_id}/devices/upgrade", {
            "version":    version,
            "device_ids": device_ids,
            "enable_p2p": True,
        })
        if r.ok:
            return jsonify({"status": "ok", "count": len(device_ids), "version": version})
        return jsonify({"status": "error", "detail": r.text[:300]}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Network Health routes ─────────────────────────────────────────────────────

@app.route("/health/<org_id>")
def health(org_id):
    if not valid_uuid(org_id):
        return redirect(url_for("orgs"))
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))
    if not org_allowed(org_id):
        return redirect(url_for("orgs"))
    return render_template("health.html",
                           org_id=org_id,
                           user_name=_sessions[sid].get("user_name", ""))


def _fetch_sle(sid, org_id):
    """Fetch SLE for all three categories. Returns dict keyed by category."""
    end   = int(time.time())
    start = end - 86400
    sle   = {}
    for category in ("wifi", "wired", "wan"):
        try:
            raw = mist_get(sid, f"/orgs/{org_id}/insights/sites-sle?sle={category}&start={start}&end={end}")
            results = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
            sle[category] = results
        except Exception as e:
            sle[category] = []
            _log.warning("SLE %s fetch failed: %s", category, e)
    return sle


def _fetch_site_names(sid, org_id):
    """Return {site_id: site_name} for the org."""
    try:
        raw = mist_get(sid, f"/orgs/{org_id}/sites")
        sites = raw if isinstance(raw, list) else raw.get("results", [])
        return {s["id"]: s.get("name", s["id"]) for s in sites if s.get("id")}
    except Exception:
        return {}


@app.route("/api/health/<org_id>")
def api_health(org_id):
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    sle        = _fetch_sle(sid, org_id)
    site_names = _fetch_site_names(sid, org_id)

    # Active alarms — fetch all device types including chassis
    alarms = []
    seen_ids = set()
    alarm_queries = [
        f"/orgs/{org_id}/alarms/search?status=open&limit=100",
        f"/orgs/{org_id}/alarms/search?status=open&limit=100&group=infrastructure",
        f"/orgs/{org_id}/alarms/search?status=open&limit=100&group=marvis",
    ]
    for query in alarm_queries:
        try:
            raw     = mist_get(sid, query)
            results = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
            for a in results:
                aid = a.get("id") or f"{a.get('type')}-{a.get('timestamp')}-{a.get('site_id')}"
                if aid not in seen_ids:
                    seen_ids.add(aid)
                    alarms.append(a)
        except Exception as e:
            _log.warning("Alarms query failed (%s): %s", query, e)

    # Sort by severity then timestamp (most recent first)
    sev_order = {"critical": 0, "major": 1, "minor": 2, "warn": 3, "info": 4}
    alarms.sort(key=lambda a: (
        sev_order.get((a.get("severity") or "").lower(), 9),
        -(a.get("timestamp") or 0)
    ))

    marvis = [{
        "title":     a.get("type", "Alarm"),
        "site_name": a.get("site_name", ""),
        "severity":  a.get("severity", ""),
        "group":     a.get("group", ""),
        "hostnames": a.get("hostnames", []),
        "count":     a.get("count", 1),
        "timestamp": a.get("timestamp"),
    } for a in alarms]

    cloud_host  = _sessions[sid]["cloud_host"]
    manage_host = cloud_host.replace("api.", "manage.", 1)

    return jsonify({
        "sle":        sle,
        "site_names": site_names,
        "manage_host": manage_host,
        "marvis":     marvis,
    })


@app.route("/site/<org_id>/<site_id>")
def site_health(org_id, site_id):
    if not valid_uuid(org_id) or not valid_uuid(site_id):
        return redirect(url_for("orgs"))
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))
    if not org_allowed(org_id):
        return redirect(url_for("orgs"))
    return render_template("site_health.html",
                           org_id=org_id,
                           site_id=site_id,
                           user_name=_sessions[sid].get("user_name", ""))


@app.route("/api/site/<org_id>/<site_id>")
def api_site_health(org_id, site_id):
    if not valid_uuid(org_id) or not valid_uuid(site_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    sle_all    = _fetch_sle(sid, org_id)
    site_names = _fetch_site_names(sid, org_id)

    # Filter each category down to just this site
    sle = {cat: [s for s in sites if s.get("site_id") == site_id]
           for cat, sites in sle_all.items()}

    cloud_host  = _sessions[sid]["cloud_host"]
    manage_host = cloud_host.replace("api.", "manage.", 1)
    dashboard_url = f"https://{manage_host}/admin/?org_id={org_id}#!insights/wifi/{site_id}"

    return jsonify({
        "sle":           sle,
        "site_name":     site_names.get(site_id, site_id),
        "manage_host":   manage_host,
        "dashboard_url": dashboard_url,
    })


# ── Client lookup + Marvis client troubleshoot ───────────────────────────────

@app.route("/api/clients/<org_id>")
def api_clients(org_id):
    """Return recent wireless clients for the org (used to populate dropdown)."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    try:
        raw     = mist_get(sid, f"/orgs/{org_id}/clients/search?limit=1000&duration=1d")
        results = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
        clients = []
        seen    = set()
        for c in results:
            mac = (c.get("mac") or "").strip().lower()
            if not mac or mac in seen:
                continue
            seen.add(mac)
            hostname = _normalize_field(c.get("hostname")) or _normalize_field(c.get("username")) or ""
            clients.append({
                "mac":      mac,
                "hostname": hostname,
                "username": _normalize_field(c.get("username")),
                "ip":       _normalize_field(c.get("ip")),
                "site_id":  c.get("site_id", ""),
                "ssid":     _normalize_field(c.get("ssid")),
                "os":       _normalize_field(c.get("os")),
            })
        # Sort: named clients first, then by hostname
        clients.sort(key=lambda c: (0 if c["hostname"] else 1, c["hostname"].lower()))
        return jsonify({"clients": clients})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/troubleshoot-client/<org_id>")
def api_troubleshoot_client(org_id):
    """Run Marvis client troubleshoot for a specific MAC address."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    mac     = (request.args.get("mac") or "").strip()
    site_id = (request.args.get("site_id") or "").strip()

    if not mac:
        return jsonify({"error": "mac parameter required"}), 400

    try:
        path = f"/orgs/{org_id}/troubleshoot?mac={mac}"
        if site_id and valid_uuid(site_id):
            path += f"&site_id={site_id}"
        result = mist_get(sid, path)
        return jsonify(result if isinstance(result, dict) else {"results": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Troubleshooting routes ────────────────────────────────────────────────────

@app.route("/troubleshoot/<org_id>")
def troubleshoot(org_id):
    if not valid_uuid(org_id):
        return redirect(url_for("orgs"))
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))
    if not org_allowed(org_id):
        return redirect(url_for("orgs"))
    return render_template("troubleshoot.html",
                           org_id=org_id,
                           user_name=_sessions[sid].get("user_name", ""))


@app.route("/api/troubleshoot/<org_id>")
def api_troubleshoot(org_id):
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    end   = int(time.time())
    start = end - 7 * 86400

    # 7-day SLE trends — one API call per day per category (21 calls in parallel)
    _SKIP = {"site_id", "num_aps", "num_clients", "num_switches", "num_gateways"}

    def _day_avg(category, day_start, day_end):
        """Return org-wide average SLE score (0–100) for one category over one day."""
        try:
            raw     = mist_get(sid, f"/orgs/{org_id}/insights/sites-sle"
                                    f"?sle={category}&start={day_start}&end={day_end}")
            results = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
            vals = [v for site in results
                      for k, v in site.items()
                      if k not in _SKIP
                      and isinstance(v, (int, float))
                      and not isinstance(v, bool)
                      and 0 <= v <= 1]
            avg = round(sum(vals) / len(vals) * 100, 1) if vals else None
            _log.info("SLE day %s %s→%s: %d sites, %d vals → %s",
                      category, day_start, day_end, len(results), len(vals), avg)
            return avg
        except Exception as e:
            _log.warning("SLE day_avg %s [%s-%s] failed: %s", category, day_start, day_end, e)
            return None

    days = [(start + i * 86400, start + (i + 1) * 86400) for i in range(7)]
    trends = {cat: [None] * 7 for cat in ("wifi", "wired", "wan")}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(_day_avg, cat, ds, de): (cat, idx)
            for idx, (ds, de) in enumerate(days)
            for cat in ("wifi", "wired", "wan")
        }
        for fut in as_completed(futures):
            cat, idx = futures[fut]
            trends[cat][idx] = fut.result()

    # Marvis Actions — open Marvis-group alarms
    marvis_open = []
    try:
        raw = mist_get(sid, f"/orgs/{org_id}/alarms/search?group=marvis&status=open&limit=100")
        results = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
        marvis_open = [{
            "title":     a.get("type", "Action"),
            "site_id":   a.get("site_id", ""),
            "site_name": a.get("site_name", ""),
            "severity":  a.get("severity", ""),
            "hostnames": a.get("hostnames", []),
            "count":     a.get("count", 1),
            "timestamp": a.get("timestamp"),
        } for a in results]
    except Exception as e:
        _log.warning("Marvis open fetch failed: %s", e)

    # AI Validated Events — resolved Marvis-group alarms
    marvis_resolved = []
    try:
        raw = mist_get(sid, f"/orgs/{org_id}/alarms/search?group=marvis&status=resolved&limit=100")
        results = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
        marvis_resolved = [{
            "title":          a.get("type", "Event"),
            "site_id":        a.get("site_id", ""),
            "site_name":      a.get("site_name", ""),
            "severity":       a.get("severity", ""),
            "hostnames":      a.get("hostnames", []),
            "count":          a.get("count", 1),
            "timestamp":      a.get("timestamp"),
            "resolved_time":  a.get("resolved_time") or a.get("updated_time"),
        } for a in results]
    except Exception as e:
        _log.warning("Marvis resolved fetch failed: %s", e)

    # Enrich with site names where missing
    site_names = _fetch_site_names(sid, org_id)
    for item in marvis_open + marvis_resolved:
        if not item.get("site_name") and item.get("site_id"):
            item["site_name"] = site_names.get(item["site_id"], "")

    return jsonify({
        "trends":          trends,   # {wifi: [avg0..avg6], wired: [...], wan: [...]}
        "ts_start":        start,    # epoch of day 0
        "marvis_open":     marvis_open,
        "marvis_resolved": marvis_resolved,
    })


# ── Best Practices routes ─────────────────────────────────────────────────────

GOLDEN_RF_TEMPLATE = {
    "name": "Suggested Baseline Settings",
    "country_code": "US",
    # 2.4 GHz — "auto" mode: allow RRM to disable the band if needed
    "band_24": {
        "allow_rrm_disable": True,
        "preamble":  "short",
        "power_min": 4,
        "power_max": 8,
        "ant_gain":  0,
        # channels omitted → automatic
    },
    # 5 GHz
    "band_5": {
        "bandwidth": 20,
        "power_min": 6,
        "power_max": 10,
        "ant_gain":  0,
    },
    # 6 GHz
    "band_6": {
        "bandwidth": 40,
        "power_min": 8,
        "power_max": 17,
        "ant_gain":  0,
    },
    # Dual-band radios: use 2.4 GHz on both
    "band_24_usage": "24",
}

BP_FILTERS = [
    {
        "field":   "arp_filter",
        "label":   "ARP Filter",
        "tooltip": (
            "Smart ARP filtering: the AP answers ARP requests on behalf of "
            "wireless clients, eliminating broadcast ARP traffic on the SSID. "
            "Reduces airtime waste and improves performance on high-density networks."
        ),
    },
    {
        "field":   "limit_bcast",
        "label":   "Broadcast / Multicast Filter",
        "tooltip": (
            "Limits broadcast and multicast packets forwarded to wireless clients. "
            "Suppresses chatty protocols (SSDP, NetBIOS, etc.) that consume airtime "
            "without benefiting most clients."
        ),
    },
    {
        "field":   "limit_probe_response",
        "label":   "Limit Probe Response",
        "tooltip": (
            "Ignores 802.11 broadcast probe requests — probes sent without a specific "
            "SSID. The AP only responds to directed probes for this SSID, reducing "
            "unnecessary probe response overhead and improving channel efficiency."
        ),
    },
    {
        "field":      "no_legacy",
        "label":      "High Density Data Rates",
        "standalone": True,
        "tooltip": (
            "Disables 802.11b (1/2/5.5/11 Mbps) legacy data rates on 2.4 GHz. "
            "Removing these rates eliminates the slowest transmissions that consume "
            "the most airtime, improving overall throughput and reducing the DIFS/SIFS "
            "overhead for all clients on the SSID."
        ),
    },
    {
        "field":      "block_blacklist_clients",
        "label":      "Prevent Banned Clients",
        "standalone": True,
        "tooltip": (
            "Prevents clients on the org's banned/blacklisted client list from "
            "associating to this SSID. When enabled, any client whose MAC address "
            "appears in the banned clients list will be denied association, even if "
            "they have valid credentials."
        ),
    },
]


@app.route("/bestpractices/<org_id>")
def bestpractices(org_id):
    if not valid_uuid(org_id):
        return redirect(url_for("orgs"))
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))
    if not org_allowed(org_id):
        return redirect(url_for("orgs"))
    return render_template("bestpractices.html",
                           org_id=org_id,
                           user_name=_sessions[sid].get("user_name", ""))


@app.route("/api/bestpractices/<org_id>")
def api_bestpractices(org_id):
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    def _parse_wlans(raw_list, scope, scope_id, site_name=""):
        out = []
        for w in (raw_list if isinstance(raw_list, list) else raw_list.get("results", [])):
            wlan_id = w.get("id", "")
            if not wlan_id:
                continue
            out.append({
                "id":                        wlan_id,
                "ssid":                      w.get("ssid", "Unnamed"),
                "enabled":                   w.get("enabled", True),
                "arp_filter":                bool(w.get("arp_filter", False)),
                "limit_bcast":               bool(w.get("limit_bcast", False)),
                "limit_probe_response":      bool(w.get("limit_probe_response", False)),
                "no_legacy":                 bool(w.get("no_legacy", False)),
                "block_blacklist_clients": bool(w.get("block_blacklist_clients", False)),
                "scope":                     scope,
                "scope_id":                  scope_id,
                "site_name":                 site_name,
            })
        return out

    def _fetch_site_wlans(site_id, site_name):
        try:
            raw = mist_get(sid, f"/sites/{site_id}/wlans")
            return _parse_wlans(raw, "site", site_id, site_name)
        except Exception as e:
            _log.warning("Site WLAN fetch failed %s: %s", site_id, e)
            return []

    try:
        result   = []
        seen_ids = set()

        # 1. Org-level WLAN templates
        try:
            raw = mist_get(sid, f"/orgs/{org_id}/wlans")
            for w in _parse_wlans(raw, "org", org_id):
                if w["id"] not in seen_ids:
                    seen_ids.add(w["id"])
                    result.append(w)
        except Exception as e:
            _log.warning("Org WLAN fetch failed: %s", e)

        # 2. Site-level WLANs — fetch all sites in parallel
        site_names = _fetch_site_names(sid, org_id)
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {
                pool.submit(_fetch_site_wlans, sid_val, sname): sid_val
                for sid_val, sname in site_names.items()
            }
            for fut in as_completed(futures):
                for w in fut.result():
                    if w["id"] not in seen_ids:
                        seen_ids.add(w["id"])
                        result.append(w)

        result.sort(key=lambda w: (w["site_name"].lower(), w["ssid"].lower()))

        # 3. Network template checks — DPC rules + DNS/NTP (single fetch per template)
        def _check_template(tmpl):
            tmpl_id = tmpl.get("id")
            if not tmpl_id:
                return None
            try:
                detail      = mist_get(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}")
                rules       = detail.get("port_usages", {}).get("dynamic", {}).get("rules", [])
                ntp_servers = detail.get("ntp_servers") or []
                dns_servers = detail.get("dns_servers") or []
                return {
                    "id":          tmpl_id,
                    "name":        detail.get("name", tmpl.get("name", tmpl_id)),
                    "dpc_rules":   len(rules),
                    "has_dpc":     len(rules) > 0,
                    "ntp_servers": ntp_servers,
                    "dns_servers": dns_servers,
                    "has_ntp":     len(ntp_servers) > 0,
                    "has_dns":     len(dns_servers) > 0,
                }
            except Exception:
                return None

        tmpl_details  = []
        dpc_info      = {"has_rules": False, "template_count": 0, "rule_count": 0, "templates": []}
        dns_ntp_info  = {"total": 0, "ntp_count": 0, "dns_count": 0, "templates": []}
        try:
            raw_tmpls = mist_get(sid, f"/orgs/{org_id}/networktemplates")
            tmpls     = raw_tmpls if isinstance(raw_tmpls, list) else raw_tmpls.get("results", [])
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(_check_template, t): t for t in tmpls}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        tmpl_details.append(res)
            tmpl_details.sort(key=lambda t: t["name"].lower())

            dpc_with_rules = [t for t in tmpl_details if t["has_dpc"]]
            dpc_info = {
                "has_rules":      len(dpc_with_rules) > 0,
                "template_count": len(dpc_with_rules),
                "rule_count":     sum(t["dpc_rules"] for t in dpc_with_rules),
                "templates":      [{"name": t["name"], "rule_count": t["dpc_rules"]}
                                   for t in dpc_with_rules],
            }

            dns_ntp_info = {
                "total":     len(tmpl_details),
                "ntp_count": sum(1 for t in tmpl_details if t["has_ntp"]),
                "dns_count": sum(1 for t in tmpl_details if t["has_dns"]),
                "templates": [{"name":        t["name"],
                               "has_ntp":     t["has_ntp"],
                               "ntp_servers": t["ntp_servers"],
                               "has_dns":     t["has_dns"],
                               "dns_servers": t["dns_servers"]}
                              for t in tmpl_details],
            }
        except Exception as e:
            _log.warning("Network template check failed: %s", e)
            dns_ntp_info = {"total": 0, "ntp_count": 0, "dns_count": 0,
                            "templates": [], "error": str(e)}

        # 3b. WAN (gateway) template DNS/NTP check
        wan_dns_ntp_info = {}
        try:
            raw_wan = mist_get(sid, f"/orgs/{org_id}/gatewaytemplates")
            wan_tmpls = raw_wan if isinstance(raw_wan, list) else raw_wan.get("results", [])

            def _check_wan_template(tmpl):
                tmpl_id = tmpl.get("id")
                if not tmpl_id:
                    return None
                try:
                    detail      = mist_get(sid, f"/orgs/{org_id}/gatewaytemplates/{tmpl_id}")
                    ntp_servers = detail.get("ntp_servers") or []
                    dns_servers = detail.get("dns_servers") or []
                    return {
                        "name":        detail.get("name", tmpl.get("name", tmpl_id)),
                        "ntp_servers": ntp_servers,
                        "dns_servers": dns_servers,
                        "has_ntp":     len(ntp_servers) > 0,
                        "has_dns":     len(dns_servers) > 0,
                    }
                except Exception:
                    return None

            wan_details = []
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(_check_wan_template, t): t for t in wan_tmpls}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        wan_details.append(res)
            wan_details.sort(key=lambda t: t["name"].lower())

            wan_dns_ntp_info = {
                "total":     len(wan_details),
                "ntp_count": sum(1 for t in wan_details if t["has_ntp"]),
                "dns_count": sum(1 for t in wan_details if t["has_dns"]),
                "templates": wan_details,
            }
        except Exception as e:
            _log.warning("WAN template DNS/NTP check failed: %s", e)
            wan_dns_ntp_info = {"total": 0, "ntp_count": 0, "dns_count": 0,
                                "templates": [], "error": str(e)}

        # 4. Subscriptions / License check + Access Assurance — fetch in parallel
        WARN_DAYS = 90
        now = int(time.time())
        licenses_info = {}
        aa_info       = {}

        def _fetch_subs():
            return mist_get(sid, f"/orgs/{org_id}/subscriptions")

        def _fetch_setting():
            return mist_get(sid, f"/orgs/{org_id}/setting")

        def _fetch_nacrules():
            return mist_get(sid, f"/orgs/{org_id}/nacrules")

        def _fetch_rftemplates():
            return mist_get(sid, f"/orgs/{org_id}/rftemplates")

        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                f_subs    = pool.submit(_fetch_subs)
                f_setting = pool.submit(_fetch_setting)
                f_nac     = pool.submit(_fetch_nacrules)
                f_rf      = pool.submit(_fetch_rftemplates)

            subs_raw = f_subs.result()
            subs = subs_raw if isinstance(subs_raw, list) else subs_raw.get("results", [])

            processed = []
            for s in subs:
                end = s.get("end_time", 0)
                if not end or end > now + WARN_DAYS * 86400:
                    st = "active"
                elif end > now:
                    st = "expiring"
                else:
                    st = "expired"
                processed.append({
                    "type":               s.get("type", "Unknown"),
                    "quantity":           s.get("quantity", 0),
                    "remaining_quantity": s.get("remaining_quantity"),
                    "end_time":           end,
                    "status":             st,
                })
            processed.sort(key=lambda s: (s["status"] != "expired", s["status"] != "expiring", s["type"].lower()))

            licenses_info = {
                "total":    len(processed),
                "active":   sum(1 for s in processed if s["status"] == "active"),
                "expiring": sum(1 for s in processed if s["status"] == "expiring"),
                "expired":  sum(1 for s in processed if s["status"] == "expired"),
                "subscriptions": processed,
            }

            # Access Assurance — look for AA subscription type
            aa_sub = next(
                (s for s in processed if "ACCESS_ASSURANCE" in s["type"].upper() or s["type"].upper() in ("SUB_AA",)),
                None
            )
            aa_subscribed = aa_sub is not None and aa_sub["status"] != "expired"

            aa_configured = False
            aa_nac_rules  = 0
            aa_setting    = {}

            try:
                setting   = f_setting.result()
                mist_nac  = setting.get("mist_nac", {})
                aa_setting = {
                    "enabled":    bool(mist_nac.get("enabled", False)),
                    "server_cert_id": mist_nac.get("server_cert_id"),
                }
                if mist_nac.get("enabled"):
                    aa_configured = True
            except Exception as e:
                _log.warning("AA setting fetch failed: %s", e)

            try:
                nac_raw    = f_nac.result()
                nac_rules  = nac_raw if isinstance(nac_raw, list) else nac_raw.get("results", [])
                aa_nac_rules = len(nac_rules)
                if aa_nac_rules > 0:
                    aa_configured = True
            except Exception as e:
                _log.warning("NAC rules fetch failed: %s", e)

            aa_info = {
                "subscribed":  aa_subscribed,
                "configured":  aa_configured,
                "nac_rules":   aa_nac_rules,
                "nac_enabled": aa_setting.get("enabled", False),
                "subscription": aa_sub,
            }

        except Exception as e:
            _log.warning("License/AA check failed: %s", e)
            licenses_info = {"error": str(e), "subscriptions": []}
            aa_info       = {"error": str(e)}

        # 5. RF template — check for "Suggested Baseline Settings"
        rf_info = {}
        try:
            rf_raw  = f_rf.result()
            rf_list = rf_raw if isinstance(rf_raw, list) else rf_raw.get("results", [])
            golden  = next((t for t in rf_list
                            if t.get("name", "").lower() == "suggested baseline settings"), None)
            rf_info = {
                "exists": golden is not None,
                "id":     golden.get("id")   if golden else None,
                "name":   golden.get("name") if golden else None,
            }
        except Exception as e:
            _log.warning("RF template check failed: %s", e)
            rf_info = {"exists": False, "error": str(e)}

        return jsonify({
            "wlans":        result,
            "filters":      BP_FILTERS,
            "dpc":          dpc_info,
            "dns_ntp":      dns_ntp_info,
            "wan_dns_ntp":  wan_dns_ntp_info,
            "licenses":     licenses_info,
            "aa":           aa_info,
            "rf":           rf_info,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/bestpractices/<org_id>/<wlan_id>", methods=["POST"])
def api_bestpractices_apply(org_id, wlan_id):
    """Confirm or enable a best-practice filter on one WLAN."""
    if not valid_uuid(org_id) or not valid_uuid(wlan_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    data     = request.json or {}
    field    = data.get("field", "")
    scope    = data.get("scope", "org")     # "org" or "site"
    scope_id = data.get("scope_id", org_id)

    if field not in {f["field"] for f in BP_FILTERS}:
        return jsonify({"error": f"Unknown field: {field}"}), 400
    if scope not in ("org", "site"):
        return jsonify({"error": "Invalid scope"}), 400
    if scope == "site" and not valid_uuid(scope_id):
        return jsonify({"error": "Invalid scope_id"}), 400

    # Build API paths based on scope
    if scope == "site":
        get_path = f"/sites/{scope_id}/wlans/{wlan_id}"
        put_path = f"/sites/{scope_id}/wlans/{wlan_id}"
    else:
        get_path = f"/orgs/{org_id}/wlans/{wlan_id}"
        put_path = f"/orgs/{org_id}/wlans/{wlan_id}"

    try:
        wlan    = mist_get(sid, get_path)
        current = bool(wlan.get(field, False))

        if current:
            return jsonify({"status": "already_enabled", "field": field})

        actor = _sessions[sid].get("email", "unknown")
        _log.info("BESTPRACTICE scope=%s scope_id=%s wlan=%s ssid=%s field=%s actor=%s ip=%s",
                  scope, scope_id, wlan_id, wlan.get("ssid", ""), field, actor, request.remote_addr)

        wlan[field] = True
        r = mist_put(sid, put_path, wlan)
        if r.ok:
            return jsonify({"status": "applied", "field": field})
        try:
            detail = r.json().get("detail", r.text[:300])
        except Exception:
            detail = r.text[:300]
        return jsonify({"status": "error", "detail": detail}), r.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/datarates/<org_id>")
def api_datarates(org_id):
    """Return per-WLAN data rate settings by fetching full WLAN objects."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    # Only fetch org-level WLANs — site-level WLANs without a template are flagged, not fixed
    stubs = []
    try:
        for w in (mist_get(sid, f"/orgs/{org_id}/wlans") or []):
            if w.get("id"):
                stubs.append((w["id"], w.get("template_id") or ""))
    except Exception as e:
        _log.warning("org wlan list failed: %s", e)

    # Also collect site-level WLANs (for display only — no fix applied)
    try:
        sites = mist_get(sid, f"/orgs/{org_id}/sites") or []
    except Exception:
        sites = []

    def _site_stubs(site):
        try:
            wlans = mist_get(sid, f"/sites/{site['id']}/wlans") or []
            return [(w["id"], "", site["id"], site.get("name", ""))
                    for w in wlans if w.get("id") and not w.get("template_id")]
        except Exception:
            return []

    site_stubs = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for result in as_completed([ex.submit(_site_stubs, s) for s in sites]):
            site_stubs.extend(result.result())

    # Fetch each org WLAN individually to get full rateset
    def _fetch_wlan(wlan_id, template_id):
        try:
            w = mist_get(sid, f"/orgs/{org_id}/wlans/{wlan_id}")
            rateset = w.get("rateset", {})
            bands   = w.get("bands", [])
            band_24 = rateset.get("24", {}).get("template", "compatible")
            band_5  = rateset.get("5",  {}).get("template", "compatible")
            band_6  = rateset.get("6",  {}).get("template", "compatible")
            _log.info("DATARATES_FETCH wlan=%s ssid=%s rateset=%s", wlan_id, w.get("ssid"), rateset)
            return {
                "id":          wlan_id,
                "ssid":        w.get("ssid", "Unnamed"),
                "enabled":     w.get("enabled", True),
                "scope":       "org",
                "scope_id":    org_id,
                "site_name":   "",
                "template_id": template_id,
                "in_template": bool(template_id),
                "band_24":     band_24,
                "band_5":      band_5,
                "band_6":      band_6,
                "bands":       bands,
                "high_density": all(
                    rateset.get(b, {}).get("template", "compatible") == "high-density"
                    for b in bands if b in rateset
                ) and bool(rateset),
            }
        except Exception as e:
            _log.warning("wlan detail fetch failed %s: %s", wlan_id, e)
            return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = [ex.submit(_fetch_wlan, wlan_id, tmpl_id) for wlan_id, tmpl_id in stubs]
        wlans = [r.result() for r in as_completed(futures) if r.result()]

    # Add site-only WLANs (no template) as display-only entries
    for wlan_id, _, site_id, site_name in site_stubs:
        try:
            w = mist_get(sid, f"/sites/{site_id}/wlans/{wlan_id}")
            rateset = w.get("rateset", {})
            bands   = w.get("bands", [])
            wlans.append({
                "id":          wlan_id,
                "ssid":        w.get("ssid", "Unnamed"),
                "enabled":     w.get("enabled", True),
                "scope":       "site",
                "scope_id":    site_id,
                "site_name":   site_name,
                "template_id": "",
                "in_template": False,
                "band_24":     rateset.get("24", {}).get("template", "compatible"),
                "band_5":      rateset.get("5",  {}).get("template", "compatible"),
                "band_6":      rateset.get("6",  {}).get("template", "compatible"),
                "bands":       bands,
                "high_density": False,
            })
        except Exception:
            pass

    seen = set()
    unique = []
    for w in wlans:
        if w["id"] not in seen:
            seen.add(w["id"])
            unique.append(w)

    return jsonify({"wlans": unique})


@app.route("/api/datarates/<org_id>/<wlan_id>", methods=["POST"])
def api_datarates_apply(org_id, wlan_id):
    """Set a WLAN's data rates to high-density on all active bands."""
    if not valid_uuid(org_id) or not valid_uuid(wlan_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    data = request.json or {}
    # Only allow changes to org-level template WLANs
    if data.get("scope") == "site":
        return jsonify({"error": "Site-level WLANs must be managed via a WLAN template"}), 400

    path = f"/orgs/{org_id}/wlans/{wlan_id}"

    try:
        wlan    = mist_get(sid, path)
        bands   = wlan.get("bands", ["24", "5"])
        rateset = wlan.get("rateset", {})

        # Build updated rateset — set high-density on all active bands
        new_rateset = dict(rateset)
        for b in bands:
            band_cfg = dict(new_rateset.get(b, {}))
            band_cfg["template"] = "high-density"
            new_rateset[b] = band_cfg

        # Merge into full WLAN object for PUT (Mist doesn't support PATCH on WLANs)
        wlan["rateset"] = new_rateset

        actor = _sessions[sid].get("email", "unknown")
        _log.info("DATARATES wlan=%s ssid=%s new_rateset=%s actor=%s ip=%s",
                  wlan_id, wlan.get("ssid", ""), new_rateset, actor, request.remote_addr)

        r = mist_put(sid, path, wlan)
        _log.info("DATARATES PUT status=%s body=%s", r.status_code, r.text[:500])
        if r.ok:
            return jsonify({"status": "applied"})
        try:
            detail = r.json().get("detail", r.text[:300])
        except Exception:
            detail = r.text[:300]
        return jsonify({"status": "error", "detail": detail}), r.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/wlantemplates/<org_id>")
def api_list_wlantemplates(org_id):
    """Return org wlantemplates for the template picker."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403
    try:
        raw = mist_get(sid, f"/orgs/{org_id}/templates")
        templates = [{"id": t["id"], "name": t.get("name", t["id"])}
                     for t in (raw if isinstance(raw, list) else raw.get("results", []))
                     if t.get("id")]
        return jsonify({"templates": templates})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/convert_wlan/<org_id>", methods=["POST"])
def api_convert_wlan(org_id):
    """
    Convert a site-level WLAN into an existing org WLAN template.
    Steps:
      1. Fetch full site WLAN config
      2. Ensure the chosen template applies to this site
      3. Create an org-level WLAN with the same config under that template,
         with rateset set to high-density on all active bands
      4. Delete the original site-level WLAN
    """
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    data      = request.json or {}
    wlan_id   = data.get("wlan_id", "")
    site_id   = data.get("site_id", "")
    site_name = data.get("site_name", site_id)
    tmpl_id   = data.get("template_id", "")

    if not valid_uuid(wlan_id) or not valid_uuid(site_id):
        return jsonify({"error": "Invalid wlan_id or site_id"}), 400

    try:
        # 1. Fetch full site WLAN
        wlan  = mist_get(sid, f"/sites/{site_id}/wlans/{wlan_id}")
        ssid  = wlan.get("ssid", "Unnamed")
        bands = wlan.get("bands", ["24", "5"])

        # 2. Create a new template named "{ssid} ({site_name})"
        tmpl_name = f"{ssid} ({site_name})"
        tmpl_resp = mist_post(sid, f"/orgs/{org_id}/templates", {
            "name":    tmpl_name,
            "applies": {"site_ids": [site_id], "sitegroup_ids": []},
        })
        if not tmpl_resp.ok:
            return jsonify({"error": f"Failed to create template: {tmpl_resp.text[:300]}"}), tmpl_resp.status_code
        tmpl_id   = tmpl_resp.json().get("id")
        tmpl_name = tmpl_resp.json().get("name", tmpl_name)

        # 3. Build org WLAN — copy config as-is, strip site-specific fields only
        _strip   = {"id", "created_time", "modified_time", "site_id", "for_site",
                    "template_id", "org_id", "portal_template_url"}
        org_wlan = {k: v for k, v in wlan.items() if k not in _strip}
        org_wlan["template_id"] = tmpl_id

        wlan_resp = mist_post(sid, f"/orgs/{org_id}/wlans", org_wlan)
        if not wlan_resp.ok:
            return jsonify({"error": f"Failed to create org WLAN: {wlan_resp.text[:200]}"}), wlan_resp.status_code
        new_wlan_id = wlan_resp.json().get("id")

        # 4. Disable the original site WLAN (preserve config, just turn it off)
        wlan["enabled"] = False
        dis_resp = mist_put(sid, f"/sites/{site_id}/wlans/{wlan_id}", wlan)
        if not dis_resp.ok:
            _log.warning("Failed to disable site WLAN %s: %s", wlan_id, dis_resp.text[:200])

        _log.info("CONVERT_WLAN ssid=%s site=%s new_wlan=%s tmpl=%s actor=%s",
                  ssid, site_id, new_wlan_id, tmpl_id, _sessions[sid].get("email", "unknown"))

        return jsonify({
            "status":        "converted",
            "ssid":          ssid,
            "template_id":   tmpl_id,
            "template_name": tmpl_name,
            "new_wlan_id":   new_wlan_id,
        })

    except Exception as e:
        _log.exception("CONVERT_WLAN error: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/rftemplate/<org_id>", methods=["POST"])
def api_create_rf_template(org_id):
    """Create the Suggested Baseline Settings RF template for the org."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    try:
        # Check if it already exists
        rf_raw  = mist_get(sid, f"/orgs/{org_id}/rftemplates")
        rf_list = rf_raw if isinstance(rf_raw, list) else rf_raw.get("results", [])
        existing = next((t for t in rf_list
                         if t.get("name", "").lower() == "suggested baseline settings"), None)
        if existing:
            return jsonify({"status": "already_exists", "id": existing["id"], "name": existing["name"]})

        actor = _sessions[sid].get("email", "unknown")
        _log.info("RF_TEMPLATE_CREATE org=%s actor=%s ip=%s", org_id, actor, request.remote_addr)

        r = mist_post(sid, f"/orgs/{org_id}/rftemplates", GOLDEN_RF_TEMPLATE)
        if r.ok:
            created = r.json()
            return jsonify({"status": "created", "id": created.get("id"), "name": created.get("name")})
        try:
            detail = r.json().get("detail", r.text[:300])
        except Exception:
            detail = r.text[:300]
        return jsonify({"status": "error", "detail": detail}), r.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False, port=5001)
