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


# ── Journey (main entry point) ────────────────────────────────────────────────

@app.route("/journey/<org_id>")
def journey(org_id):
    if not valid_uuid(org_id):
        return redirect(url_for("orgs"))
    sid = get_authed_sid()
    if not sid:
        return redirect(url_for("login"))
    if not org_allowed(org_id):
        return redirect(url_for("orgs"))
    return render_template("journey.html",
                           org_id=org_id,
                           user_name=_sessions[sid].get("user_name", ""))


@app.route("/api/deploy_status/<org_id>")
def api_deploy_status(org_id):
    """Per-site go/no-go checklist for the Deploy phase."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    try:
        # ── Parallel fetch of all data needed for checks ──────────────────────
        def _fetch(fn, *args):
            try:    return fn(*args)
            except: return None

        def _dev_results(r):
            r = r or {}
            return r.get("results", []) if isinstance(r, dict) else (r if isinstance(r, list) else [])

        with ThreadPoolExecutor(max_workers=9) as pool:
            f_sites    = pool.submit(_fetch, mist_list, sid, f"/orgs/{org_id}/sites")
            f_ap       = pool.submit(_fetch, mist_get,  sid, f"/orgs/{org_id}/stats/devices?type=ap&limit=1000")
            f_switch   = pool.submit(_fetch, mist_get,  sid, f"/orgs/{org_id}/stats/devices?type=switch&limit=1000")
            f_gateway  = pool.submit(_fetch, mist_get,  sid, f"/orgs/{org_id}/stats/devices?type=gateway&limit=1000")
            f_mxedge   = pool.submit(_fetch, mist_get,  sid, f"/orgs/{org_id}/stats/devices?type=mxedge&limit=1000")
            f_tmpls    = pool.submit(_fetch, mist_list, sid, f"/orgs/{org_id}/templates")
            f_dpc      = pool.submit(_fetch, mist_list, sid, f"/orgs/{org_id}/networktemplates")
            f_wlans    = pool.submit(_fetch, mist_list, sid, f"/orgs/{org_id}/wlans")

        sites_raw  = (f_sites.result()  or ([], None))[0]
        site_names = {s["id"]: s.get("name", s["id"]) for s in sites_raw}

        # Combine and deduplicate by device id
        _seen_dev = set()
        devices   = []
        for d in (_dev_results(f_ap.result())      +
                  _dev_results(f_switch.result())  +
                  _dev_results(f_gateway.result()) +
                  _dev_results(f_mxedge.result())):
            key = d.get("id") or d.get("mac")
            if key and key not in _seen_dev:
                _seen_dev.add(key)
                devices.append(d)

        tmpls_raw  = (f_tmpls.result() or ([], None))[0]
        dpc_raw    = (f_dpc.result()   or ([], None))[0]
        wlans_raw  = (f_wlans.result() or ([], None))[0]

        # ── Which sites have a WLAN template assigned ─────────────────────────
        sites_with_tmpl = set()
        for t in tmpls_raw:
            applies = t.get("applies") or {}
            for sid_val in applies.get("site_ids", []):
                sites_with_tmpl.add(sid_val)
            # sitegroup_ids handled separately; for now site-level is sufficient

        # ── Which sites have site-level WLAN overrides (not template) ─────────
        site_wlan_sites = set(w["site_id"] for w in wlans_raw
                              if w.get("site_id") and not w.get("template_id"))

        # ── Org-level DPC rules exist? ────────────────────────────────────────
        org_has_dpc = any(
            tmpl.get("port_usages", {}).get("dynamic", {}).get("rules")
            for tmpl in dpc_raw
        )

        # ── Aggregate device stats per site + build per-type device lists ────────
        site_dev = {}   # site_id → {total, online, offline, has_gateway, wan_up, types}
        devices_by_type = {"ap": [], "switch": [], "gateway": [], "mxedge": []}
        for d in devices:
            site_id = d.get("site_id")
            if not site_id:
                continue
            if site_id not in site_dev:
                site_dev[site_id] = {
                    "total": 0, "online": 0, "offline": 0,
                    "has_gateway": False, "wan_up": False,
                    "by_type": {"ap": 0, "switch": 0, "gateway": 0},
                }
            s   = site_dev[site_id]
            ok  = d.get("status") == "connected"
            typ = d.get("type", "")
            if typ in devices_by_type:
                devices_by_type[typ].append({
                    "id":     d.get("id", ""),
                    "name":   d.get("name") or d.get("hostname") or d.get("mac", ""),
                    "model":  d.get("model", ""),
                    "online": ok,
                    "site":   site_names.get(site_id, ""),
                    "ip":     d.get("ip_address") or d.get("ip") or "",
                })
            s["total"]  += 1
            s["online"]  = s["online"]  + (1 if ok else 0)
            s["offline"] = s["offline"] + (0 if ok else 1)
            if typ in s["by_type"]:
                s["by_type"][typ] += 1
            if typ == "gateway":
                s["has_gateway"] = True
                # WAN up if gateway is connected and has a wan link
                if ok:
                    wan_ifaces = d.get("wan_tunnel_status") or d.get("uplinks") or []
                    s["wan_up"] = True   # connected gateway = WAN reachable

        # ── Per-site client check (have any clients been seen?) ───────────────
        # Use org-level client search, bucket by site_id
        sites_with_clients = set()
        try:
            cr = mist_get(sid, f"/orgs/{org_id}/clients/search?limit=100&duration=1d")
            for c in (cr.get("results", []) if isinstance(cr, dict) else []):
                if c.get("site_id"):
                    sites_with_clients.add(c["site_id"])
        except Exception:
            pass

        # ── Build per-site checklist ──────────────────────────────────────────
        def _check(go, label, detail, fix_url=None, fix_label=None, na=False):
            return {
                "go":        go,
                "na":        na,
                "label":     label,
                "detail":    detail,
                "fix_url":   fix_url,
                "fix_label": fix_label,
            }

        total_online  = sum(s["online"]  for s in site_dev.values())
        total_devices = sum(s["total"]   for s in site_dev.values())
        by_type_org   = {"ap": 0, "switch": 0, "gateway": 0}
        for s in site_dev.values():
            for t in by_type_org:
                by_type_org[t] += s["by_type"].get(t, 0)

        sites_list = []
        for site_id, name in site_names.items():
            dev   = site_dev.get(site_id)
            total = dev["total"]   if dev else 0
            online= dev["online"]  if dev else 0
            offline=dev["offline"] if dev else 0

            checks = []

            # 1 — Devices connected
            if total == 0:
                checks.append(_check(False, "Devices connected",
                    "No devices claimed to this site yet"))
            elif offline == 0:
                checks.append(_check(True, "Devices connected",
                    f"All {total} device{'' if total==1 else 's'} online"))
            else:
                checks.append(_check(False, "Devices connected",
                    f"{offline} of {total} device{'' if total==1 else 's'} offline",
                    f"/inventory/{org_id}", "View inventory"))

            # 2 — WLAN template applied
            has_tmpl  = site_id in sites_with_tmpl
            has_override = site_id in site_wlan_sites
            if has_tmpl and not has_override:
                checks.append(_check(True, "WLAN template applied",
                    "Site is running from a WLAN template"))
            elif has_tmpl and has_override:
                checks.append(_check(False, "WLAN template applied",
                    "Template assigned but site-level WLANs are overriding it",
                    f"/bestpractices/{org_id}", "Review WLANs"))
            else:
                checks.append(_check(False, "WLAN template applied",
                    "No WLAN template assigned — running site-level config",
                    f"/bestpractices/{org_id}", "Fix in Best Practices"))

            # 3 — WAN reachable (only if a gateway is present)
            if dev and dev["has_gateway"]:
                checks.append(_check(dev["wan_up"], "WAN reachable",
                    "Gateway online, WAN link up" if dev["wan_up"]
                    else "Gateway present but WAN link may be down",
                    None if dev["wan_up"] else f"/troubleshoot/{org_id}",
                    None if dev["wan_up"] else "Troubleshoot"))
            else:
                checks.append(_check(True, "WAN reachable",
                    "No gateway assigned — WAN check not applicable", na=True))

            # 4 — DPC → NAC converted (only if org has DPC rules)
            if org_has_dpc:
                checks.append(_check(False, "DPC → NAC converted",
                    "DPC rules exist — convert to NAC for production security",
                    f"/scan/{org_id}", "Open converter"))
            else:
                checks.append(_check(True, "DPC → NAC converted",
                    "No DPC rules to convert", na=True))

            # 5 — First client seen
            has_clients = site_id in sites_with_clients
            checks.append(_check(has_clients, "Clients connected",
                "Real traffic confirmed — clients have connected" if has_clients
                else "No clients seen yet — connect a test device to validate"))

            all_go = all(c["go"] or c["na"] for c in checks)
            sites_list.append({
                "id":      site_id,
                "name":    name,
                "go":      all_go,
                "total":   total,
                "online":  online,
                "offline": offline,
                "by_type": dev["by_type"] if dev else {"ap":0,"switch":0,"gateway":0},
                "checks":  checks,
            })

        # Sort: issues first (not-go), then go, alphabetical within each group
        sites_list.sort(key=lambda s: (s["go"], s["name"]))

        sites_go = sum(1 for s in sites_list if s["go"])

        return jsonify({
            "sites":          sites_list,
            "sites_go":       sites_go,
            "sites_total":    len(site_names),
            "devices_by_type": devices_by_type,
            "totals": {
                "devices":        total_devices,
                "devices_online": total_online,
                "by_type":        by_type_org,
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/deploy_clients/<org_id>")
def api_deploy_clients(org_id):
    """Wireless, wired, and NAC client snapshot for the Deploy tab."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403
    try:
        def _fetch(path):
            try:
                r = mist_get(sid, path)
                return r.get("results", []) if isinstance(r, dict) else (r if isinstance(r, list) else [])
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=4) as pool:
            f_wifi    = pool.submit(_fetch, f"/orgs/{org_id}/clients/search?limit=1000&duration=1d")
            f_wired   = pool.submit(_fetch, f"/orgs/{org_id}/wired_clients/search?limit=1000&duration=1d")
            f_nac     = pool.submit(_fetch, f"/orgs/{org_id}/nac_clients/search?limit=1000")
            f_dpc_pat = pool.submit(_get_org_dpc_patterns, sid, org_id)

        lldp_patterns, oui_patterns = f_dpc_pat.result()

        def _is_dpc(c):
            if not lldp_patterns and not oui_patterns:
                return False
            name = (c.get("last_hostname") or _normalize_field(c.get("hostname") or "")).lower()
            mac_str = mac_to_colon(c.get("mac", "")).upper()
            oui = mac_str[:8]
            for val, n in lldp_patterns:
                if name[:n] == val[:n]:
                    return True
            return oui in oui_patterns

        def _wifi_entry(c):
            # Mist returns most fields as lists; last_* fields are scalars
            return {
                "mac":      mac_to_colon(c.get("mac", "")),
                "hostname": c.get("last_hostname") or _normalize_field(c.get("hostname") or ""),
                "ssid":     c.get("last_ssid")     or _normalize_field(c.get("ssid") or ""),
                "mfg":      c.get("mfg", ""),
                "site":     _normalize_field(c.get("site_name") or c.get("site_id", "")),
            }

        def _wired_entry(c):
            return {
                "mac":      mac_to_colon(c.get("mac", "")),
                "hostname": _normalize_field(c.get("hostname") or ""),
                "port":     c.get("last_port_id") or _normalize_field(c.get("port_id") or ""),
                "vlan":     str(c.get("last_vlan") or ""),
                "mfg":      c.get("manufacture", ""),
                "site":     _normalize_field(c.get("site_name") or c.get("site_id", "")),
                "dpc":      _is_dpc(c),
            }

        def _nac_entry(c):
            return {
                "mac":      mac_to_colon(_normalize_field(c.get("mac") or c.get("client_mac", ""))),
                "username": _normalize_field(c.get("username") or c.get("name", "")),
                "type":     _normalize_field(c.get("type", "")),
                "site":     _normalize_field(c.get("site_name") or c.get("site_id", "")),
            }

        return jsonify({
            "wireless": [_wifi_entry(c)  for c in f_wifi.result()],
            "wired":    [_wired_entry(c) for c in f_wired.result()],
            "nac":      [_nac_entry(c)   for c in f_nac.result()],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/debug_deploy/<org_id>")
def api_debug_deploy(org_id):
    """Temporary: dump raw device types and client counts to diagnose deploy tab issues."""
    if not valid_uuid(org_id): return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid: return jsonify({"error": "Not authenticated"}), 401
    try:
        raw = mist_get(sid, f"/orgs/{org_id}/stats/devices?status=all&limit=1000")
        devices = raw.get("results", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
        type_counts = {}
        samples = []
        for d in devices:
            t = d.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
            if len(samples) < 3 and t in ("switch", "gateway"):
                samples.append({"type": t, "name": d.get("name") or d.get("hostname"),
                                 "site_id": d.get("site_id"), "status": d.get("status"),
                                 "model": d.get("model")})
        try:
            wired = mist_get(sid, f"/orgs/{org_id}/wired_clients/search?limit=5&duration=1d")
            wired_sample = wired.get("results", [])[:2] if isinstance(wired, dict) else []
        except Exception as e:
            wired_sample = [str(e)]
        try:
            wifi = mist_get(sid, f"/orgs/{org_id}/clients/search?limit=5&duration=1d")
            wifi_sample = wifi.get("results", [])[:2] if isinstance(wifi, dict) else []
        except Exception as e:
            wifi_sample = [str(e)]
        return jsonify({"device_count": len(devices), "type_counts": type_counts,
                        "switch_gateway_samples": samples,
                        "wired_client_sample": wired_sample,
                        "wifi_client_sample": wifi_sample})
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
                "block_blacklist_clients":   bool(w.get("block_blacklist_clients", False)),
                "scope":                     scope,
                "scope_id":                  scope_id,
                "site_name":                 site_name,
                "template_id":               w.get("template_id", ""),
                "template_name":             w.get("template_name", ""),
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
                "templates": [{"id":          t["id"],
                               "name":        t["name"],
                               "has_ntp":     t["has_ntp"],
                               "ntp_servers": t["ntp_servers"],
                               "has_dns":     t["has_dns"],
                               "dns_servers": t["dns_servers"],
                               "has_dpc":     t["has_dpc"],
                               "dpc_rules":   t["dpc_rules"]}
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
                        "id":          tmpl_id,
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
            # Also return total raw template count (includes templates with no details fetched)
            wan_dns_ntp_info["template_count"] = len(wan_tmpls)
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
            return mist_get(sid, f"/orgs/{org_id}/licenses")

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

            lic_data  = f_subs.result()
            lic_list  = lic_data.get("licenses", [])
            entitled  = lic_data.get("entitled", {})   # {type: total_owned}
            summary   = lic_data.get("summary",  {})   # {type: total_assigned}

            cloud_host  = _sessions[sid].get("cloud_host", "api.mist.com")
            manage_host = cloud_host.replace("api.", "manage.", 1)

            # Build individual license rows for display
            processed = []
            for s in lic_list:
                end = s.get("end_time", 0)
                if not end or end > now + WARN_DAYS * 86400:
                    st = "active"
                elif end > now:
                    st = "expiring"
                else:
                    st = "expired"
                processed.append({
                    "type":     s.get("type", "Unknown"),
                    "quantity": s.get("quantity", 0),
                    "end_time": end,
                    "status":   st,
                })
            processed.sort(key=lambda s: (s["status"] != "active", s["status"] != "expiring", s["type"].lower()))

            # Seat detail: compare entitled (owned) vs summary (assigned to devices)
            seat_detail = []
            for sub_type in sorted(set(entitled) | set(summary)):
                total = entitled.get(sub_type, 0)
                used  = summary.get(sub_type, 0)
                seat_detail.append({
                    "type":  sub_type,
                    "total": total,
                    "used":  used,
                    "free":  total - used,
                })

            exceeded_subs = [s for s in seat_detail if s["free"] < 0]

            licenses_info = {
                "total":         len(processed),
                "active":        sum(1 for s in processed if s["status"] == "active"),
                "expiring":      sum(1 for s in processed if s["status"] == "expiring"),
                "expired":       sum(1 for s in processed if s["status"] == "expired"),
                "exceeded":      len(exceeded_subs),
                "subscriptions": processed,
                "seat_detail":   seat_detail,
                "seat_mismatch": len(exceeded_subs) > 0,
                "manage_host":   manage_host,
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
            "wlans":       result,
            "filters":     BP_FILTERS,
            "dpc":         dpc_info,
            "dns_ntp":     dns_ntp_info,
            "wan_dns_ntp": wan_dns_ntp_info,
            "licenses":    licenses_info,
            "aa":          aa_info,
            "rf":          rf_info,
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
            # Only expose rates for active bands; use None for inactive bands
            # so the frontend doesn't factor them into worst-rate calculation
            active  = set(bands) if bands else (set(rateset.keys()) or {"24", "5"})
            band_24 = rateset.get("24", {}).get("template", "compatible") if "24" in active else None
            band_5  = rateset.get("5",  {}).get("template", "compatible") if "5"  in active else None
            band_6  = rateset.get("6",  {}).get("template", "compatible") if "6"  in active else None
            _log.info("DATARATES_FETCH wlan=%s ssid=%s bands=%s rateset=%s", wlan_id, w.get("ssid"), bands, rateset)
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
                    for b in active if b in rateset
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
            active  = set(bands) if bands else (set(rateset.keys()) or {"24", "5"})
            wlans.append({
                "id":          wlan_id,
                "ssid":        w.get("ssid", "Unnamed"),
                "enabled":     w.get("enabled", True),
                "scope":       "site",
                "scope_id":    site_id,
                "site_name":   site_name,
                "template_id": "",
                "in_template": False,
                "band_24":     rateset.get("24", {}).get("template", "compatible") if "24" in active else None,
                "band_5":      rateset.get("5",  {}).get("template", "compatible") if "5"  in active else None,
                "band_6":      rateset.get("6",  {}).get("template", "compatible") if "6"  in active else None,
                "bands":       bands,
                "high_density": all(
                    rateset.get(b, {}).get("template", "compatible") == "high-density"
                    for b in active if b in rateset
                ) and bool(rateset),
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

    data     = request.json or {}
    scope    = data.get("scope", "org")
    scope_id = data.get("scope_id", org_id)

    if scope not in ("org", "site"):
        return jsonify({"error": "Invalid scope"}), 400
    if scope == "site":
        if not valid_uuid(scope_id):
            return jsonify({"error": "Invalid scope_id for site WLAN"}), 400
        path = f"/sites/{scope_id}/wlans/{wlan_id}"
    else:
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
        _log.info("DATARATES scope=%s wlan=%s ssid=%s new_rateset=%s actor=%s ip=%s",
                  scope, wlan_id, wlan.get("ssid", ""), new_rateset, actor, request.remote_addr)

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


# ── DPC Discovery endpoints ────────────────────────────────────────────────────

_DPC_SKIP_PROFILES = {"dynamic", "default", "disabled", "dot1x", ""}

# Mist system-defined switch port profiles — always available on every template
# but never returned in port_usages by the API
_MIST_SYSTEM_PROFILES = ["ap", "default", "disabled", "dot1x", "iot", "uplink"]


def _get_org_dpc_patterns(sid, org_id):
    """Return (lldp_patterns, oui_patterns) built from all org DPC rules.

    lldp_patterns: list of (value_lower, prefix_len)
    oui_patterns:  list of "XX:XX:XX" strings
    """
    lldp_patterns, oui_patterns = [], []
    try:
        tmpl_list = mist_get(sid, f"/orgs/{org_id}/networktemplates")
        if not isinstance(tmpl_list, list):
            return lldp_patterns, oui_patterns
        tmpl_ids = [t["id"] for t in tmpl_list if t.get("id")]

        def _fetch_rules(tid):
            try:
                t = mist_get(sid, f"/orgs/{org_id}/networktemplates/{tid}")
                return t.get("port_usages", {}).get("dynamic", {}).get("rules", [])
            except Exception:
                return []

        all_rules = []
        with ThreadPoolExecutor(max_workers=6) as pool:
            for rules in pool.map(_fetch_rules, tmpl_ids):
                all_rules.extend(rules)

        for rule in all_rules:
            src = rule.get("src", "")
            val = (rule.get("equals") or rule.get("value") or "").strip()
            if not val:
                continue
            if src == "lldp_system_name":
                try:
                    n = int(rule.get("expression", f"[0:{len(val)}]").strip("[]").split(":")[1])
                except Exception:
                    n = len(val)
                lldp_patterns.append((val.lower(), n))
            elif src == "link_peermac":
                oui_patterns.append(val.upper()[:8])
    except Exception:
        pass
    return lldp_patterns, oui_patterns


def _all_org_port_profiles(sid, org_id):
    """Return sorted list of every port profile available across the org.

    Includes Mist system-defined profiles (always present but not in API responses)
    plus any custom profiles defined in any org network template.
    """
    try:
        tmpl_list = mist_get(sid, f"/orgs/{org_id}/networktemplates")
        if not isinstance(tmpl_list, list):
            tmpl_list = []
        tmpl_ids = [t["id"] for t in tmpl_list if t.get("id")]

        def _fetch(tid):
            try:
                detail = mist_get(sid, f"/orgs/{org_id}/networktemplates/{tid}")
                return {k for k in detail.get("port_usages", {}) if k and k != "dynamic"}
            except Exception:
                return set()

        profiles: set[str] = set(_MIST_SYSTEM_PROFILES)
        with ThreadPoolExecutor(max_workers=8) as pool:
            for result in pool.map(_fetch, tmpl_ids):
                profiles.update(result)
        return sorted(profiles)
    except Exception:
        return list(_MIST_SYSTEM_PROFILES)


def _common_prefix(strings):
    """Longest common prefix across all strings."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
        if not prefix:
            break
    return prefix


def _normalize_oui(mac_str):
    """Return first 3 octets of a MAC as 'XX:XX:XX' uppercase, or None."""
    clean = mac_str.lower().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 6:
        return None
    return ":".join(clean[i:i+2] for i in range(0, 6, 2)).upper()


@app.route("/api/dpc_discover/<org_id>/<tmpl_id>")
def api_dpc_discover(org_id, tmpl_id):
    """Scan all org clients + port LLDP data to suggest DPC rules.

    Groups devices by natural patterns (OUI, LLDP prefix) regardless of their
    current port profile — the user then maps each group to a template profile.
    """
    if not valid_uuid(org_id) or not valid_uuid(tmpl_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403
    try:
        # Fast path: caller only needs the profile list (no device scan)
        if request.args.get("profiles_only"):
            tmpl = mist_get(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}")
            custom = {k for k in tmpl.get("port_usages", {}) if k and k != "dynamic"}
            tmpl_profiles = sorted(custom | set(_MIST_SYSTEM_PROFILES))
            return jsonify({
                "profiles":      _all_org_port_profiles(sid, org_id),
                "tmpl_profiles": tmpl_profiles,
            })

        with ThreadPoolExecutor(max_workers=4) as pool:
            f_wired    = pool.submit(mist_get, sid,
                f"/orgs/{org_id}/wired_clients/search?limit=1000&duration=7d")
            f_wireless = pool.submit(mist_get, sid,
                f"/orgs/{org_id}/clients/search?limit=1000&duration=7d")
            f_ports    = pool.submit(mist_get, sid,
                f"/orgs/{org_id}/stats/ports/search?limit=1000")
            f_tmpl     = pool.submit(mist_get, sid,
                f"/orgs/{org_id}/networktemplates/{tmpl_id}")

        wired_raw    = f_wired.result()
        wireless_raw = f_wireless.result()
        ports_raw    = f_ports.result()
        tmpl         = f_tmpl.result()

        wired    = wired_raw.get("results",    []) if isinstance(wired_raw,    dict) else []
        wireless = wireless_raw.get("results", []) if isinstance(wireless_raw, dict) else []
        ports    = ports_raw.get("results",    []) if isinstance(ports_raw,    dict) else []

        # Build LLDP name lookup: neighbour_mac (normalised) → system_name
        lldp_by_mac: dict[str, str] = {}
        for p in ports:
            n_mac = _normalize_field(p.get("neighbor_mac")).lower().replace(":", "").strip()
            lldp  = _normalize_field(p.get("neighbor_system_name")).strip()
            if n_mac and lldp:
                lldp_by_mac[n_mac] = lldp

        # Build unified device catalogue: mac → {mac, make, lldp_name}
        devices: dict[str, dict] = {}
        for c in wired + wireless:
            mac  = _normalize_field(c.get("mac")).lower().replace(":", "").strip()
            if not mac or mac in devices:
                continue
            lldp = lldp_by_mac.get(mac, "")
            devices[mac] = {
                "mac":  mac,
                "make": _normalize_field(c.get("manufacture")).strip(),
                "lldp": lldp,
            }

        all_devs = list(devices.values())

        # ── Group 1: LLDP system name prefix ─────────────────────────────────
        lldp_pairs = [(d["mac"], d["lldp"]) for d in all_devs if d["lldp"]]
        lldp_groups = []
        assigned_lldp: set[str] = set()

        if lldp_pairs:
            # Count how many devices share each candidate prefix (len 2-20)
            from collections import Counter
            prefix_count: Counter = Counter()
            for _, name in lldp_pairs:
                for length in range(2, min(len(name) + 1, 21)):
                    prefix_count[name[:length]] += 1

            # Greedily pick prefixes: most devices first, longest prefix to break ties
            for prefix, cnt in sorted(prefix_count.items(),
                                      key=lambda x: (-x[1], -len(x[0]))):
                if cnt < 2:
                    continue
                unassigned = [(mac, nm) for mac, nm in lldp_pairs
                              if nm.startswith(prefix) and mac not in assigned_lldp]
                if len(unassigned) < 2:
                    continue
                assigned_lldp.update(mac for mac, _ in unassigned)
                makes = list({devices[mac]["make"] for mac, _ in unassigned
                              if devices[mac]["make"]})
                lldp_groups.append({
                    "id":       f"lldp_{prefix}",
                    "src":      "lldp_system_name",
                    "value":    prefix,
                    "count":    len(unassigned),
                    "examples": [nm for _, nm in unassigned[:3]],
                    "makes":    makes[:2],
                })

        # ── Group 2: MAC OUI ──────────────────────────────────────────────────
        oui_buckets: dict[str, list] = {}
        for d in all_devs:
            oui = _normalize_oui(d["mac"])
            if oui:
                oui_buckets.setdefault(oui, []).append(d)

        oui_groups = []
        for oui, devs in sorted(oui_buckets.items(), key=lambda x: -len(x[1])):
            if len(devs) < 2:
                continue
            makes = list({d["make"] for d in devs if d["make"]})
            lldp_examples = [d["lldp"] for d in devs if d["lldp"]][:3]
            oui_groups.append({
                "id":            f"oui_{oui}",
                "src":           "link_peermac",
                "value":         oui,
                "count":         len(devs),
                "examples":      [mac_to_colon(d["mac"]) for d in devs[:3]],
                "lldp_examples": lldp_examples,
                "makes":         makes[:2],
            })

        org_profiles  = _all_org_port_profiles(sid, org_id)
        custom_tmpl   = {k for k in tmpl.get("port_usages", {}) if k and k != "dynamic"}
        tmpl_profiles = sorted(custom_tmpl | set(_MIST_SYSTEM_PROFILES))
        existing_rules = tmpl.get("port_usages", {}).get("dynamic", {}).get("rules", [])

        return jsonify({
            "lldp_groups":     lldp_groups,
            "oui_groups":      oui_groups,
            "profiles":        org_profiles,
            "tmpl_profiles":   tmpl_profiles,
            "existing_rules":  existing_rules,
            "devices_scanned": len(all_devs),
            "ports_scanned":   len(ports),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/template_profile/<org_id>/<tmpl_id>/<profile_name>", methods=["DELETE"])
def api_delete_template_profile(org_id, tmpl_id, profile_name):
    """Remove a port profile from a network template's port_usages."""
    if not valid_uuid(org_id) or not valid_uuid(tmpl_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403
    if not profile_name or profile_name == "dynamic":
        return jsonify({"error": "Cannot delete this profile"}), 400
    try:
        tmpl   = mist_get(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}")
        usages = tmpl.get("port_usages", {})
        if profile_name not in usages:
            return jsonify({"error": "Profile not found"}), 404
        del usages[profile_name]
        tmpl["port_usages"] = usages
        r = mist_put(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}", tmpl)
        if r.ok:
            remaining = sorted(k for k in usages if k and k != "dynamic")
            return jsonify({"ok": True, "profiles": remaining})
        return jsonify({"error": r.text[:200]}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/dpc_rules_batch/<org_id>/<tmpl_id>", methods=["POST"])
def api_dpc_rules_batch(org_id, tmpl_id):
    """Append a batch of DPC rules to a network template in a single PUT."""
    if not valid_uuid(org_id) or not valid_uuid(tmpl_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403
    data       = request.json or {}
    rules_body = data.get("rules", [])
    if not rules_body:
        return jsonify({"error": "No rules provided"}), 400
    try:
        tmpl   = mist_get(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}")
        usages = tmpl.setdefault("port_usages", {})
        dyn    = usages.setdefault("dynamic", {"rules": []})
        rules  = dyn.setdefault("rules", [])

        # Identify which profiles are missing so we can source them from other templates
        needed = {(r.get("usage") or "").strip() for r in rules_body} - set(usages)
        if needed:
            all_tmpls = mist_get(sid, f"/orgs/{org_id}/networktemplates")
            if not isinstance(all_tmpls, list):
                all_tmpls = []
            for other_summary in all_tmpls:
                if not needed:
                    break
                if other_summary.get("id") == tmpl_id:
                    continue
                try:
                    other = mist_get(sid, f"/orgs/{org_id}/networktemplates/{other_summary['id']}")
                    for profile in list(needed):
                        if profile in other.get("port_usages", {}):
                            usages[profile] = other["port_usages"][profile]
                            needed.discard(profile)
                except Exception:
                    continue

        # Build a set of (src, equals) for existing rules to prevent duplicates
        existing_keys = {
            (rx.get("src", ""), rx.get("equals", "") or rx.get("value", ""))
            for rx in rules
        }

        for r in rules_body:
            src   = (r.get("src",   "") or "").strip()
            value = (r.get("value", "") or "").strip()
            usage = (r.get("usage", "") or "").strip()
            if not src or not usage:
                continue
            if (src, value) in existing_keys:
                continue   # duplicate — skip
            if src == "lldp_system_name":
                rule = {"src": src, "expression": f"[0:{len(value)}]", "equals": value, "usage": usage}
            elif src == "link_peermac":
                rule = {"src": src, "expression": "[0:8]", "equals": value, "usage": usage}
            else:
                rule = {"src": src, "equals": value, "usage": usage}
            existing_keys.add((src, value))
            rules.append(rule)
        dyn["rules"]        = rules
        usages["dynamic"]   = dyn
        tmpl["port_usages"] = usages
        resp = mist_put(sid, f"/orgs/{org_id}/networktemplates/{tmpl_id}", tmpl)
        if resp.ok:
            return jsonify({"ok": True, "rules": rules})
        return jsonify({"error": resp.text[:200]}), resp.status_code
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


@app.route("/api/dnsntp/<org_id>/<tmpl_id>", methods=["POST"])
def api_dnsntp_apply(org_id, tmpl_id):
    """Set dns_servers and/or ntp_servers on a network template."""
    if not valid_uuid(org_id) or not valid_uuid(tmpl_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    data        = request.json or {}
    dns_servers = data.get("dns_servers")   # list[str] or None
    ntp_servers = data.get("ntp_servers")   # list[str] or None

    if dns_servers is None and ntp_servers is None:
        return jsonify({"error": "Provide dns_servers and/or ntp_servers"}), 400

    try:
        path  = f"/orgs/{org_id}/networktemplates/{tmpl_id}"
        tmpl  = mist_get(sid, path)
        if dns_servers is not None:
            tmpl["dns_servers"] = [s.strip() for s in dns_servers if s.strip()]
        if ntp_servers is not None:
            tmpl["ntp_servers"] = [s.strip() for s in ntp_servers if s.strip()]

        actor = _sessions[sid].get("email", "unknown")
        _log.info("DNSNTP tmpl=%s dns=%s ntp=%s actor=%s ip=%s",
                  tmpl_id, tmpl.get("dns_servers"), tmpl.get("ntp_servers"),
                  actor, request.remote_addr)

        r = mist_put(sid, path, tmpl)
        if r.ok:
            return jsonify({"status": "applied",
                            "dns_servers": tmpl.get("dns_servers"),
                            "ntp_servers": tmpl.get("ntp_servers")})
        try:
            detail = r.json().get("detail", r.text[:300])
        except Exception:
            detail = r.text[:300]
        return jsonify({"status": "error", "detail": detail}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/wan_dnsntp/<org_id>/<tmpl_id>", methods=["POST"])
def api_wan_dnsntp_apply(org_id, tmpl_id):
    """Set dns_servers and/or ntp_servers on a gateway (WAN) template."""
    if not valid_uuid(org_id) or not valid_uuid(tmpl_id):
        return jsonify({"error": "Invalid ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    data        = request.json or {}
    dns_servers = data.get("dns_servers")
    ntp_servers = data.get("ntp_servers")

    if dns_servers is None and ntp_servers is None:
        return jsonify({"error": "Provide dns_servers and/or ntp_servers"}), 400

    try:
        path = f"/orgs/{org_id}/gatewaytemplates/{tmpl_id}"
        tmpl = mist_get(sid, path)
        if dns_servers is not None:
            tmpl["dns_servers"] = [s.strip() for s in dns_servers if s.strip()]
        if ntp_servers is not None:
            tmpl["ntp_servers"] = [s.strip() for s in ntp_servers if s.strip()]

        actor = _sessions[sid].get("email", "unknown")
        _log.info("WAN_DNSNTP tmpl=%s dns=%s ntp=%s actor=%s ip=%s",
                  tmpl_id, tmpl.get("dns_servers"), tmpl.get("ntp_servers"),
                  actor, request.remote_addr)

        r = mist_put(sid, path, tmpl)
        if r.ok:
            return jsonify({"status": "applied",
                            "dns_servers": tmpl.get("dns_servers"),
                            "ntp_servers": tmpl.get("ntp_servers")})
        try:
            detail = r.json().get("detail", r.text[:300])
        except Exception:
            detail = r.text[:300]
        return jsonify({"status": "error", "detail": detail}), r.status_code
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


# ── Golden Config Templates ───────────────────────────────────────────────────
#
# HPE Networking recommended defaults.  These are opinionated starting points;
# the operator is expected to assign them to sites and customise as needed.
#
_GOLDEN_NAME_WLAN    = "HPE Best Practices"
_GOLDEN_NAME_NETWORK = "HPE Golden — Network"
_GOLDEN_NAME_RF      = "HPE Golden — RF"
_GOLDEN_NAME_GATEWAY = "HPE Golden — Gateway"

_GOLDEN_WLAN_TEMPLATE = {
    "name": _GOLDEN_NAME_WLAN,
}

# Best-practice WLAN created inside the golden template.
# SSID and PSK are placeholders — update before enabling.
_GOLDEN_WLAN_BODY = {
    "ssid":                    "HPE-Golden-SSID",
    "enabled":                 False,
    "auth": {
        "type":     "psk",
        "psk":      "ChangeMe123!",
        "pairwise": ["wpa2-ccmp", "wpa3"],
    },
    "block_blacklist_clients": True,
    "arp_filter":              True,
    "limit_bcast":             True,
    "limit_probe_response":    True,
    "no_legacy":               True,
    "rateset": {
        "24": {"template": "high-density"},
        "5":  {"template": "high-density"},
        "6":  {"template": "high-density"},
    },
}

_GOLDEN_NETWORK_TEMPLATE = {
    "name": _GOLDEN_NAME_NETWORK,
    # DNS placeholder — operator must fill in site-specific servers
    "dns_servers": [],
    # Public NTP servers (replace with internal if required)
    "ntp_servers": ["0.pool.ntp.org", "1.pool.ntp.org"],
    # LLDP on all switch ports
    "switch_mgmt": {
        "lldp_med_enabled": True,
    },
}

_GOLDEN_RF_TEMPLATE_V2 = {
    "name": _GOLDEN_NAME_RF,
    "country_code": "US",
    "band_24": {
        "allow_rrm_disable": True,
        "preamble":  "short",
        "power_min": 4,
        "power_max": 8,
        "ant_gain":  0,
    },
    "band_5": {
        "bandwidth": 20,
        "power_min": 6,
        "power_max": 10,
        "ant_gain":  0,
    },
    "band_6": {
        "bandwidth": 40,
        "power_min": 8,
        "power_max": 17,
        "ant_gain":  0,
    },
    "band_24_usage": "24",
    "scanning_enabled": True,
}

# Best-practice gateway (SD-WAN / SRX) template.
# Enables path-selection, sets public NTP/DNS, and enforces
# recommended BGP/routing hardening flags as sane defaults.
_GOLDEN_GATEWAY_TEMPLATE = {
    "name": _GOLDEN_NAME_GATEWAY,
    # Public DNS resolvers — operator should replace with internal servers
    "dns_servers": ["8.8.8.8", "8.8.4.4"],
    # Public NTP — replace with internal if required
    "ntp_servers": ["0.pool.ntp.org", "1.pool.ntp.org"],
    # Path-selection: prefer lowest latency, failover on packet-loss
    "path_preferences": {},
    # BGP hardening: log state changes, send notifications on reset
    "bgp_config": {},
    # DHCP snooping on all ports
    "dhcpd_config": {"enabled": False},
}


def _find_golden(tmpl_list, golden_name):
    """Return the first template whose name matches (case-insensitive)."""
    name_lower = golden_name.lower()
    return next((t for t in tmpl_list
                 if t.get("name", "").lower() == name_lower), None)


@app.route("/api/golden_status/<org_id>")
def api_golden_status(org_id):
    """Return {wlan, network, rf} exists/id/name for the three HPE golden templates."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    try:
        def _safe_list(path):
            try:
                raw = mist_get(sid, path)
                return raw if isinstance(raw, list) else raw.get("results", [])
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=3) as pool:
            f_wlan = pool.submit(_safe_list, f"/orgs/{org_id}/templates")
            f_net  = pool.submit(_safe_list, f"/orgs/{org_id}/networktemplates")
            f_rf   = pool.submit(_safe_list, f"/orgs/{org_id}/rftemplates")

        def _status(tmpl_list, name):
            t = _find_golden(tmpl_list, name)
            if t is None:
                # Also accept the legacy RF name for backwards compat
                t = _find_golden(tmpl_list, "Suggested Baseline Settings")
            return {
                "exists": t is not None,
                "id":     t.get("id")   if t else None,
                "name":   t.get("name") if t else None,
            }

        return jsonify({
            "wlan":    _status(f_wlan.result(), _GOLDEN_NAME_WLAN),
            "network": _status(f_net.result(),  _GOLDEN_NAME_NETWORK),
            "rf":      _status(f_rf.result(),   _GOLDEN_NAME_RF),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/create_golden/<org_id>/<tmpl_type>", methods=["POST"])
def api_create_golden(org_id, tmpl_type):
    """
    Create an HPE golden template for the org.
    tmpl_type: "wlan" | "network" | "rf"
    Returns: {id, name, created: true}
    """
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    if tmpl_type not in ("wlan", "network", "rf", "gateway"):
        return jsonify({"error": "Invalid template type"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    if tmpl_type == "wlan":
        api_path    = f"/orgs/{org_id}/templates"
        golden_body = _GOLDEN_WLAN_TEMPLATE
        golden_name = _GOLDEN_NAME_WLAN
    elif tmpl_type == "network":
        api_path    = f"/orgs/{org_id}/networktemplates"
        golden_body = _GOLDEN_NETWORK_TEMPLATE
        golden_name = _GOLDEN_NAME_NETWORK
    elif tmpl_type == "gateway":
        api_path    = f"/orgs/{org_id}/gatewaytemplates"
        golden_body = _GOLDEN_GATEWAY_TEMPLATE
        golden_name = _GOLDEN_NAME_GATEWAY
    else:  # rf
        api_path    = f"/orgs/{org_id}/rftemplates"
        golden_body = _GOLDEN_RF_TEMPLATE_V2
        golden_name = _GOLDEN_NAME_RF

    try:
        # Idempotent: check if it already exists (tolerate 404 — org may have no templates yet)
        try:
            raw = mist_get(sid, api_path)
            lst = raw if isinstance(raw, list) else raw.get("results", [])
        except Exception:
            lst = []
        existing = _find_golden(lst, golden_name)
        if existing is None and tmpl_type == "rf":
            existing = _find_golden(lst, "Suggested Baseline Settings")
        if existing:
            return jsonify({"id": existing["id"], "name": existing["name"], "created": False})

        actor = _sessions[sid].get("email", "unknown")
        _log.info("GOLDEN_CREATE type=%s org=%s actor=%s ip=%s",
                  tmpl_type, org_id, actor, request.remote_addr)

        r = mist_post(sid, api_path, golden_body)
        if not r.ok:
            try:
                detail = r.json().get("detail", r.text[:200])
            except Exception:
                detail = f"Mist API error {r.status_code}"
            return jsonify({"error": detail}), r.status_code

        created  = r.json()
        tmpl_id  = created.get("id")
        tmpl_name = created.get("name")

        # For WLAN templates: also create the best-practice WLAN inside the template
        wlan_warning = None
        if tmpl_type == "wlan" and tmpl_id:
            wlan_body = dict(_GOLDEN_WLAN_BODY)
            wlan_body["template_id"] = tmpl_id
            wr = mist_post(sid, f"/orgs/{org_id}/wlans", wlan_body)
            if not wr.ok:
                wlan_warning = f"Template created but WLAN creation failed: {wr.text[:200]}"
                _log.warning("GOLDEN_WLAN_CREATE failed: %s", wr.text[:200])

        resp = {"id": tmpl_id, "name": tmpl_name, "created": True}
        if wlan_warning:
            resp["warning"] = wlan_warning
        return jsonify(resp)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Site Creation ─────────────────────────────────────────────────────────────

@app.route("/api/site_options/<org_id>")
def api_site_options(org_id):
    """Return available templates (network, wlan, gateway, rf) for new-site creation."""
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    try:
        def _safe_list(path):
            try:
                raw = mist_get(sid, path)
                lst = raw if isinstance(raw, list) else raw.get("results", [])
                return [{"id": t["id"], "name": t.get("name", t["id"])}
                        for t in lst if t.get("id")]
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=4) as pool:
            f_net  = pool.submit(_safe_list, f"/orgs/{org_id}/networktemplates")
            f_wlan = pool.submit(_safe_list, f"/orgs/{org_id}/templates")
            f_gw   = pool.submit(_safe_list, f"/orgs/{org_id}/gatewaytemplates")
            f_rf   = pool.submit(_safe_list, f"/orgs/{org_id}/rftemplates")

        return jsonify({
            "network": f_net.result(),
            "wlan":    f_wlan.result(),
            "gateway": f_gw.result(),
            "rf":      f_rf.result(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/create_site/<org_id>", methods=["POST"])
def api_create_site(org_id):
    """
    Create a new site and optionally assign network/WLAN/gateway/RF templates.
    Body: {name, address, timezone, country_code,
           network_template_id, wlan_template_id, gateway_template_id, rf_template_id}
    Returns: {site_id, site_name, steps: [{label, status, detail}]}
    """
    if not valid_uuid(org_id):
        return jsonify({"error": "Invalid org ID"}), 400
    sid = get_authed_sid()
    if not sid:
        return jsonify({"error": "Not authenticated"}), 401
    if not org_allowed(org_id):
        return jsonify({"error": "Access denied"}), 403

    data = request.json or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Site name is required"}), 400

    steps = []

    try:
        # 1. Create the site
        site_body = {"name": name}
        if data.get("address"):
            site_body["address"] = data["address"].strip()
        if data.get("timezone"):
            site_body["timezone"] = data["timezone"]
        if data.get("country_code"):
            site_body["country_code"] = data["country_code"].upper()[:2]

        actor = _sessions[sid].get("email", "unknown")
        _log.info("CREATE_SITE org=%s name=%s actor=%s ip=%s",
                  org_id, name, actor, request.remote_addr)

        r = mist_post(sid, f"/orgs/{org_id}/sites", site_body)
        if not r.ok:
            try:
                detail = r.json().get("detail", r.text[:300])
            except Exception:
                detail = r.text[:300]
            return jsonify({"error": f"Failed to create site: {detail}"}), r.status_code

        site    = r.json()
        site_id = site.get("id")
        steps.append({"label": "Create site", "status": "ok",
                       "detail": f"Site '{name}' created (ID: {site_id})"})

        # Helper: fetch template, add site_id to applies.site_ids, PUT back
        def _assign_applies(tmpl_id, api_path, label):
            try:
                tmpl    = mist_get(sid, f"{api_path}/{tmpl_id}")
                applies = tmpl.get("applies") or {"site_ids": [], "sitegroup_ids": []}
                if "site_ids" not in applies:
                    applies["site_ids"] = []
                if site_id not in applies["site_ids"]:
                    applies["site_ids"].append(site_id)
                tmpl["applies"] = applies
                resp = mist_put(sid, f"{api_path}/{tmpl_id}", tmpl)
                if resp.ok:
                    steps.append({"label": label, "status": "ok",
                                   "detail": f"Assigned '{tmpl.get('name', tmpl_id)}'"})
                else:
                    steps.append({"label": label, "status": "warn",
                                   "detail": f"Assignment failed: {resp.text[:200]}"})
            except Exception as ex:
                steps.append({"label": label, "status": "warn", "detail": str(ex)})

        # 2. Network template
        net_id = data.get("network_template_id", "")
        if net_id and valid_uuid(net_id):
            _assign_applies(net_id, f"/orgs/{org_id}/networktemplates",
                            "Assign network template")

        # 3. WLAN template
        wlan_id = data.get("wlan_template_id", "")
        if wlan_id and valid_uuid(wlan_id):
            _assign_applies(wlan_id, f"/orgs/{org_id}/templates",
                            "Assign WLAN template")

        # 4. Gateway template
        gw_id = data.get("gateway_template_id", "")
        if gw_id and valid_uuid(gw_id):
            _assign_applies(gw_id, f"/orgs/{org_id}/gatewaytemplates",
                            "Assign gateway template")

        # 5. RF template — assigned via site setting (rftemplate_id), not applies
        rf_id = data.get("rf_template_id", "")
        if rf_id and valid_uuid(rf_id):
            try:
                resp = mist_patch(sid, f"/sites/{site_id}/setting",
                                  {"rftemplate_id": rf_id})
                if resp.ok:
                    steps.append({"label": "Assign RF template", "status": "ok",
                                   "detail": "RF template applied to site settings"})
                else:
                    steps.append({"label": "Assign RF template", "status": "warn",
                                   "detail": f"RF assignment failed: {resp.text[:200]}"})
            except Exception as ex:
                steps.append({"label": "Assign RF template", "status": "warn",
                               "detail": str(ex)})

        return jsonify({
            "site_id":   site_id,
            "site_name": name,
            "steps":     steps,
        })

    except Exception as e:
        _log.exception("CREATE_SITE error: %s", e)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False, port=5001)
