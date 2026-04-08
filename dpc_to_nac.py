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

_SESSION_TTL = 8 * 3600  # seconds; sessions pruned lazily on each request
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


if __name__ == "__main__":
    app.run(debug=False, port=5001)
