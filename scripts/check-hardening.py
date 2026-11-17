"""Checks the rendered Compose config for the container controls of docs/operations/hardening.md.

Usage (make check-hardening): docker compose ... config --format json | python3 -I scripts/check-hardening.py <production|development>

The rendered config holds values from .env (secrets among them): this script prints service,
key and variable names only, never a value from the input. It also reads the nginx files and
two backend sources from the repository (no secrets there): nginx's own /api/ answers must be
the ones registered in backend/internal/apperr/edge.go, the 404 page must be the only status
page (nginx's error_page 404 target, its one HTML location, frontend/js/utils.js
STATUS_PAGES.NOT_FOUND and the only HTML file in frontend/ besides index.html), and the backend's stop grace must
outlast its shutdown budget in backend/cmd/server/main.go. EDGE_TRUSTED_PROXIES: nginx
believes a client address or protocol a request names only from a listed proxy on the clearnet
listener, and nginx-edge-proxies.sh is run (into a temporary directory) to prove that the
configured value renders, that the default renders no entry and that malformed lists are
refused. Exit 0 when every control holds, 1
with one line per failure otherwise, 2 on unusable input.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from http import HTTPStatus
from pathlib import Path

# Capabilities each service may add back after cap_drop ALL. postgres starts as root only to
# hand its TLS key to uid 70 and drop to it (postgres/entrypoint.sh, docker-compose.yaml).
ALLOWED_CAPS = {
    "postgres": {"CHOWN", "DAC_READ_SEARCH", "FOWNER", "SETUID", "SETGID"},
}
# Services whose PID 1 starts as root on purpose (the reason is in ALLOWED_CAPS)
ROOT_START = {"postgres"}
# Services whose PID 1 reaps no children and therefore runs under tini
NEEDS_INIT = {"backend", "tor"}
# Exactly these networks per service; development adds devhost where it publishes
NETWORKS = {
    "frontend": {"edge", "app"},
    "tor": {"edge"},
    "backend": {"app", "data"},
    "postgres": {"data"},
}
INTERNAL_NETWORKS = {"app", "data"}
# No address on their bridges: the host cannot route into them (docker-compose.yaml)
GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"
ISOLATED = "isolated"
# Who may publish a port, always on loopback only
PUBLISHERS = {
    "production": {"frontend"},
    "development": {"frontend", "backend", "postgres"},
}
DEV_NETWORK = "devhost"
LOOPBACK = "127.0.0.1"
TMPFS_FLAGS = {"noexec", "nosuid", "nodev"}
RESTART_POLICIES = {"always", "unless-stopped", "on-failure"}
FORBIDDEN_KEYS = ("privileged", "devices", "volumes_from", "cgroup_parent")
HOST_NAMESPACE_KEYS = ("network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup")
FORBIDDEN_SECURITY_OPTS = ("seccomp", "apparmor", "label")
DOCKER_SOCKET = "docker.sock"
ROOT_USERS = {"", "0", "root", "0:0", "root:root"}
# The backend's memory limit must hold the runtime, 20 database connections, event streams and
# the GC's headroom (BACKEND_HEADROOM_BYTES) plus the file-request pool at its bound:
# maxConcurrentFileRequests (backend/internal/handlers/files.go) requests of about
# FILE_REQUEST_BYTES each, as that file's comment counts them
BACKEND_HEADROOM_BYTES = 128 << 20
FILE_REQUEST_BYTES = 1_600_000

# Every service logs through the rotating "local" driver (docker-compose.yaml x-logging)
LOG_DRIVER = "local"
LOG_OPTIONS = ("max-size", "max-file")
# The backend listens on this port inside its container: nginx-api-proxy.conf, the healthcheck
# and docker-compose.dev.yaml name it, so BACKEND_PORT is pinned to it in Compose
BACKEND_PORT = "8080"
HEALTH_PATH = "/internal/health"
# Repository files read for the nginx and shutdown checks
ROOT = Path(__file__).resolve().parent.parent
MAIN_GO = ROOT / "backend/cmd/server/main.go"
APPERR_GO = ROOT / "backend/internal/apperr/apperr.go"
EDGE_GO = ROOT / "backend/internal/apperr/edge.go"
NGINX_SITE = ROOT / "nginx-site.conf"
NGINX_API_ERRORS = ROOT / "nginx-api-errors.conf"
NGINX_CONF = ROOT / "nginx.conf"
NGINX_API_PROXY = ROOT / "nginx-api-proxy.conf"
# Renders EDGE_TRUSTED_PROXIES into the files nginx.conf includes (run at every nginx start)
EDGE_RENDERER = ROOT / "nginx-edge-proxies.sh"
EDGE_SETTING = "EDGE_TRUSTED_PROXIES"
EDGE_OUT_DIR = "EDGE_PROXIES_OUT_DIR"
EDGE_REALIP_FILE = "edge-proxies.realip"
EDGE_GEO_FILE = "edge-proxies.geo"
EDGE_REALIP_INCLUDE = "include /etc/nginx/conf.d/" + EDGE_REALIP_FILE + ";"
EDGE_GEO_INCLUDE = "include /etc/nginx/conf.d/" + EDGE_GEO_FILE + ";"
EDGE_RENDER_TIMEOUT_SEC = 10
# Entries the renderer must refuse: injection, a zero prefix (every address), malformed, empty
EDGE_MALFORMED = ("192.0.2.1;", "0.0.0.0/0", "::/0", "192.0.2.300", "192.0.2.1/33", "192.0.2.1,,192.0.2.2",
                  "192.0.2.1,", "01.2.3.4", "1::2::3", "192.0.2.1\nset_real_ip_from 0.0.0.0/0")
EDGE_SAMPLE = ("192.0.2.1", "2001:db8::/32")
# Directives that make nginx believe a client-sent address; only the rendered file may hold them
REALIP_DIRECTIVES = ("set_real_ip_from", "real_ip_header", "real_ip_recursive")
# Headers nginx passes to the backend, each from the variable nginx alone decides
FORWARDED_HEADERS = {
    "X-Real-IP": "$client_addr",
    "X-Forwarded-For": "$client_addr",
    "X-Forwarded-Proto": "$forwarded_proto",
}
# A client-sent forwarding header used anywhere but the protocol map is a client choosing it
CLIENT_FORWARDING = re.compile(r"\$(?:proxy_add_x_forwarded_for|http_x_forwarded_for|http_x_real_ip|http_forwarded)\b")
EDGE_GEO = re.compile(r"^geo \$realip_remote_addr \$edge_peer \{\n\s+default 0;\n\s+" + re.escape(EDGE_GEO_INCLUDE) + r"\n\}",
                      re.MULTILINE)
PROTO_MAP = re.compile(r'^map "\$proxy_protocol_addr\|\$edge_peer\|\$http_x_forwarded_proto" \$forwarded_proto \{\n(.*?)\n\}',
                       re.MULTILINE | re.DOTALL)
PROTO_MAP_LINES = ["default $scheme;", '"|1|https" https;', '"|1|http" http;']
SERVER_BLOCK = re.compile(r"^server \{\n(.*?)\n\}", re.MULTILINE | re.DOTALL)
CLEARNET_LISTEN = "listen 8080;"
ONION_LISTEN = "listen 8081 proxy_protocol;"
FRONTEND = ROOT / "frontend"
UTILS_JS = FRONTEND / "js/utils.js"
# The SPA's page; every other HTML file in frontend/ is a status page
SPA_PAGE = "index.html"
# The one status page: nginx's error_page 404 target, served by an exact location, and the page
# frontend/js/utils.js sends an unknown route to
ERROR_PAGE_404 = re.compile(r"^error_page 404 (/[\w-]+\.html);$", re.MULTILINE)
# error_page to a named location: "error_page 500 502 =503 @name;" (the =NNN group may be missing)
ERROR_PAGE_NAMED = re.compile(r"^error_page ((?:\d{3} )+)(?:=(\d{3}) )?@(\w+);$", re.MULTILINE)
# A named location and the JSON body it returns
NAMED_ANSWER = re.compile(r"^location @(\w+) \{(?:(?!^location ).)*?return \d{3} '(\{[^']*)';", re.MULTILINE | re.DOTALL)
# The opening line of every location that names an HTML file
HTML_LOCATION = re.compile(r"^location [^{\n]*html[^{\n]*\{", re.MULTILINE)
NOT_FOUND_PAGE = re.compile(r"NOT_FOUND: '(/[\w-]+\.html)'")
API_PROXY_INCLUDE = "include /etc/nginx/elyrn/api-proxy.conf;"
API_ERRORS_INCLUDE = "include /etc/nginx/elyrn/api-errors.conf;"
API_DEFAULT_DENY = "location /api/ { " + API_ERRORS_INCLUDE + " return 404; }"
# nginx is the one source of these on every response; the backend's copies are hidden on /api/,
# so an API answer carries exactly one of each (the two CSPs both stay: they differ on purpose)
NGINX_OWNED_HEADERS = {
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
# nginx-owned too, with a value too long to repeat here: nginx's one line is found by name
NGINX_OWNED_BY_NAME = ("Permissions-Policy",)
# Every header the backend's security middleware sets must be nginx-owned (hidden on /api/) or
# one that stays on purpose
SECURITY_GO = ROOT / "backend/internal/middleware/security.go"
BACKEND_HEADER_SET = re.compile(r'w\.Header\(\)\.Set\(("[A-Za-z-]+"|utils\.\w+)')
BACKEND_HEADERS_KEPT = {'"Content-Security-Policy"', "utils.HeaderCacheControl"}
# The event stream's location: unbuffered here, and an outer proxy is told so (the backend's
# X-Accel-Buffering passed on); an add_header there would drop the server's security headers
EVENTS_LOCATION = "location = /api/v2/events {"
EVENTS_STREAM_LINES = ("proxy_buffering off;", "proxy_pass_header X-Accel-Buffering;")
# The file parts location: at most as many requests at once as the backend admits (its contract
# bound), in memory only; the zone is one key for all clients (nginx.conf)
FILES_LOCATION = re.compile(r"^location [^\n]*/files\(/", re.MULTILINE)
FILES_GO = ROOT / "backend/internal/handlers/files.go"
FILES_BOUND = re.compile(r"^const maxConcurrentFileRequests = (\d+)$", re.MULTILINE)
FILES_ZONES = ("limit_conn_zone $file_requests_key zone=files:1m;",
               "limit_conn_zone $client_addr zone=files_per_client:10m;")
# Per client address (as the request-rate zone counts it): small enough that one cannot take the pool
FILES_PER_CLIENT = re.compile(r"^limit_conn files_per_client (\d+);$")
FILES_KEY_MAP = re.compile(r"^map \$request_method \$file_requests_key \{\n\s+default all;\n\}", re.MULTILINE)
FILES_MEMORY_LINES = ("client_body_buffer_size 342k;", "proxy_max_temp_file_size 0;", "limit_conn_status 503;",
                      "client_body_timeout 5s;")
# HSTS: one source, nginx's server-level header from $hsts, which nginx-hsts.sh renders at start
HSTS_RENDERER = ROOT / "nginx-hsts.sh"
HSTS_OUT_DIR = "HSTS_OUT_DIR"
HSTS_MAP_FILE = "hsts.map"
HSTS_HEADER = "Strict-Transport-Security"
HSTS_ADD_HEADER = "add_header " + HSTS_HEADER + " $hsts always;"
HSTS_SETTINGS = ("APP_ENV", "HSTS_MAX_AGE", "HSTS_INCLUDE_SUBDOMAINS", "HSTS_PRELOAD")
HSTS_MAP = re.compile(r'^map "\$proxy_protocol_addr\|\$forwarded_proto" \$hsts \{\n\s+default "";\n\s+'
                      r'include /etc/nginx/conf\.d/' + re.escape(HSTS_MAP_FILE) + r';\n\}', re.MULTILINE)
# (settings, the one entry the map must hold, or None for none); the key "|https" is the clearnet
# listener (no PROXY address) with HTTPS vouched for by a listed edge proxy
HSTS_CASES = (
    ({"APP_ENV": "production"}, '"|https" "max-age=31536000";'),
    ({"APP_ENV": "production", "HSTS_MAX_AGE": ""}, '"|https" "max-age=31536000";'),
    ({"APP_ENV": "Production", "HSTS_MAX_AGE": "600", "HSTS_INCLUDE_SUBDOMAINS": "true", "HSTS_PRELOAD": "YES"},
     '"|https" "max-age=600; includeSubDomains; preload";'),
    ({"APP_ENV": "prod", "HSTS_MAX_AGE": "63072000", "HSTS_PRELOAD": "1"}, '"|https" "max-age=63072000; preload";'),
    ({"APP_ENV": "production", "HSTS_MAX_AGE": "0"}, None),
    ({"APP_ENV": "development"}, None),
    ({"APP_ENV": "development", "HSTS_MAX_AGE": "31536000"}, None),
    ({"APP_ENV": "test", "HSTS_INCLUDE_SUBDOMAINS": "true"}, None),
    ({}, None),
)
HSTS_MALFORMED = (
    {"APP_ENV": "production", "HSTS_MAX_AGE": "-1"}, {"APP_ENV": "production", "HSTS_MAX_AGE": "1e3"},
    {"APP_ENV": "production", "HSTS_MAX_AGE": "63072001"}, {"APP_ENV": "production", "HSTS_MAX_AGE": "01"},
    {"APP_ENV": "production", "HSTS_MAX_AGE": "one year"}, {"APP_ENV": "production", "HSTS_MAX_AGE": "99999999999"},
    {"APP_ENV": "development", "HSTS_MAX_AGE": "abc"}, {"APP_ENV": "production", "HSTS_INCLUDE_SUBDOMAINS": "on"},
    {"APP_ENV": "production", "HSTS_PRELOAD": "maybe"}, {"APP_ENV": "staging"},
    {"APP_ENV": "production", "HSTS_MAX_AGE": '1"; add_header X 1'},
)
# Go sources that answer requests; a second HSTS source there would disagree with nginx's
BACKEND_SOURCES = ROOT / "backend/internal"
# Zero telemetry: at error level nginx names the client address in upstream and limit_req lines
NGINX_LOG_LINES = ("access_log off;", "error_log /dev/stderr crit;")
# Shutdown budget constants in main.go, e.g. "shutdownGrace   = 10 * time.Second"
SHUTDOWN_CONSTANTS = ("shutdownGrace", "jobStopDeadline")

failures = []


def fail(service, message):
    failures.append(f"{service}: {message}")


def as_int(raw, default):
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def check_privileges(name, svc):
    if "ALL" not in (svc.get("cap_drop") or []):
        fail(name, "cap_drop must contain ALL")
    extra = set(svc.get("cap_add") or []) - ALLOWED_CAPS.get(name, set())
    if extra:
        fail(name, "cap_add not allowed: " + ", ".join(sorted(extra)))
    opts = svc.get("security_opt") or []
    if "no-new-privileges:true" not in opts:
        fail(name, "security_opt must contain no-new-privileges:true")
    for opt in opts:
        if opt.split("=")[0].split(":")[0] in FORBIDDEN_SECURITY_OPTS:
            fail(name, "security_opt must keep the default seccomp, AppArmor and SELinux profiles")
    user = str(svc.get("user") or "")
    if name not in ROOT_START and user in ROOT_USERS:
        fail(name, "user must be set to a non-root user")
    for key in FORBIDDEN_KEYS:
        if svc.get(key):
            fail(name, f"{key} is forbidden")
    for key in HOST_NAMESPACE_KEYS:
        if str(svc.get(key) or "").startswith(("host", "container:", "service:")):
            fail(name, f"{key} must not share another namespace")


def check_filesystem(name, svc):
    if svc.get("read_only") is not True:
        fail(name, "read_only must be true")
    for entry in svc.get("tmpfs") or []:
        path, _, options = str(entry).partition(":")
        flags = set(options.split(","))
        if not TMPFS_FLAGS <= flags or not any(f.startswith("size=") for f in flags):
            fail(name, f"tmpfs {path} needs size=, noexec, nosuid and nodev")
    for vol in svc.get("volumes") or []:
        if DOCKER_SOCKET in str(vol.get("source", "")) or DOCKER_SOCKET in str(vol.get("target", "")):
            fail(name, "the Docker socket must never be mounted")
        if vol.get("type") == "bind" and vol.get("read_only") is not True:
            fail(name, f"bind mount {vol.get('target')} must be read-only")


def check_resources(name, svc):
    mem = as_int(svc.get("mem_limit"), 0)
    if mem <= 0:
        fail(name, "mem_limit is missing")
    if as_int(svc.get("memswap_limit"), -1) != mem:
        fail(name, "memswap_limit must equal mem_limit (no swap)")
    if as_int(svc.get("pids_limit"), 0) <= 0:
        fail(name, "pids_limit is missing")
    if not svc.get("cpus"):
        fail(name, "cpus is missing")
    # Docker mounts /dev/shm writable in every container; its size must be stated, not inherited
    if as_int(svc.get("shm_size"), 0) <= 0:
        fail(name, "shm_size is missing (/dev/shm)")
    nofile = (svc.get("ulimits") or {}).get("nofile")
    if not nofile:
        fail(name, "ulimits.nofile is missing")
    if svc.get("restart") not in RESTART_POLICIES:
        fail(name, "restart policy is missing")
    health = svc.get("healthcheck") or {}
    if not health.get("test") or health.get("disable"):
        fail(name, "healthcheck is missing")
    if name in NEEDS_INIT and svc.get("init") is not True:
        fail(name, "init must be true (PID 1 reaps no children)")


def check_logging(name, svc):
    logging = svc.get("logging") or {}
    options = logging.get("options") or {}
    if logging.get("driver") != LOG_DRIVER or any(not options.get(o) for o in LOG_OPTIONS):
        fail(name, f"logging must use the {LOG_DRIVER} driver with " + " and ".join(LOG_OPTIONS))


def duration_seconds(raw):
    """Compose durations as rendered ("30s", "1m30s"); None when unparseable."""
    text = str(raw or "").strip()
    parts = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m(?!s))?(?:(\d+)s)?", text)
    if not text or not parts:
        return None
    hours, minutes, secs = (int(p or 0) for p in parts.groups())
    return hours * 3600 + minutes * 60 + secs


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        fail("repository", f"{path.relative_to(ROOT)} is missing")
        return ""


def shutdown_budget():
    """shutdownGrace + jobStopDeadline from main.go, in seconds (None when not found)."""
    source = read(MAIN_GO)
    total = 0
    for name in SHUTDOWN_CONSTANTS:
        found = re.search(name + r"\s*=\s*(\d+)\s*\*\s*time\.Second", source)
        if not found:
            fail("backend", f"{name} not found in {MAIN_GO.relative_to(ROOT)}")
            return None
        total += int(found.group(1))
    return total


def check_backend_lifecycle(svc):
    env = svc.get("environment") or {}
    if str(env.get("BACKEND_PORT")) != BACKEND_PORT:
        fail("backend", f"BACKEND_PORT must be pinned to {BACKEND_PORT} (nginx and the healthcheck use it)")
    test = " ".join(str(t) for t in ((svc.get("healthcheck") or {}).get("test") or []))
    if f"127.0.0.1:{BACKEND_PORT}{HEALTH_PATH}" not in test:
        fail("backend", f"healthcheck must probe http://127.0.0.1:{BACKEND_PORT}{HEALTH_PATH} (it touches the database)")
    budget = shutdown_budget()
    grace = duration_seconds(svc.get("stop_grace_period"))
    if budget is not None and (grace is None or grace <= budget):
        fail("backend", f"stop_grace_period must exceed shutdownGrace + jobStopDeadline ({budget} s)")


def go_strings(source):
    """Every `name = "text"` constant in a Go source."""
    return dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', source))


def edge_answers():
    """{id: expected JSON body} from apperr/edge.go, rendered as EdgeAnswer.Body does."""
    sentences = go_strings(read(APPERR_GO))
    edge = read(EDGE_GO)
    sentences.update(go_strings(edge))
    answers = {}
    for code, status, say in re.findall(r'\{"(E_[A-Z0-9_]+)", http\.Status(\w+), (\w+)\}', edge):
        number = HTTPStatus[re.sub(r"(?<!^)(?=[A-Z])", "_", status).upper()].value
        body = json.dumps({"success": False, "message": sentences.get(say, ""), "code": code}, separators=(",", ":"))
        answers[code] = (number, body)
    if not answers:
        fail("apperr", "no EdgeAnswers found in edge.go")
    return answers


def check_nginx():
    site, errors = read(NGINX_SITE), read(NGINX_API_ERRORS)
    for line in NGINX_LOG_LINES:
        if line not in site.splitlines():
            fail("nginx", f"nginx-site.conf must keep '{line}'")
    if API_DEFAULT_DENY not in site.splitlines():
        fail("nginx", "the /api/ default-deny line is missing")
    proxy = read(NGINX_API_PROXY)
    for header, value in NGINX_OWNED_HEADERS.items():
        if f'add_header {header} "{value}" always;' not in site.splitlines():
            fail("nginx", f"nginx-site.conf must send {header}: {value} on every response")
        if f"proxy_hide_header {header};" not in proxy.splitlines():
            fail("nginx", f"nginx-api-proxy.conf must hide the backend's {header} (one header, never two)")
    for header in NGINX_OWNED_BY_NAME:
        if len([line for line in site.splitlines() if line.startswith(f"add_header {header} ")]) != 1:
            fail("nginx", f"nginx-site.conf must send {header} once, at server level")
        if f"proxy_hide_header {header};" not in proxy.splitlines():
            fail("nginx", f"nginx-api-proxy.conf must hide the backend's {header} (one header, never two)")
    hidden = {f'"{h}"' for h in list(NGINX_OWNED_HEADERS) + list(NGINX_OWNED_BY_NAME)}
    for header in BACKEND_HEADER_SET.findall(read(SECURITY_GO)):
        if header not in hidden and header not in BACKEND_HEADERS_KEPT:
            fail("backend", f"security.go sets {header}, which nginx does not hide: an API answer would carry two")
    if "proxy_intercept_errors off;" not in errors or re.search(r"proxy_intercept_errors\s+on", site + errors):
        fail("nginx", "proxy_intercept_errors must be off: the backend's coded answers pass through")
    # Every location that proxies to the backend answers nginx's own failures in JSON
    for block in re.split(r"\n(?=location )", site):
        if API_PROXY_INCLUDE in block and API_ERRORS_INCLUDE not in block:
            fail("nginx", "a location proxies /api/ without " + API_ERRORS_INCLUDE)
    # Every JSON body nginx returns is a registered edge answer, byte for byte, with its status
    answers = edge_answers()
    returned = re.findall(r"return (\d{3}) '([^']*)';", site)
    for status, body in returned:
        code = (json.loads(body) if body.startswith("{") else {}).get("code", "")
        if code not in answers or answers[code] != (int(status), body):
            fail("nginx", f"a JSON answer ({status}) is not the one registered in apperr/edge.go")
    missing = set(answers) - {json.loads(b).get("code") for _, b in returned if b.startswith("{")}
    if missing:
        fail("nginx", "registered edge answers nginx never returns: " + ", ".join(sorted(missing)))
    check_error_page_statuses(site + "\n" + errors, answers)
    check_status_pages(site)
    check_events_location(site)
    check_files_location(site, read(NGINX_CONF))


def check_events_location(site):
    """The stream passes no proxy unbuffered: this nginx does not buffer it, and an outer one is
    told not to by the X-Accel-Buffering field this nginx would otherwise swallow."""
    blocks = [b for b in re.split(r"\n(?=location )", site) if b.startswith(EVENTS_LOCATION)]
    if len(blocks) != 1:
        fail("nginx", f"nginx-site.conf must have exactly one '{EVENTS_LOCATION}' location")
        return
    lines = {line.strip() for line in blocks[0].splitlines()}
    for line in EVENTS_STREAM_LINES:
        if line not in lines:
            fail("nginx", f"the event stream location must keep '{line}'")
    if any(line.startswith("add_header") for line in lines):
        fail("nginx", "no add_header in the event stream location: it would drop the server's headers")


def check_files_location(site, main):
    """File requests hold about 0.7 MB each in nginx and 2 MB in the backend: the files location
    admits at most the backend's own bound at once (one zone key for every client), refuses one
    more with 503 (the registered edge body), and keeps bodies in memory, never in temp files."""
    blocks = [b for b in re.split(r"\n(?=location )", site) if FILES_LOCATION.match(b)]
    if len(blocks) != 1:
        fail("nginx", "nginx-site.conf must have exactly one file parts location")
        return
    bound = FILES_BOUND.search(read(FILES_GO))
    if not bound:
        fail("nginx", "backend/internal/handlers/files.go no longer states maxConcurrentFileRequests")
        return
    lines = {line.strip() for line in blocks[0].splitlines()}
    for line in (f"limit_conn files {bound.group(1)};",) + FILES_MEMORY_LINES:
        if line not in lines:
            fail("nginx", f"the file parts location must keep '{line}'")
    per_client = [int(m.group(1)) for m in map(FILES_PER_CLIENT.match, lines) if m]
    if len(per_client) != 1 or not 1 <= per_client[0] < int(bound.group(1)) // 2:
        fail("nginx", "the file parts location must limit each client address to fewer than half the pool")
    for zone in FILES_ZONES:
        if zone not in main.splitlines():
            fail("nginx", f"nginx.conf must define '{zone}'")
    if not FILES_KEY_MAP.search(main):
        fail("nginx", "nginx.conf must key the files zone by one value for every request")
    if any(line.startswith("add_header") for line in lines):
        fail("nginx", "no add_header in the file parts location: it would drop the server's headers")


def check_error_page_statuses(config, answers):
    """Every error_page to an edge-answer location states =NNN, the status edge.go registers for
    that location's code: without it nginx keeps the triggering status (a 504 answered 504 with
    E_BACKEND_UNAVAILABLE, which the agent reads as E_AGENT_SERVER_ANSWER)."""
    codes = {name: json.loads(body).get("code", "") for name, body in NAMED_ANSWER.findall(config)}
    for _, status, name in ERROR_PAGE_NAMED.findall(config):
        if name not in codes:
            continue
        expected = answers.get(codes[name], (None, ""))[0]
        if status == "" or int(status) != expected:
            fail("nginx", f"error_page to @{name} must state ={expected} (the status of {codes[name]} in apperr/edge.go)")


def check_status_pages(site):
    """The 404 page is the only status page: nginx's error_page 404 target, the one location that
    serves a status page (exactly that URI), the page the app redirects to, and the only HTML file
    in frontend/ besides the SPA's own."""
    target = ERROR_PAGE_404.findall(site)
    if len(target) != 1:
        fail("nginx", "nginx-site.conf must name exactly one error_page 404 target")
        return
    page = target[0]
    if HTML_LOCATION.findall(site) != [f"location = {page} {{"]:
        fail("nginx", f"the only status-page location must be the exact location of {page}")
    if NOT_FOUND_PAGE.findall(read(UTILS_JS)) != [page]:
        fail("frontend", f"utils.js STATUS_PAGES.NOT_FOUND must be {page}")
    pages = sorted("/" + p.name for p in FRONTEND.glob("*.html") if p.name != SPA_PAGE)
    if pages != [page]:
        fail("frontend", "the only status page in frontend/ must be the 404 page; found: " + ", ".join(pages))


def render_edge(value, out_dir):
    """Runs the renderer as the nginx entrypoint does; its exit code (None if it would not run)."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), EDGE_SETTING: value, EDGE_OUT_DIR: out_dir}
    try:
        return subprocess.run(["sh", str(EDGE_RENDERER)], env=env, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=EDGE_RENDER_TIMEOUT_SEC, check=False).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def rendered_edge(value):
    """(exit code, realip file, geo file) for one EDGE_TRUSTED_PROXIES value."""
    with tempfile.TemporaryDirectory() as out_dir:
        code = render_edge(value, out_dir)
        texts = []
        for name in (EDGE_REALIP_FILE, EDGE_GEO_FILE):
            try:
                texts.append(Path(out_dir, name).read_text(encoding="utf-8"))
            except OSError:
                texts.append(None)
        return code, texts[0], texts[1]


def entries(text):
    """The lines of a rendered file that are not comments."""
    return [line for line in (text or "").splitlines() if line.strip() and not line.startswith("#")]


def check_edge_proxies(services):
    """EDGE_TRUSTED_PROXIES: an address or protocol a request names is believed only from a
    listed proxy, on the clearnet listener; the default (empty) believes none; a malformed list
    stops nginx (nginx.conf, nginx-edge-proxies.sh)."""
    conf, site, proxy, errors = read(NGINX_CONF), read(NGINX_SITE), read(NGINX_API_PROXY), read(NGINX_API_ERRORS)
    # Comments may name what is forbidden; only directives count
    static = "\n".join(line for text in (conf, site, proxy, errors) for line in text.splitlines()
                       if not line.lstrip().startswith("#"))
    for directive in REALIP_DIRECTIVES:
        if re.search(r"^\s*" + directive + r"\b", static, re.MULTILINE):
            fail("nginx", f"{directive} belongs only in the file rendered from {EDGE_SETTING}")
    if CLIENT_FORWARDING.search(static):
        fail("nginx", "a client-sent forwarding header is passed on or used outside the protocol map")
    for header, variable in FORWARDED_HEADERS.items():
        if f"proxy_set_header {header} {variable};" not in proxy.splitlines():
            fail("nginx", f"nginx-api-proxy.conf must set {header} from {variable}")
    if not EDGE_GEO.search(conf):
        fail("nginx", "nginx.conf must decide $edge_peer by geo on $realip_remote_addr, default 0, from the rendered list")
    proto = PROTO_MAP.search(conf)
    if not proto or [" ".join(line.split()) for line in proto.group(1).splitlines()] != PROTO_MAP_LINES:
        fail("nginx", "$forwarded_proto must be $scheme unless a listed proxy on the clearnet listener names http or https")
    servers = SERVER_BLOCK.findall(conf)
    clearnet = [body for body in servers if CLEARNET_LISTEN in body]
    onion = [body for body in servers if ONION_LISTEN in body]
    if len(clearnet) != 1 or EDGE_REALIP_INCLUDE not in clearnet[0]:
        fail("nginx", f"the clearnet server must include {EDGE_REALIP_FILE}")
    if len(onion) != 1 or EDGE_REALIP_INCLUDE in onion[0]:
        fail("nginx", f"the onion server must not include {EDGE_REALIP_FILE}: its peer is tor")
    env = services.get("frontend", {}).get("environment") or {}
    if EDGE_SETTING not in env:
        fail("frontend", f"{EDGE_SETTING} must be passed to nginx (empty by default)")
    code, realip, geo = rendered_edge(str(env.get(EDGE_SETTING) or ""))
    if code is None:
        fail("nginx", f"{EDGE_RENDERER.name} cannot be run")
        return
    if code != 0:
        fail("frontend", f"{EDGE_SETTING} is malformed: nginx would refuse to start")
    code, realip, geo = rendered_edge("")
    if code != 0 or realip is None or geo is None or entries(realip) or entries(geo):
        fail("nginx", f"an empty {EDGE_SETTING} must render both files without a single entry")
    code, realip, geo = rendered_edge(",".join(EDGE_SAMPLE))
    want_realip = [f"set_real_ip_from {e};" for e in EDGE_SAMPLE] + ["real_ip_header X-Forwarded-For;", "real_ip_recursive on;"]
    if code != 0 or entries(realip) != want_realip or entries(geo) != [f"{e} 1;" for e in EDGE_SAMPLE]:
        fail("nginx", f"{EDGE_RENDERER.name} must render one set_real_ip_from and one geo entry per listed proxy")
    for value in EDGE_MALFORMED:
        if rendered_edge(value)[0] in (0, None):
            fail("nginx", f"{EDGE_RENDERER.name} accepts a malformed {EDGE_SETTING}")


def rendered_hsts(settings):
    """(exit code, rendered map or None) for one set of HSTS settings, as the entrypoint runs it."""
    with tempfile.TemporaryDirectory() as out_dir:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), HSTS_OUT_DIR: out_dir}
        env.update(settings)
        try:
            code = subprocess.run(["sh", str(HSTS_RENDERER)], env=env, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=EDGE_RENDER_TIMEOUT_SEC, check=False).returncode
        except (OSError, subprocess.TimeoutExpired):
            return None, None
        try:
            return code, Path(out_dir, HSTS_MAP_FILE).read_text(encoding="utf-8")
        except OSError:
            return code, None


def check_hsts(services):
    """HSTS has one source: nginx's server-level header from $hsts, on every answer of the
    clearnet listener in production when a listed edge proxy vouched for HTTPS, never on the
    onion listener, in development or with a max-age of 0; a malformed setting stops nginx."""
    conf, site = read(NGINX_CONF), read(NGINX_SITE)
    server_level = site.split("\nlocation ", 1)[0].splitlines()
    if site.splitlines().count(HSTS_ADD_HEADER) != 1 or HSTS_ADD_HEADER not in server_level:
        fail("nginx", f"nginx-site.conf must send '{HSTS_ADD_HEADER}' once, at server level")
    others = [text for text in (conf, read(NGINX_API_PROXY), read(NGINX_API_ERRORS))
              if HSTS_HEADER in "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))]
    directives = [line for line in site.splitlines() if HSTS_HEADER in line and not line.lstrip().startswith("#")]
    if others or directives != [HSTS_ADD_HEADER]:
        fail("nginx", f"{HSTS_HEADER} must have no source in nginx but '{HSTS_ADD_HEADER}'")
    for path in BACKEND_SOURCES.rglob("*.go"):
        if not path.name.endswith("_test.go") and HSTS_HEADER in path.read_text(encoding="utf-8"):
            fail("backend", f"{path.relative_to(ROOT)} names {HSTS_HEADER}: nginx is its one source")
    if not HSTS_MAP.search(conf):
        fail("nginx", "nginx.conf must decide $hsts by map on the PROXY address and $forwarded_proto, default empty, from hsts.map")
    env = services.get("frontend", {}).get("environment") or {}
    for setting in HSTS_SETTINGS:
        if setting not in env:
            fail("frontend", f"{setting} must be passed to nginx (nginx-hsts.sh)")
    backend = services.get("backend", {}).get("environment") or {}
    for setting in HSTS_SETTINGS[1:]:
        if setting in backend:
            fail("backend", f"{setting} belongs to nginx now: the backend sends no HSTS")
    code, _ = rendered_hsts({k: str(env.get(k) or "") for k in HSTS_SETTINGS})
    if code is None:
        fail("nginx", f"{HSTS_RENDERER.name} cannot be run")
        return
    if code != 0:
        fail("frontend", "an HSTS setting is malformed: nginx would refuse to start")
    for settings, want in HSTS_CASES:
        code, text = rendered_hsts(settings)
        if code != 0 or text is None or entries(text) != ([want] if want else []):
            fail("nginx", f"{HSTS_RENDERER.name} with {settings} must render {want or 'no entry'}")
    for settings in HSTS_MALFORMED:
        if rendered_hsts(settings)[0] in (0, None):
            fail("nginx", f"{HSTS_RENDERER.name} accepts the malformed {settings}")


def check_backend_memory(svc):
    bound = FILES_BOUND.search(read(FILES_GO))
    if not bound:
        fail("backend", "backend/internal/handlers/files.go no longer states maxConcurrentFileRequests")
        return
    need = int(bound.group(1)) * FILE_REQUEST_BYTES + BACKEND_HEADROOM_BYTES
    if as_int(svc.get("mem_limit"), 0) < need:
        fail("backend", "mem_limit (BACKEND_MEM_LIMIT) is below maxConcurrentFileRequests x file request "
             f"+ {BACKEND_HEADROOM_BYTES >> 20} MiB ({-(-need // (1 << 20))} MiB needed)")


def check_ports(name, svc, layout):
    ports = svc.get("ports") or []
    if ports and name not in PUBLISHERS[layout]:
        fail(name, f"must not publish a port in the {layout} layout")
    for port in ports:
        if port.get("host_ip") != LOOPBACK:
            fail(name, f"published port {port.get('target')} must bind {LOOPBACK} only")


def check_networks(name, svc, layout, networks):
    want = set(NETWORKS.get(name, set()))
    if layout == "development" and name in PUBLISHERS["development"] - PUBLISHERS["production"]:
        want.add(DEV_NETWORK)
    have = set((svc.get("networks") or {}).keys())
    if have != want:
        fail(name, "networks must be exactly " + ", ".join(sorted(want)))
    for net in INTERNAL_NETWORKS:
        spec = networks.get(net) or {}
        if net in have and spec.get("internal") is not True:
            fail(name, f"network {net} must be internal")
        if net in have and (spec.get("driver_opts") or {}).get(GATEWAY_MODE) != ISOLATED:
            fail(name, f"network {net} must set {GATEWAY_MODE}={ISOLATED}")


def address(services, name, net):
    return str(((services.get(name, {}).get("networks") or {}).get(net) or {}).get("ipv4_address") or "")


def check_trust(services):
    """The backend trusts nginx's fixed app address; nginx's onion listener trusts tor's."""
    proxy = address(services, "frontend", "app")
    if not proxy:
        fail("frontend", "needs a fixed ipv4_address on app (PROXY_IP)")
    if not address(services, "backend", "app"):
        fail("backend", "needs a fixed ipv4_address on app (BACKEND_IP)")
    trusted = str((services.get("backend", {}).get("environment") or {}).get("TRUSTED_PROXIES") or "")
    if proxy and proxy not in [t.strip() for t in trusted.split(",")]:
        fail("backend", "TRUSTED_PROXIES must name nginx's app address (PROXY_IP)")
    tor = address(services, "tor", "edge")
    tor_env = str((services.get("frontend", {}).get("environment") or {}).get("TOR_IP") or "")
    if "tor" in services and (not tor or tor != tor_env):
        fail("tor", "TOR_IP (nginx's onion allowlist) must equal tor's fixed edge address")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in PUBLISHERS:
        print("usage: check-hardening.py production|development < rendered-config.json", file=sys.stderr)
        return 2
    layout = sys.argv[1]
    try:
        config = json.load(sys.stdin)
    except ValueError:
        print("[ERROR] check-hardening: the rendered compose config is not JSON", file=sys.stderr)
        return 2
    services = config.get("services") or {}
    networks = config.get("networks") or {}
    missing = set(NETWORKS) - set(services)
    if missing:
        print("[ERROR] check-hardening: services missing: " + ", ".join(sorted(missing)), file=sys.stderr)
        return 2
    for name, svc in sorted(services.items()):
        check_privileges(name, svc)
        check_filesystem(name, svc)
        check_resources(name, svc)
        check_ports(name, svc, layout)
        check_networks(name, svc, layout, networks)
        check_logging(name, svc)
    check_backend_memory(services["backend"])
    check_backend_lifecycle(services["backend"])
    check_trust(services)
    check_nginx()
    check_edge_proxies(services)
    check_hsts(services)
    if failures:
        for line in failures:
            print(f"[FAIL] {layout}: {line}")
        return 1
    print(f"[OK] check-hardening: {layout} layout, {len(services)} services keep every control")
    return 0


if __name__ == "__main__":
    sys.exit(main())
