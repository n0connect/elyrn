"""Checks the rendered Compose config for the container controls of docs/operations/hardening.md.

Usage (make check-hardening): docker compose ... config --format json | python3 -I scripts/check-hardening.py <production|development>

The rendered config holds values from .env (secrets among them): this script prints service,
key and variable names only, never a value from the input. It also reads the nginx files and
two backend sources from the repository (no secrets there): nginx's own /api/ answers must be
the ones registered in backend/internal/apperr/edge.go, the 404 page must be the only status
page (nginx's error_page 404 target, its one HTML location, frontend/js/utils.js
STATUS_PAGES.NOT_FOUND and the only HTML file in frontend/ besides index.html), and the backend's stop grace must
outlast its shutdown budget in backend/cmd/server/main.go. Exit 0 when every control holds, 1
with one line per failure otherwise, 2 on unusable input.
"""

import json
import re
import sys
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
# The backend's memory limit must hold every Argon2id computation at once plus this much
BACKEND_HEADROOM_BYTES = 128 << 20
KIB = 1024
# Backend defaults (backend/internal/config) when .env leaves a value empty
DEFAULT_ARGON2_MEMORY_KIB = 65536
DEFAULT_ARGON2_MAX_CONCURRENT = 4

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
FRONTEND = ROOT / "frontend"
UTILS_JS = FRONTEND / "js/utils.js"
# The SPA's page; every other HTML file in frontend/ is a status page
SPA_PAGE = "index.html"
# The one status page: nginx's error_page 404 target, served by an exact location, and the page
# frontend/js/utils.js sends an unknown route to
ERROR_PAGE_404 = re.compile(r"^error_page 404 (/[\w-]+\.html);$", re.MULTILINE)
# The opening line of every location that names an HTML file
HTML_LOCATION = re.compile(r"^location [^{\n]*html[^{\n]*\{", re.MULTILINE)
NOT_FOUND_PAGE = re.compile(r"NOT_FOUND: '(/[\w-]+\.html)'")
API_PROXY_INCLUDE = "include /etc/nginx/elyrn/api-proxy.conf;"
API_ERRORS_INCLUDE = "include /etc/nginx/elyrn/api-errors.conf;"
API_DEFAULT_DENY = "location /api/ { " + API_ERRORS_INCLUDE + " return 404; }"
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
    check_status_pages(site)


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


def check_backend_memory(svc):
    env = svc.get("environment") or {}
    kib = as_int(env.get("ARGON2_MEMORY_KIB"), DEFAULT_ARGON2_MEMORY_KIB)
    slots = as_int(env.get("ARGON2_MAX_CONCURRENT"), DEFAULT_ARGON2_MAX_CONCURRENT)
    need = slots * kib * KIB + BACKEND_HEADROOM_BYTES
    if as_int(svc.get("mem_limit"), 0) < need:
        fail("backend", "mem_limit (BACKEND_MEM_LIMIT) is below ARGON2_MAX_CONCURRENT x ARGON2_MEMORY_KIB "
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
    if failures:
        for line in failures:
            print(f"[FAIL] {layout}: {line}")
        return 1
    print(f"[OK] check-hardening: {layout} layout, {len(services)} services keep every control")
    return 0


if __name__ == "__main__":
    sys.exit(main())
