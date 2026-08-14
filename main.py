#!/usr/bin/env python3
"""
vps_mcp_agent.py
================
Plug-and-play MCP server that gives ChatGPT (or any MCP client) direct,
unsandboxed access to THIS machine - shell commands, Python execution,
file read/write, and basic system diagnostics. No separate "worker" -
this process is both the MCP host and the thing that does the work, so
it's meant to run on a dedicated VPS/computer you actually want an
assistant to be able to inspect and fix.

What it does, in order:
  1. Bootstraps its own Python dependencies (installs anything missing,
     falling back to an isolated venv if the system Python refuses).
  2. Downloads a matching `cloudflared` binary if one isn't on PATH.
  3. Starts a local MCP server (Streamable HTTP) with tools ChatGPT can
     call: run_shell, run_python, read_file, write_file, system_info.
  4. Opens a Cloudflare Quick Tunnel and prints the public MCP URL,
     with a auth token that's generated once and reused across restarts.
  5. Optionally stays running after you log out (--daemon), or installs
     itself as a systemd service (--install-service) that survives
     reboots and auto-restarts if it crashes.

Quick start on a fresh VPS:
    python3 vps_mcp_agent.py --install-service     # recommended
    journalctl -u vps-mcp-agent -f                 # watch logs / get URL

Or just try it in the foreground first:
    python3 vps_mcp_agent.py

SECURITY - read this before you run it:
  run_shell and run_python execute with the same permissions as whoever
  starts this process, with NO sandbox, by design. Anyone who has the
  MCP URL (or the bearer token) can run arbitrary commands on this
  machine - treat that URL exactly like a root password. It's generated
  once and stored in ~/.vps_mcp_agent/token; run with --rotate-token any
  time you think it's leaked. If you install the systemd service as
  root, commands run as root. Consider putting Cloudflare Access (an
  email/SSO login gate) in front of the tunnel for a second layer.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import uuid
from pathlib import Path

# --------------------------------------------------------------------------
# 0. Basic environment checks + working directory
# --------------------------------------------------------------------------

if sys.version_info < (3, 10):
    sys.exit(
        "vps_mcp_agent.py needs Python 3.10 or newer "
        f"(found {sys.version.split()[0]}). Please upgrade Python and re-run."
    )

WORK_DIR = Path.home() / ".vps_mcp_agent"
BIN_DIR = WORK_DIR / "bin"
WORK_DIR.mkdir(parents=True, exist_ok=True)
BIN_DIR.mkdir(parents=True, exist_ok=True)

TOKEN_FILE = WORK_DIR / "token"
PID_FILE = WORK_DIR / "agent.pid"
STATUS_FILE = WORK_DIR / "status.json"
LOG_FILE = WORK_DIR / "agent.log"

AUTH_TOKEN: str | None = None  # set in main() before the server starts


# --------------------------------------------------------------------------
# 1. Dependency bootstrap - auto-install anything missing, and fall back to
#    an isolated virtualenv if the system Python refuses installs.
# --------------------------------------------------------------------------

REQUIRED_PACKAGES = ["fastmcp", "uvicorn"]
if platform.system() == "Windows":
    REQUIRED_PACKAGES.append("pywin32")
VENV_DIR = WORK_DIR / "venv"


def _have_deps() -> bool:
    try:
        from fastmcp import FastMCP  # noqa: F401
        import uvicorn  # noqa: F401
        return True
    except ImportError:
        return False


def _venv_python() -> Path:
    sub = "Scripts/python.exe" if platform.system() == "Windows" else "bin/python"
    return VENV_DIR / sub


def _in_target_venv() -> bool:
    try:
        return Path(sys.prefix).resolve() == VENV_DIR.resolve()
    except OSError:
        return False


def _try_pip_install(python_exe: str, packages: list[str]) -> bool:
    for extra_flags in ([], ["--break-system-packages"]):
        cmd = [python_exe, "-m", "pip", "install", "-q", "--upgrade", *extra_flags, *packages]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return True
    print(result.stdout[-1500:])
    print(result.stderr[-1500:])
    return False


def ensure_deps() -> None:
    if _have_deps():
        return

    if _in_target_venv():
        if not _try_pip_install(sys.executable, REQUIRED_PACKAGES):
            sys.exit("[setup] pip install failed even inside a fresh virtualenv.")
        return

    print(f"[setup] installing missing Python packages: {', '.join(REQUIRED_PACKAGES)}")
    if _try_pip_install(sys.executable, REQUIRED_PACKAGES):
        return

    print("[setup] system Python install was blocked - creating an isolated "
          f"virtual environment at {VENV_DIR} instead")
    subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    venv_py = str(_venv_python())
    if not _try_pip_install(venv_py, ["pip", *REQUIRED_PACKAGES]):
        sys.exit("[setup] pip install failed inside the new virtualenv too - "
                  "please install fastmcp and uvicorn manually.")

    print("[setup] re-launching inside the virtual environment...")
    os.execv(venv_py, [venv_py, str(Path(__file__).resolve()), *sys.argv[1:]])


ensure_deps()

try:
    import uvicorn  # noqa: E402
    from fastmcp import FastMCP  # noqa: E402
    from starlette.requests import Request  # noqa: E402
    from starlette.responses import JSONResponse, PlainTextResponse  # noqa: E402
except ImportError as exc:
    print(f"[setup] import still failing after install ({exc}) - trying one more fix...")
    remedy: list[str] = []
    msg = str(exc).lower()
    if platform.system() == "Windows" and ("pywintypes" in msg or "win32" in msg):
        remedy = ["pywin32"]
    if remedy and _try_pip_install(sys.executable, remedy):
        import uvicorn  # noqa: E402
        from fastmcp import FastMCP  # noqa: E402
        from starlette.requests import Request  # noqa: E402
        from starlette.responses import JSONResponse, PlainTextResponse  # noqa: E402
    else:
        sys.exit(f"[setup] required packages still won't import: {exc}")


# --------------------------------------------------------------------------
# 2. cloudflared bootstrap - detect, else download the right binary
# --------------------------------------------------------------------------

CLOUDFLARED_RELEASE_BASE = (
    "https://github.com/cloudflare/cloudflared/releases/latest/download"
)


def _cloudflared_asset_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
                "arm64": "arm64", "armv7l": "arm", "i386": "386", "i686": "386"}.get(machine, "amd64")
        return f"cloudflared-linux-{arch}"
    if system == "darwin":
        arch = {"x86_64": "amd64", "arm64": "arm64"}.get(machine, "arm64")
        return f"cloudflared-darwin-{arch}.tgz"
    if system == "windows":
        arch = {"amd64": "amd64", "x86_64": "amd64"}.get(machine, "amd64")
        return f"cloudflared-windows-{arch}.exe"
    raise RuntimeError(f"Unsupported OS for cloudflared: {system}")


def _extract_darwin_tgz(tgz_path: Path, dest: Path) -> None:
    with tarfile.open(tgz_path, "r:gz") as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("cloudflared"))
        member.name = dest.name
        tf.extract(member, path=dest.parent)


def ensure_cloudflared() -> str:
    on_path = shutil.which("cloudflared")
    if on_path:
        return on_path

    dest = BIN_DIR / ("cloudflared.exe" if platform.system() == "Windows" else "cloudflared")
    if dest.exists():
        return str(dest)

    asset = _cloudflared_asset_name()
    url = f"{CLOUDFLARED_RELEASE_BASE}/{asset}"
    print(f"[setup] cloudflared not found - downloading {url}")

    download_target = BIN_DIR / asset
    try:
        urllib.request.urlretrieve(url, download_target)
    except Exception as exc:  # noqa: BLE001
        sys.exit(
            f"[setup] could not download cloudflared automatically ({exc}).\n"
            "Install it manually from https://github.com/cloudflare/cloudflared/releases "
            "and make sure it's on your PATH, then re-run this script."
        )

    if asset.endswith(".tgz"):
        _extract_darwin_tgz(download_target, dest)
        download_target.unlink(missing_ok=True)
    else:
        download_target.rename(dest)

    if platform.system() != "Windows":
        dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"[setup] cloudflared installed at {dest}")
    return str(dest)


def start_quick_tunnel(port: int, cloudflared_bin: str) -> tuple[subprocess.Popen, str]:
    """Anonymous Cloudflare Quick Tunnel - zero config, but the URL is
    random and changes every time this process restarts."""
    print("[setup] starting Cloudflare Quick Tunnel...")
    proc = subprocess.Popen(
        [cloudflared_bin, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    url_pattern = re.compile(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com")
    found_url: list[str] = []

    def _drain():
        for line in proc.stdout:  # type: ignore[union-attr]
            m = url_pattern.search(line)
            if m and not found_url:
                found_url.append(m.group(0))

    t = threading.Thread(target=_drain, daemon=True)
    t.start()

    deadline = time.time() + 30
    while time.time() < deadline and not found_url:
        time.sleep(0.25)

    if not found_url:
        proc.terminate()
        sys.exit(
            "[setup] timed out waiting for a trycloudflare.com URL.\n"
            "Check that outbound network access to Cloudflare's edge isn't "
            "blocked by a firewall, then re-run."
        )

    return proc, found_url[0]


def start_named_tunnel(token: str, cloudflared_bin: str) -> subprocess.Popen:
    """Stable Cloudflare Tunnel bound to a hostname you configured in the
    Zero Trust dashboard - survives restarts with the same URL. Requires
    CF_TUNNEL_TOKEN (and you should set CF_TUNNEL_HOSTNAME too, just for
    the printed instructions)."""
    print("[setup] starting named Cloudflare Tunnel (stable hostname)...")
    proc = subprocess.Popen(
        [cloudflared_bin, "tunnel", "run", "--token", token],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    return proc


# --------------------------------------------------------------------------
# 3. MCP server: tools that act directly on THIS machine
# --------------------------------------------------------------------------

mcp = FastMCP(
    name="vps-agent",
    instructions=(
        "Tools that run directly on this machine - not sandboxed. "
        "run_shell executes any shell command and run_python executes "
        "arbitrary Python, both with the permissions of the user running "
        "this agent. Use them to inspect logs, install packages, restart "
        "services, edit config files, or otherwise diagnose and fix "
        "problems on this machine. There is no undo for destructive "
        "commands - confirm with the user before anything destructive "
        "(deleting data, dropping databases, stopping production services)."
    ),
)


def _shell_argv(command: str) -> list[str]:
    if platform.system() == "Windows":
        return ["cmd", "/c", command]
    return ["/bin/bash", "-lc", command]


async def _run_argv(argv: list[str], timeout_seconds: int, cwd: str | None = None) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd or None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "status": "timeout",
            "message": f"Still running after {timeout_seconds}s, killed it. "
                       "Call again with a larger timeout_seconds if it needs more time.",
        }

    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "exit_code": proc.returncode,
        "stdout": stdout.decode(errors="replace")[-20000:],
        "stderr": stderr.decode(errors="replace")[-20000:],
    }


@mcp.tool
async def run_shell(command: str, timeout_seconds: int = 60, cwd: str | None = None) -> str:
    """Run a shell command directly on this machine (bash -lc on Linux/
    macOS, cmd /c on Windows) and return stdout, stderr, and the exit
    code. Not sandboxed - runs with this agent's own permissions. Use it
    to inspect or fix the system: check logs, restart services, install
    packages, edit files, check disk/memory, etc."""
    result = await _run_argv(_shell_argv(command), timeout_seconds, cwd)
    return json.dumps(result)


@mcp.tool
async def run_python(code: str, timeout_seconds: int = 60) -> str:
    """Run Python code directly on this machine in a fresh interpreter
    (not sandboxed) and return stdout/stderr. Use print() to capture
    output."""
    tmp = WORK_DIR / f"job_{uuid.uuid4().hex}.py"
    tmp.write_text(code)
    try:
        result = await _run_argv([sys.executable, str(tmp)], timeout_seconds)
    finally:
        tmp.unlink(missing_ok=True)
    return json.dumps(result)


@mcp.tool
def read_file(path: str, max_bytes: int = 200_000) -> str:
    """Read a text file from this machine's filesystem (up to max_bytes)."""
    try:
        data = Path(path).expanduser().read_bytes()[:max_bytes]
        return json.dumps({"status": "ok", "content": data.decode(errors="replace")})
    except Exception as exc:
        return json.dumps({"status": "error", "message": str(exc)})


@mcp.tool
def write_file(path: str, content: str, append: bool = False) -> str:
    """Write (or append to) a text file on this machine's filesystem.
    Creates parent directories if they don't exist."""
    try:
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a" if append else "w") as f:
            f.write(content)
        return json.dumps({"status": "ok", "bytes_written": len(content)})
    except Exception as exc:
        return json.dumps({"status": "error", "message": str(exc)})


@mcp.tool
async def system_info() -> str:
    """Quick system diagnostics: OS/kernel, uptime, disk usage, memory."""
    if platform.system() == "Windows":
        cmds = {
            "os": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
            "disk": "wmic logicaldisk get size,freespace,caption",
            "memory": "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize",
        }
    else:
        cmds = {
            "os": "uname -a",
            "uptime": "uptime",
            "disk": "df -h",
            "memory": "free -h",
        }
    out: dict[str, str] = {}
    for name, cmd in cmds.items():
        result = await _run_argv(_shell_argv(cmd), timeout_seconds=10)
        out[name] = result.get("stdout") or result.get("message", "")
    return json.dumps(out, indent=2)


def _authorized(request: Request) -> bool:
    header = request.headers.get("authorization", "")
    api_key = request.headers.get("x-api-key", "")
    return header == f"Bearer {AUTH_TOKEN}" or api_key == AUTH_TOKEN


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "host": platform.node()})


# --------------------------------------------------------------------------
# 4. Thin auth wrapper around the whole ASGI app
# --------------------------------------------------------------------------

class _AuthMiddleware:
    """Gates every HTTP request except /health. Two ways in:
      - A token embedded in the URL path (/t/<token>/...) - so a client
        with no field for custom headers (e.g. ChatGPT's connector setup)
        can just be given the URL as-is and still be gated.
      - A header (Authorization: Bearer <token> or X-Api-Key: <token>).
    Whoever has that URL or token can run commands on this machine -
    treat it like a password."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token
        self.token_prefix = f"/t/{token}"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/health":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == self.token_prefix or path.startswith(self.token_prefix + "/"):
            stripped = path[len(self.token_prefix):] or "/"
            scope = {**scope, "path": stripped, "raw_path": stripped.encode()}
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode()
        api_key = headers.get(b"x-api-key", b"").decode()
        if auth == f"Bearer {self.token}" or api_key == self.token:
            await self.app(scope, receive, send)
            return

        response = PlainTextResponse("Unauthorized", status_code=401)
        await response(scope, receive, send)


def build_app():
    return _AuthMiddleware(mcp.http_app(), AUTH_TOKEN)


def run_server_in_thread(host: str, port: int) -> None:
    app = build_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    def _run():
        asyncio.run(server.serve())

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection((host if host != "0.0.0.0" else "127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    sys.exit("[setup] local MCP server never came up - aborting.")


# --------------------------------------------------------------------------
# 5. Token persistence + background/process management
# --------------------------------------------------------------------------

def get_or_create_token(rotate: bool = False) -> str:
    if not rotate and TOKEN_FILE.exists():
        tok = TOKEN_FILE.read_text().strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(tok)
    try:
        TOKEN_FILE.chmod(0o600)
    except OSError:
        pass
    return tok


def _pid_alive(pid: int) -> bool:
    if platform.system() == "Windows":
        result = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def daemonize(log_path: Path) -> None:
    """Detach from the controlling terminal so the process survives an
    SSH logout. On POSIX this is a classic double-fork; on Windows it
    relaunches itself as a detached process."""
    if platform.system() == "Windows":
        creationflags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        log_f = open(log_path, "a")
        args = [a for a in sys.argv[1:] if a != "--daemon"]
        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), *args],
            stdout=log_f, stderr=log_f, stdin=subprocess.DEVNULL,
            creationflags=creationflags, close_fds=True,
        )
        PID_FILE.write_text(str(proc.pid))
        print(f"[daemon] started in background (pid {proc.pid}), logging to {log_path}")
        sys.exit(0)

    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "r")
    log_f = open(log_path, "a", buffering=1)
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(log_f.fileno(), sys.stdout.fileno())
    os.dup2(log_f.fileno(), sys.stderr.fileno())
    PID_FILE.write_text(str(os.getpid()))


def stop_daemon() -> None:
    if not PID_FILE.exists():
        print("[stop] no pidfile found - is the agent running (as --daemon or a service)?")
        return
    pid = int(PID_FILE.read_text().strip())
    try:
        if platform.system() == "Windows":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True)
        else:
            os.kill(pid, signal.SIGTERM)
        print(f"[stop] sent stop signal to pid {pid}")
    except (ProcessLookupError, subprocess.CalledProcessError):
        print(f"[stop] process {pid} was not running")
    PID_FILE.unlink(missing_ok=True)


def show_status() -> None:
    running = False
    if PID_FILE.exists():
        try:
            running = _pid_alive(int(PID_FILE.read_text().strip()))
        except ValueError:
            pass
    print(f"[status] running: {running}")
    if STATUS_FILE.exists():
        print(STATUS_FILE.read_text())
    else:
        print("[status] no status.json yet - it's written on first successful start.")


SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=VPS MCP Agent (ChatGPT computer-access bridge)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={python} {script} --port {port}
Restart=always
RestartSec=5
User={user}
WorkingDirectory={workdir}
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""


def install_systemd_service(port: int) -> None:
    if platform.system() != "Linux":
        sys.exit("[install] --install-service only supports Linux (systemd).")

    unit_text = SYSTEMD_UNIT_TEMPLATE.format(
        python=sys.executable,
        script=str(Path(__file__).resolve()),
        port=port,
        user=os.environ.get("SUDO_USER") or getpass.getuser(),
        workdir=str(WORK_DIR),
    )
    local_copy = WORK_DIR / "vps-mcp-agent.service"
    local_copy.write_text(unit_text)

    manual_steps = (
        f"  sudo cp {local_copy} /etc/systemd/system/vps-mcp-agent.service\n"
        "  sudo systemctl daemon-reload\n"
        "  sudo systemctl enable --now vps-mcp-agent"
    )

    if not shutil.which("systemctl"):
        print(f"[install] wrote unit file to {local_copy}")
        print("[install] systemd doesn't seem to be available on this machine")
        print("(common inside Docker containers - use the container's own")
        print("--restart policy instead, or run with --daemon). If this is a")
        print(f"real VPS with systemd, install it manually:\n{manual_steps}")
        return

    if os.geteuid() != 0:
        print(f"[install] wrote unit file to {local_copy}")
        print("[install] not running as root - finish the install with:")
        print(manual_steps)
        return

    dest = Path("/etc/systemd/system/vps-mcp-agent.service")
    dest.write_text(unit_text)
    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, text=True)
        subprocess.run(["systemctl", "enable", "--now", "vps-mcp-agent"], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        print(f"[install] wrote {dest} but systemctl failed: {exc.stderr or exc}")
        print("(common inside Docker containers, where systemd isn't actually")
        print("running as PID 1 even if the systemctl binary is present - use")
        print("the container's own --restart policy instead, or --daemon)")
        print(f"On a real VPS, try running the commands manually:\n{manual_steps}")
        return
    print("[install] systemd service installed & started: vps-mcp-agent")
    print("  Logs:  journalctl -u vps-mcp-agent -f")
    print("  Stop:  sudo systemctl stop vps-mcp-agent")
    print("  Status: sudo systemctl status vps-mcp-agent")


# --------------------------------------------------------------------------
# 6. Main
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--port", type=int, default=8642, help="local port for the MCP server")
    parser.add_argument("--daemon", action="store_true",
                         help="detach and keep running after you close this terminal/SSH session")
    parser.add_argument("--stop", action="store_true", help="stop a background agent (--daemon or service)")
    parser.add_argument("--status", action="store_true", help="show whether the agent is running, and its URL")
    parser.add_argument("--install-service", action="store_true",
                         help="install + start as a systemd service (recommended on a VPS, Linux only)")
    parser.add_argument("--rotate-token", action="store_true",
                         help="generate a new auth token (invalidates the old connector URL)")
    parser.add_argument("--no-tunnel", action="store_true",
                         help="skip the Cloudflare tunnel and bind on 0.0.0.0 (e.g. behind your own reverse proxy)")
    args = parser.parse_args()

    if args.stop:
        stop_daemon()
        return
    if args.status:
        show_status()
        return
    if args.install_service:
        install_systemd_service(args.port)
        return

    global AUTH_TOKEN
    AUTH_TOKEN = get_or_create_token(rotate=args.rotate_token)

    if args.daemon:
        daemonize(LOG_FILE)
        # only the detached child/background process continues past this point

    PID_FILE.write_text(str(os.getpid()))

    host = "0.0.0.0" if args.no_tunnel else "127.0.0.1"
    print(f"[setup] starting MCP server on {host}:{args.port} ...")
    run_server_in_thread(host, args.port)

    tunnel_proc = None
    if args.no_tunnel:
        tunnel_url = f"http://<this-machine's-ip-or-domain>:{args.port}"
    else:
        cloudflared_bin = ensure_cloudflared()
        cf_named_token = os.environ.get("CF_TUNNEL_TOKEN")
        if cf_named_token:
            tunnel_proc = start_named_tunnel(cf_named_token, cloudflared_bin)
            tunnel_url = os.environ.get("CF_TUNNEL_HOSTNAME", "<see your Cloudflare Zero Trust dashboard>")
        else:
            tunnel_proc, tunnel_url = start_quick_tunnel(args.port, cloudflared_bin)

    def _cleanup(*_a):
        if tunnel_proc:
            tunnel_proc.terminate()
        PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    if platform.system() != "Windows":
        signal.signal(signal.SIGTERM, _cleanup)
        signal.signal(signal.SIGINT, _cleanup)

    mcp_url = f"{tunnel_url}/t/{AUTH_TOKEN}/mcp"
    status = {
        "pid": os.getpid(),
        "port": args.port,
        "tunnel_url": tunnel_url,
        "mcp_url": mcp_url,
        "started_at": time.time(),
    }
    STATUS_FILE.write_text(json.dumps(status, indent=2))

    print("\n" + "=" * 72)
    print("READY - this machine is the MCP host AND the worker")
    print("=" * 72)
    print(f"MCP server URL : {mcp_url}")
    print("Authentication  : No authentication (token is baked into the URL)")
    print(f"Bearer token    : {AUTH_TOKEN}")
    print(f"                  (stored in {TOKEN_FILE}, stable across restarts -")
    print("                   re-run with --rotate-token to invalidate it)")
    print()
    print("In ChatGPT: Settings -> Apps -> Advanced -> Developer mode -> on")
    print("Settings -> Connectors -> Create -> paste the MCP server URL above.")
    if not args.no_tunnel and not os.environ.get("CF_TUNNEL_TOKEN"):
        print()
        print("NOTE: this is a Cloudflare Quick Tunnel - the URL changes every")
        print("time this process restarts. For a stable URL across restarts,")
        print("create a named tunnel in the Cloudflare Zero Trust dashboard and")
        print("export CF_TUNNEL_TOKEN (and CF_TUNNEL_HOSTNAME) before starting.")
    if not args.daemon:
        print()
        print("Running in the foreground - this stops if you close the terminal")
        print("or the SSH session drops. Use --daemon to keep it alive in the")
        print("background, or --install-service for auto-restart + boot survival.")
    print("=" * 72)

    try:
        while True:
            time.sleep(30)
            status["last_heartbeat"] = time.time()
            STATUS_FILE.write_text(json.dumps(status, indent=2))
    except KeyboardInterrupt:
        _cleanup()


if __name__ == "__main__":
    main()
