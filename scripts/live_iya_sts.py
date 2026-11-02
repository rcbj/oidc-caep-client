#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Sign the demo SPA in to a fresh iya-sts in a headless browser and confirm
two Shared Signals events.

Starts the latest main branch of iya-sts in memory mode, with persistence and
clustering off and no request workers, unless IYA_STS_URL is already set.
Registers the SPA as a public client by running
scripts/register-iya-sts-client.mjs in the Node image (it also creates the
test user and puts it in ssf-read and ssf-manage). Serves the SPA from the demo
image with an oidc.json pointing at this iya-sts. Then
scripts/live_browser.py, in Playwright's official Python image (with the
playwright package and certutil added by scripts/live-browser.Dockerfile), signs in
through the SPA and iya-sts's /authn screens in headless Chromium and keeps
the page open. This script emits a credential-change and a session-revoked
event through /admin-api/caep/emit and asks the browser for the SPA's
#live-status after each: still signed in after the first, signed out after
the second. The SPA receives both by polling its own SSF stream from the
browser, with its DPoP-bound access token.

TLS: the chain GET /tls/server-certificate returns is leaf, issuing CA,
intermediate, root. This script takes the self-signed root from it, verifies
iya-sts against that root and nothing else, and mounts the root into the
browser container, which adds it to Chromium's NSS database as a trusted CA.
The browser is never told to ignore certificate errors.

This file uses the host's Python (standard library only) and Docker. Node and
the browser run only in containers. Do not bind port 3000, 8081, or 18481 to
18495.

IYA_STS_URL, when set, uses an iya-sts that is already running and does not
stop it. This script never removes iya-sts-live-main, iya-sts-live-probe, or a
container whose name starts with sts. IYA_STS_IMAGE starts a fresh container
from that image. Otherwise it clones main (or builds IYA_STS_SRC) and removes
only the container it started. The demo container it removes is
oidc-caep-client-live-demo and oidc-caep-client-live-browser; the images it
builds are oidc-caep-client-live:demo and oidc-caep-client-live:browser.
"""

import base64
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STS_REPO = "https://github.com/rcbj/iya-sts.git"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
CREDENTIAL_CHANGE = CAEP + "credential-change"
SESSION_REVOKED = CAEP + "session-revoked"
FORBIDDEN_PORTS = {3000, 8081, *range(18481, 18496)}
PROTECTED_CONTAINERS = {"iya-sts-live-main", "iya-sts-live-probe"}
NODE_IMAGE = "node:24.22.1-alpine"
BROWSER_BASE = "mcr.microsoft.com/playwright/python:v1.55.0-noble"
BROWSER_IMAGE = "oidc-caep-client-live:browser"

PROFILE = {
    "repo": "oidc-caep-client",
    "client_id": "oidc-caep-demo",
    "scopes": "openid profile email offline_access ssf.read ssf.manage",
    "test_user_env": "CAEP_DEMO_USER_PASSWORD",
    "test_user": "caep-demo-user",
}


def run(command, **kwargs):
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, check=False, text=True, **kwargs)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, flush=True)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, flush=True)
        raise RuntimeError(f"{command[0]} exited {completed.returncode}")
    return completed


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def docker_rm(name):
    if not name:
        return
    if name in PROTECTED_CONTAINERS or name.startswith("sts"):
        raise RuntimeError(f"refusing to remove {name}")
    subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_port(port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 2):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"127.0.0.1:{port} did not accept a connection")


def https_get(origin, path, context, timeout=10):
    parts = urllib.parse.urlsplit(origin)
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=timeout)
    try:
        conn.request("GET", path, headers={"accept": "*/*"})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def wait_ready(origin, timeout):
    """Wait for discovery to answer. Readiness only: nothing is trusted from it."""
    context = ssl._create_unverified_context()
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, _body = https_get(origin, "/.well-known/openid-configuration", context)
            if status == 200:
                return
            last = f"answered {status}"
        except OSError as err:
            last = str(err)
        time.sleep(2)
    raise RuntimeError(f"{origin} discovery did not answer 200: {last}")


PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def root_of_chain(origin, work):
    """The self-signed root of the chain iya-sts serves at /tls/server-certificate.

    The fetch is unverified because it is how the anchor is learned; what is
    taken from it is then checked by verifying a fresh connection against it.
    """
    status, body = https_get(origin, "/tls/server-certificate", ssl._create_unverified_context())
    text = body.decode("utf-8", "replace")
    blocks = PEM_BLOCK.findall(text)
    if status != 200 or not blocks:
        raise RuntimeError(f"GET /tls/server-certificate answered {status} without a PEM chain")
    roots = []
    for index, block in enumerate(blocks):
        one = work / f"chain-{index}.pem"
        one.write_text(block + "\n", encoding="utf-8")
        decoded = ssl._ssl._test_decode_cert(str(one))
        if decoded.get("subject") == decoded.get("issuer"):
            roots.append((block, decoded))
    if len(roots) != 1:
        raise RuntimeError(f"the chain of {len(blocks)} certificates holds {len(roots)} self-signed roots")
    block, decoded = roots[0]
    name = ", ".join("=".join(pair) for rdn in decoded["subject"] for pair in rdn)
    root = work / "root.pem"
    root.write_text(block + "\n", encoding="utf-8")
    verified = ssl.create_default_context(cafile=str(root))
    status, _body = https_get(origin, "/.well-known/openid-configuration", verified)
    if status != 200:
        raise RuntimeError(f"discovery answered {status} over a connection verified against the root")
    print(f"trust anchor: {name} (one of {len(blocks)} certificates); iya-sts verifies against it", flush=True)
    return root, verified, name, len(blocks)


def json_request(context, origin, method, path, body=None, headers=None):
    parts = urllib.parse.urlsplit(origin)
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=60)
    sent = {"accept": "application/json", **(headers or {})}
    try:
        conn.request(method, path, body=body, headers=sent)
        response = conn.getresponse()
        payload = response.read()
    finally:
        conn.close()
    try:
        parsed = json.loads(payload.decode() if payload else "{}")
    except json.JSONDecodeError:
        raise RuntimeError(f"{method} {path} answered {response.status} with non-JSON: {payload[:300]!r}") from None
    return response.status, parsed


def mint_admin(context, sts_origin, secret):
    raw = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "scope": "admin:read admin:write",
        "resource": sts_origin + "/admin-api",
    })
    basic = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    status, parsed = json_request(context, sts_origin, "POST", "/oauth2/token", raw, {
        "content-type": "application/x-www-form-urlencoded",
        "authorization": f"Basic {basic}",
    })
    if status != 200 or not isinstance(parsed.get("access_token"), str):
        raise RuntimeError(f"the admin token request answered {status}: {json.dumps(parsed)[:300]}")
    return parsed["access_token"]


def admin_json(context, sts_origin, token, method, path, body=None):
    headers = {"authorization": f"Bearer {token}"}
    raw = None
    if body is not None:
        raw = json.dumps(body)
        headers["content-type"] = "application/json"
    return json_request(context, sts_origin, method, path, raw, headers)


def session_id_for(context, sts_origin, token, username):
    deadline = time.time() + 20
    sessions = []
    while time.time() < deadline:
        _status, parsed = admin_json(context, sts_origin, token, "GET", "/admin-api/caep")
        sessions = parsed.get("sessions") or []
        for row in sessions:
            if str(row.get("username") or "") == username and str(row.get("state") or "") != "revoked":
                found = row.get("sessionId")
                if found:
                    return str(found)
        time.sleep(1)
    raise RuntimeError(f"no CAEP session for {username}: {len(sessions)} sessions listed")


def emit(context, sts_origin, token, session_id, event_type):
    status, parsed = admin_json(context, sts_origin, token, "POST", "/admin-api/caep/emit", {
        "session_id": session_id,
        "type": event_type,
        "initiating_entity": "admin",
    })
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"emitting {event_type} answered {status}: {json.dumps(parsed)[:500]}")
    message = str(parsed.get("message") or "")
    if "Nothing was sent" in message:
        raise RuntimeError(f"emitting {event_type} reached no stream: {message}")
    print(f"emitted {event_type}: {message or json.dumps(parsed)[:200]}", flush=True)


def prepare_sts(sts_port, secret):
    given = os.environ.get("IYA_STS_URL", "").rstrip("/")
    if given:
        print(f"using {given}", flush=True)
        return given, None
    if sts_port in FORBIDDEN_PORTS:
        raise SystemExit(f"refusing to bind port {sts_port}")
    image = os.environ.get("IYA_STS_IMAGE", "")
    source = os.environ.get("IYA_STS_SRC", "")
    if not image:
        if not source:
            cloned = tempfile.mkdtemp(prefix="iya-sts-main-")
            run(["git", "clone", "--depth", "1", "--branch", "main", STS_REPO, cloned])
            run(["git", "-C", cloned, "submodule", "update", "--init", "--recursive"])
            source = cloned
        image = "iya-sts-live:main"
        docker("build", "-t", image, source)
    name = "iya-sts-live-" + PROFILE["repo"]
    docker_rm(name)
    docker(
        "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{sts_port}:{sts_port}",
        "-e", f"STS_PORT={sts_port}",
        "-e", "STS_PERSISTENCE_MODE=memory",
        "-e", "STS_CLUSTER_MODE=off",
        "-e", "STS_WORKERS_REQUEST_COUNT=0",
        "-e", "STS_WORKERS_SURFACE_COUNT=0",
        "-e", "STS_ADMIN_API_CLIENT_SECRET",
        "-e", "STS_LOG_LEVEL=info",
        image,
        env={**os.environ, "STS_ADMIN_API_CLIENT_SECRET": secret},
    )
    return f"https://127.0.0.1:{sts_port}", name


def write_oidc_file(path, sts_origin):
    path.write_text(json.dumps({
        "metadataUrl": sts_origin + "/.well-known/openid-configuration",
        "client_id": PROFILE["client_id"],
        "scopes": PROFILE["scopes"],
    }, indent=2) + "\n", encoding="utf-8")


def register(work, demo_origin, demo_port):
    """The registration script, in the Node image. Secrets go through the environment, not argv.
    It verifies iya-sts against the root this driver already checked (--ca)."""
    # The command is not echoed: it names the variable that carries the test user's password, and
    # nothing derived from a password may reach a log line (CodeQL
    # py/clear-text-logging-sensitive-data). A fixed label stands in for it.
    print("+ docker run " + NODE_IMAGE + " node scripts/register-iya-sts-client.mjs", flush=True)
    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "host",
            "-v", f"{ROOT / 'scripts'}:/app/scripts:ro",
            "-v", f"{work / 'oidc.json'}:/app/oidc.json:ro",
            "-v", f"{work / 'root.pem'}:/app/root.pem:ro",
            "-e", "ADMIN_API_CLIENT_SECRET",
            "-e", PROFILE["test_user_env"],
            "-e", f"PORT={demo_port}",
            "-w", "/app",
            NODE_IMAGE,
            "node", "scripts/register-iya-sts-client.mjs",
            "--config", "/app/oidc.json",
            "--public-url", demo_origin,
            "--test-user", PROFILE["test_user"],
            "--ca", "/app/root.pem",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    print(completed.stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, flush=True)
    if completed.returncode != 0:
        raise RuntimeError(f"the registration script exited {completed.returncode}")


def start_demo(work, image, name, demo_port, demo_origin):
    docker("build", "-t", image, str(ROOT))
    docker_rm(name)
    docker(
        "run", "-d", "--name", name, "--network", "host",
        "-v", f"{work / 'oidc.json'}:/app/demo/public/oidc.json:ro",
        "-e", f"PORT={demo_port}",
        "-e", f"PUBLIC_URL={demo_origin}",
        image,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", demo_port, timeout=3)
            conn.request("GET", "/oidc.json")
            response = conn.getresponse()
            body = response.read()
            conn.close()
            if response.status == 200 and json.loads(body).get("client_id") == PROFILE["client_id"]:
                return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    logs = subprocess.run(["docker", "logs", name], check=False, text=True, capture_output=True)
    print(logs.stdout + logs.stderr, file=sys.stderr, flush=True)
    raise RuntimeError("the demo did not serve its oidc.json")


class Browser:
    """scripts/live_browser.py in Playwright's image, driven over stdin and stdout."""

    def __init__(self, work, name, sts_origin, demo_origin):
        command = [
            "docker", "run", "--rm", "-i", "--name", name, "--network", "host", "--ipc", "host",
            "-v", f"{work / 'root.pem'}:/trust/root.pem:ro",
            "-e", f"STS_ORIGIN={sts_origin}",
            "-e", f"DEMO_ORIGIN={demo_origin}",
            "-e", f"LIVE_USERNAME={PROFILE['test_user']}",
            "-e", "LIVE_PASSWORD",
            BROWSER_IMAGE,
        ]
        # A fixed label, not the command: it names the variable that carries the password.
        print("+ docker run " + BROWSER_IMAGE + " (scripts/live_browser.py)", flush=True)
        env = {**os.environ, "LIVE_PASSWORD": os.environ[PROFILE["test_user_env"]]}
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, bufsize=1
        )

    def read(self):
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"the browser exited {self.process.wait()}")
        return json.loads(line)

    def status(self):
        self.process.stdin.write("status\n")
        self.process.stdin.flush()
        return self.read()

    def close(self):
        try:
            self.process.stdin.write("quit\n")
            self.process.stdin.flush()
            self.process.wait(timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()


def wait_for(browser, predicate, what, timeout=60):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = browser.status()
        if predicate(last):
            return last
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {what}: {json.dumps(last)[:600]}")


def seen(row, event_type):
    return [item for item in row.get("events") or [] if item.get("type") == event_type]


def main():
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18504)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18604)
    sts_given = bool(os.environ.get("IYA_STS_URL", "").strip())
    bound = [demo_port] if sts_given else [sts_port, demo_port]
    if any(port in FORBIDDEN_PORTS for port in bound) or len(set(bound)) != len(bound):
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must differ and must not bind 3000, 8081, or 18481 to 18495")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = os.environ.get(PROFILE["test_user_env"]) or secrets.token_urlsafe(18)
    # Secrets reach docker as -e NAME from this environment, never on a printed command line.
    os.environ["ADMIN_API_CLIENT_SECRET"] = secret
    os.environ[PROFILE["test_user_env"]] = password
    sts_origin, sts_name = prepare_sts(sts_port, secret)
    # The SPA's redirect URI is location.origin + /callback, so this is exactly what is registered.
    demo_origin = f"http://127.0.0.1:{demo_port}"
    demo_name = PROFILE["repo"] + "-live-demo"
    browser_name = PROFILE["repo"] + "-live-browser"
    image = PROFILE["repo"] + "-live:demo"
    work = Path(tempfile.mkdtemp(prefix=PROFILE["repo"] + "-live-"))
    work.chmod(0o755)
    browser = None
    try:
        wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        wait_ready(sts_origin, 90)
        root, verified, root_name, chain_length = root_of_chain(sts_origin, work)
        root.chmod(0o644)
        oidc_file = work / "oidc.json"
        write_oidc_file(oidc_file, sts_origin)
        oidc_file.chmod(0o644)
        register(work, demo_origin, demo_port)
        start_demo(work, image, demo_name, demo_port, demo_origin)
        docker("build", "-t", BROWSER_IMAGE, "-f", str(ROOT / "scripts" / "live-browser.Dockerfile"),
               str(ROOT / "scripts"))
        docker_rm(browser_name)
        browser = Browser(work, browser_name, sts_origin, demo_origin)
        ready = browser.read()
        if not ready.get("ready"):
            raise RuntimeError(f"the browser could not sign in: {ready.get('error')}")
        signed_in = wait_for(
            browser,
            lambda row: row.get("signedIn") is True and row.get("receiver") == "connected",
            "a signed-in SPA polling its stream",
        )
        print(f"signed in as {signed_in.get('subject')}; receiver {signed_in.get('receiver')}", flush=True)
        token = mint_admin(verified, sts_origin, secret)
        session_id = session_id_for(verified, sts_origin, token, PROFILE["test_user"])
        emit(verified, sts_origin, token, session_id, "credential-change")
        after_change = wait_for(
            browser,
            lambda row: row.get("signedIn") is True and seen(row, CREDENTIAL_CHANGE),
            "credential-change while still signed in",
        )
        emit(verified, sts_origin, token, session_id, "session-revoked")
        finished = wait_for(
            browser,
            lambda row: row.get("signedIn") is False and seen(row, SESSION_REVOKED),
            "session-revoked to end the SPA's session",
        )
        print(json.dumps({
            "ok": True,
            "subject": signed_in.get("subject"),
            "credentialChange": seen(after_change, CREDENTIAL_CHANGE)[0]["jti"],
            "sessionRevoked": seen(finished, SESSION_REVOKED)[0]["jti"],
            "signedInAfterCredentialChange": after_change.get("signedIn"),
            "signedInAfterSessionRevoked": finished.get("signedIn"),
            "browser": f"headless Chromium, {BROWSER_BASE} with certutil and the playwright package",
            "trustAnchor": f"{root_name}, the root of the {chain_length}-certificate chain from "
                           "/tls/server-certificate, added to the browser's NSS database",
            "events": finished.get("events"),
        }, indent=2))
    finally:
        if browser:
            browser.close()
        docker_rm(browser_name)
        docker_rm(demo_name)
        if sts_name:
            docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
