#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The headless browser half of scripts/live_iya_sts.py. It runs ONLY inside
Playwright's official Python image, never on the host.

It trusts iya-sts the way a person's browser would: the root certificate of
iya-sts's listener chain (mounted at /trust/root.pem) goes into this
container's NSS database as a trusted CA, which is where Chromium on Linux
looks for locally added roots. Nothing tells the browser to ignore a
certificate error, so a chain that does not end at that root fails the page
load. The first thing it does is open the provider's discovery document and
fail unless that loads.

Then it opens the demo SPA, presses Sign in, and goes through iya-sts's
/authn screens as a person would: the username and password form, the consent
screen, and the skip button of an optional set-up step. It ends when the SPA
says it is signed in.

After that it answers its caller on stdin and stdout, one line each:
`status` prints the SPA's #live-status element (the JSON the page draws for
tests: signedIn, subject, receiver, and each event's type and jti, never a
token), and `quit` closes the browser. The page stays open between commands,
so its tab storage, its tokens and its SSF poll loop live on.

Environment: DEMO_ORIGIN, STS_ORIGIN, LIVE_USERNAME, LIVE_PASSWORD.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

ROOT_PEM = Path("/trust/root.pem")
NSS_DB = Path.home() / ".pki" / "nssdb"
SIGN_IN = "#who button.primary"
LOGIN = "#username"
CONSENT = "#consent-allow"
SKIP = "#mfa-setup-skip, #post-login-skip"


def say(message):
    """Progress goes to stderr; stdout carries only the answers to commands."""
    print(message, file=sys.stderr, flush=True)


def trust_root():
    NSS_DB.mkdir(parents=True, exist_ok=True)
    subprocess.run(["certutil", "-d", f"sql:{NSS_DB}", "-N", "--empty-password"], check=True)
    subprocess.run(
        ["certutil", "-d", f"sql:{NSS_DB}", "-A", "-t", "C,,", "-n", "iya-sts-live-root", "-i", str(ROOT_PEM)],
        check=True,
    )
    listed = subprocess.run(["certutil", "-d", f"sql:{NSS_DB}", "-L"], check=True, capture_output=True, text=True)
    say("NSS database now holds:\n" + listed.stdout.strip())


def live_status(page):
    return json.loads(page.locator("#live-status").text_content() or "{}")


def origin_of(url):
    parts = url.split("/")
    return "/".join(parts[:3])


def sign_in(page, demo, sts, username, password):
    page.goto(demo + "/")
    page.locator(SIGN_IN).click(timeout=30_000)
    # The page builds the request (PAR, PKCE, DPoP) and then leaves for iya-sts.
    page.wait_for_url(lambda url: origin_of(url) == sts, timeout=30_000)
    for _step in range(20):
        page.wait_for_load_state("load")
        url = page.url
        if origin_of(url) == demo:
            try:
                page.wait_for_function(
                    "() => { const e = document.getElementById('live-status'); return !!e && JSON.parse(e.textContent).signedIn === true; }",
                    timeout=30_000,
                )
            except PlaywrightTimeout:
                errors = page.locator(".banner, .form-error").all_text_contents()
                raise RuntimeError(f"back at the demo but not signed in: {errors}") from None
            return
        if origin_of(url) != sts:
            raise RuntimeError(f"the browser left for {url}")
        # iya-sts's screens are drawn by script from /authn-api; wait for whichever control appears.
        page.wait_for_selector(f"{LOGIN}, {CONSENT}, {SKIP}", timeout=30_000)
        if page.locator(LOGIN).count():
            say(f"sign-in screen at {url.split('?')[0]}")
            page.fill(LOGIN, username)
            page.fill("#password", password)
            with page.expect_navigation(timeout=30_000):
                page.click("#kc-login")
        elif page.locator(CONSENT).count():
            say(f"consent screen at {url.split('?')[0]}")
            with page.expect_navigation(timeout=30_000):
                page.click(CONSENT)
        else:
            say(f"optional step at {url.split('?')[0]}: skipping")
            with page.expect_navigation(timeout=30_000):
                page.locator(SKIP).first.click()
    raise RuntimeError(f"the sign-in did not finish; last URL {page.url.split('?')[0]}")


def main():
    demo = os.environ["DEMO_ORIGIN"].rstrip("/")
    sts = os.environ["STS_ORIGIN"].rstrip("/")
    username = os.environ["LIVE_USERNAME"]
    password = os.environ["LIVE_PASSWORD"]
    trust_root()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.on("console", lambda msg: say(f"page console {msg.type}: {msg.text}") if msg.type == "error" else None)
            # The trust check: a certificate error here fails the run.
            reply = page.goto(sts + "/.well-known/openid-configuration")
            if not reply or reply.status != 200:
                raise RuntimeError(f"discovery answered {reply.status if reply else 'nothing'}")
            say("the browser verified iya-sts's certificate chain against the imported root")
            sign_in(page, demo, sts, username, password)
            say("signed in")
            print(json.dumps({"ready": True, **live_status(page)}), flush=True)
            for line in sys.stdin:
                command = line.strip()
                if command == "status":
                    print(json.dumps(live_status(page)), flush=True)
                elif command == "quit":
                    break
                else:
                    print(json.dumps({"error": f"unknown command {command!r}"}), flush=True)
        finally:
            browser.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(json.dumps({"ready": False, "error": str(err)[:800]}), flush=True)
        say(f"browser half failed: {err}")
        sys.exit(1)
