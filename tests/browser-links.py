"""Synthetic link-display regressions; no training or SMS holdout evaluation.

Requires an existing Playwright for Python installation and Chromium executable.
Both interfaces run on temporary loopback servers; external requests are blocked.
"""
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright


AMBIGUOUS = "Ambiguous link host"
HOST_WARNING = "URL host interpretations differ. Do not open it; verify through an independently obtained contact or official app."
MALFORMED_WARNING = "Malformed URL: do not open it"
IDNA_WARNING = "Internationalized domain: compare the exact spelling independently"
# name, fictional text, independent domain, displayed hosts, warnings per link
CASES = [
    ("backslash-authority", r"Fictional request: https://fraud.example\@bank.example/login", "bank.example",
     [AMBIGUOUS], [[HOST_WARNING]]),
    ("idna-disagreement", "Fictional request: https://faß.example/login", "faß.example",
     [AMBIGUOUS], [[HOST_WARNING]]),
    ("invalid-port", "Fictional request: https://bank.example:bad/login", "bank.example",
     ["Malformed link"], [[MALFORMED_WARNING]]),
    ("out-of-range-port", "https://bank.example:65536/login", "bank.example",
     ["Malformed link"], [[MALFORMED_WARNING]]),
    ("astral-before-ambiguous-link", "😀" + r"https://fraud.example\@bank.example/login", "bank.example",
     [AMBIGUOUS], [[HOST_WARNING]]),
    ("astral-before-normal-link", "😀https://bank.example/login", "bank.example",
     ["bank.example"], [[]]),
    ("ordinary-user-information", "https://bank.example@fraud.example/login", "bank.example",
     ["fraud.example"], [["URL contains user information before the real host",
                           "Host differs from the independently supplied expected domain"]]),
    ("www-prefix", "www.bank.example/login", "bank.example", ["www.bank.example"], [[]]),
    ("http-warning-preserved", "http://bank.example/login", "bank.example",
     ["bank.example"], [["Link does not use HTTPS"]]),
    ("idna-agreement", "https://bücher.example/login", "bücher.example",
     ["xn--bcher-kva.example"], [[IDNA_WARNING]]),
    ("uppercase-and-trailing-dot", "HTTPS://BANK.EXAMPLE./login", "bank.example",
     ["bank.example"], [[]]),
    ("ipv6-brackets", "https://[2001:db8::1]/login", "", ["2001:db8::1"], [[]]),
    ("valid-port", "https://bank.example:8443/login", "bank.example", ["bank.example"], [[]]),
    ("backslash-in-path", r"https://bank.example/path\file", "bank.example", ["bank.example"], [[]]),
    ("mixed-links-and-unicode-offsets", "😀 https://bank.example/login and "
     + r"https://fraud.example\@bank.example/login and https://bank.example:bad/", "bank.example",
     ["bank.example", AMBIGUOUS, "Malformed link"], [[], [HOST_WARNING], [MALFORMED_WARNING]]),
    ("original-malformed-link", "https://[bad/", "bank.example",
     ["Malformed link"], [[MALFORMED_WARNING]]),
]
FROZEN_HASHES = {
    "core.py": "6a39dab6370c8d4b04f05a7eedafba23e1aad0f570493a255caf2f713fe11994",
    "model.json": "e3a024c6b54156da921b03ce9878cd4d043557ce590a4aeb9363d89bd7f321de",
}


class QuietFiles(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@contextmanager
def serve(root, mode):
    if mode == "static-browser":
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietFiles, directory=str(root / "docs")))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        return
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, str(root / "server.py"), "--model", str(root / "model.json"), "--port", str(port)],
        cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    origin = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 10
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"Python server exited: {process.communicate()[1]}")
            try:
                with urlopen(origin, timeout=1):
                    break
            except URLError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Python server did not become ready")
                time.sleep(0.05)
        yield origin
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def check_interface(browser, root, mode, report):
    with serve(root, mode) as origin:
        context = browser.new_context()
        outside = []

        def allow_loopback_only(route):
            if route.request.url.startswith(origin + "/"):
                route.continue_()
            else:
                outside.append(route.request.url)
                route.abort()

        context.route("**/*", allow_loopback_only)
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(origin + "/")
        expect(page.locator("#analyze")).to_be_enabled(timeout=60000)
        requests = []
        page.on("request", lambda request: requests.append({"method": request.method, "path": urlsplit(request.url).path}))
        for name, text, domain, hosts, warnings in CASES:
            page.locator("#message").fill(text)
            page.locator("#domain").fill(domain)
            page.locator("#analyze").click()
            page.locator("#result").wait_for(state="visible")
            rows = page.locator("#result .link")
            actual_hosts = rows.locator("strong").all_text_contents()
            actual_warnings = [rows.nth(i).locator(".warning").all_text_contents() for i in range(rows.count())]
            failures = []
            if actual_hosts != hosts:
                failures.append(f"hosts: expected {hosts!r}, got {actual_hosts!r}")
            if actual_warnings != warnings:
                failures.append(f"warnings: expected {warnings!r}, got {actual_warnings!r}")
            if rows.locator("a").count():
                failures.append("Pasted links became clickable")
            if rows.locator("span").all_text_contents() != ["Sender authenticity remains unverified."] * len(hosts):
                failures.append("Unverified sender notice was lost")
            report["cases"].append({"interface": mode, "name": name, "displayed_hosts": actual_hosts,
                                    "warnings": actual_warnings, "failures": failures})
        expected_requests = [] if mode == "static-browser" else [{"method": "POST", "path": "/analyze"}] * len(CASES)
        checks = {"interface": mode, "analysis_requests": requests, "external_requests": outside, "page_errors": errors}
        checks["passed"] = requests == expected_requests and not outside and not errors
        report["interface_checks"].append(checks)
        context.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not args.chromium:
        parser.error("Pass --chromium with an existing Chromium executable")
    root = args.root.resolve()
    for name, expected in FROZEN_HASHES.items():
        for relative in (name, "docs/" + name):
            if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
                raise AssertionError(f"Frozen evaluation artifact changed: {relative}")
    report = {"root": str(root), "scope": "Synthetic browser link-display regressions; no training or SMS evaluation",
              "frozen_sha256": FROZEN_HASHES, "cases": [], "interface_checks": []}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium, headless=True, args=["--no-sandbox"])
        report["chromium_version"] = browser.version
        try:
            for mode in ("static-browser", "python-server"):
                check_interface(browser, root, mode, report)
        finally:
            browser.close()
    report["total"] = len(report["cases"])
    report["passed"] = sum(not case["failures"] for case in report["cases"])
    report["all_passed"] = report["passed"] == report["total"] and all(check["passed"] for check in report["interface_checks"])
    encoded = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.report:
        args.report.write_text(encoded)
    print(encoded, end="")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
