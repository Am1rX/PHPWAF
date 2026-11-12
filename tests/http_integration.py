"""Exercise the WAF through the PHP development server with no Python dependencies."""

from contextlib import contextmanager
from http.client import HTTPConnection
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
PHP = shutil.which("php")


def request(port, path="/", method="GET", body=None, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


@contextmanager
def server(site, overrides=None, broken=False, php_options=()):
    config = site / "waf" / "config.php"
    if broken:
        config.write_text("<?php return [", encoding="utf-8")
    else:
        config.write_text(
            "<?php return array_replace_recursive(require __DIR__ . '/base-config.php', "
            + (overrides or "[]")
            + ");",
            encoding="utf-8",
        )

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with (site / "server.log").open("wb") as log:
        process = subprocess.Popen(
            [PHP, "-d", "expose_php=1", "-d", "display_errors=1", *php_options, "-S",
             f"127.0.0.1:{port}", "-t", str(site / "public")],
            stdout=log,
            stderr=log,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError((site / "server.log").read_text(errors="replace"))
                    time.sleep(0.05)
            else:
                raise RuntimeError("PHP server did not start.")
            yield port
        finally:
            process.terminate()
            process.wait(timeout=5)


def main():
    if PHP is None:
        raise SystemExit("PHP is required.")
    with tempfile.TemporaryDirectory() as directory:
        site = Path(directory)
        waf = site / "waf"
        waf.mkdir()
        for name in ("src", "waf_storage"):
            shutil.copytree(ROOT / name, waf / name)
        for name in ("autoload.php", "guard.php"):
            shutil.copyfile(ROOT / name, waf / name)
        shutil.copyfile(ROOT / "config.php", waf / "base-config.php")
        public = site / "public"
        public.mkdir()
        (public / "index.php").write_text(
            """<?php
require __DIR__ . '/../waf/guard.php';
header('X-Powered-By: example/1.2.3');
header('X-WAF-Version: example/4.5.6');
header('Server: app-server/7.8.9');
header('X-Framework-Version: demo-framework/1.2.3');
header('X-Debug-Token: private-debug-marker');
header('X-Backend-Server: private-upstream');
header('X-Application-Feature: preserved');
if (isset($_GET['redirect'])) {
    header('Location: /', true, 302);
    exit;
}
if (isset($_GET['diagnostic'])) {
    trigger_error('internal diagnostic', E_USER_WARNING);
}
echo 'app-ok';
""",
            encoding="utf-8",
        )
        (public / "syntax.php").write_text("<?php echo ;", encoding="utf-8")

        with server(site, "['honeypot_fields' => ['trap'], 'storage' => ['dir' => __FILE__]]") as port:
            status, headers, body = request(port, "/?diagnostic=1")
            assert (status, body) == (200, b"app-ok")
            private_headers = {"x-powered-by", "x-waf-version", "x-framework-version", "x-debug-token", "x-backend-server"}
            assert not {key.lower() for key in headers} & private_headers
            assert headers["X-Application-Feature"] == "preserved"
            assert "7.8.9" not in headers.get("Server", "")
            for user_agent in ("curl/8.14.1", "python-requests/2.32.5", "Mozilla/5.0"):
                assert request(port, headers={"User-Agent": user_agent})[0] == 200
            status, headers, _ = request(port, "/?redirect=1")
            assert status == 302 and headers["Location"] == "/"
            assert not {key.lower() for key in headers} & private_headers
            assert request(port, "/?" + urlencode({"trap[0]": "sample"}))[0] == 403

            json_headers = {"Content-Type": "application/json"}
            assert request(port, "/", "POST", json.dumps({"x": "a" * 8193}), json_headers)[0] == 413
            assert request(port, "/", "POST", json.dumps({"n": ["a"] * 1010}), json_headers)[0] == 413
            status, headers, body = request(
                port, "/?" + urlencode({"q": "<svg>", "token": "private-query"}),
                "POST", '{"q":"normal"}', json_headers,
            )
            assert status == 403 and b"<svg>" not in body and b"private-query" not in body
            assert "text/plain" in headers["Content-Type"] and headers["Cache-Control"] == "no-store"
            assert headers["X-Content-Type-Options"] == "nosniff"
            assert not {key.lower() for key in headers} & {"x-powered-by", "x-waf-version"}
            reference = body.decode().strip().split()[-1]
            events = (waf / "waf_storage" / "events.jsonl").read_text()
            assert "private-query" not in events
            assert json.loads(events.splitlines()[-1])["reference"] == reference
            assert request(port, "/?" + urlencode({"q": "<svg>"}), "HEAD")[2] == b""
            assert request(port, "/", "POST", '{"text":"مرحبا"}'.encode(), json_headers)[0] == 200
            details_block = '<details class="wp-block-details"><summary>Read more</summary><p>Ordinary content.</p></details>'
            assert request(port, "/", "POST", json.dumps({"content": details_block}), json_headers)[0] == 200
            assert request(port, "/", "POST", "{", json_headers)[0] == 400
            assert request(port, "/", "POST", b" " * 131073, json_headers)[0] == 413
            assert request(port, "/", "POST", json.dumps({"a": {"n": "<svg>"}}), json_headers)[0] == 403
            assert request(port, "/", "POST", json.dumps("<svg>"), json_headers)[0] == 403
            assert request(port, "/", headers={"Cookie": "k=%3Csvg%3E"})[0] == 403
            assert not (waf / "waf_storage" / "blocked_ips.json").exists()
            events_path = waf / "waf_storage" / "events.jsonl"
            for punctuation in ('"', "'", "/", "..", "--+", "-- "):
                assert request(port, "/?" + urlencode({"sample": punctuation}))[0] == 200
                event = json.loads(events_path.read_text().splitlines()[-1])
                assert event["decision"] == "shadow" and event["rule_ids"] == ["PROBE-001"] and event["score"] == 0
            form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
            assert request(port, "/", "POST", urlencode({"sample": "/"}), form_headers)[0] == 200
            assert json.loads(events_path.read_text().splitlines()[-1])["rule_ids"] == ["PROBE-001"]
            assert request(port, "/", "POST", json.dumps({"sample": "'"}), json_headers)[0] == 200
            assert json.loads(events_path.read_text().splitlines()[-1])["rule_ids"] == ["PROBE-001"]
            previous = events_path.read_bytes()
            for everyday in ("O'Brien", "folder/document", "Wait .. one minute", '"quoted text"'):
                assert request(port, "/?" + urlencode({"sample": everyday}))[0] == 200
            assert request(port, "/")[0] == 200
            assert events_path.read_bytes() == previous

        with server(site, "['shadow_rule_ids' => ['XSS-002']]") as port:
            assert request(port, "/?" + urlencode({"q": "<svg>"}))[0] == 200
            assert request(port, "/?" + urlencode({"q": "<script>"}))[0] == 403
            events = (waf / "waf_storage" / "events.jsonl").read_text().splitlines()
            assert any(
                event["decision"] == "shadow" and event["rule_ids"] == ["XSS-002"]
                for event in map(json.loads, events)
            )

        with server(site, "['mode' => 'monitor']") as port:
            assert request(port, "/?" + urlencode({"q": "<svg>"}))[0] == 200

        proxy = "['mode' => 'enforce', 'proxy' => ['trust_forwarded_header' => true, 'trusted_proxies' => ['127.0.0.1', '127.0.0.2']]]"
        with server(site, proxy) as port:
            flagged = "/?" + urlencode({"q": "<svg>"})
            assert request(port, flagged)[0] == 403
            assert request(port, "/", headers={"X-Forwarded-For": "198.51.100.22"})[0] == 200
            chain = {"X-Forwarded-For": "198.51.100.22, 127.0.0.2"}
            assert request(port, flagged, headers=chain)[0] == 403
            assert request(port, "/", headers=chain)[0] == 403
            assert request(port, "/", headers={"X-Forwarded-For": "198.51.100.23"})[0] == 200

        with server(site, broken=True) as port:
            status, headers, body = request(port)
            assert status == 503
            assert b"ParseError" not in body and b"config.php" not in body
            assert "X-Powered-By" not in headers

        production = ("-d", "display_errors=0", "-d", f"auto_prepend_file={waf / 'guard.php'}")
        with server(site, php_options=production) as port:
            assert request(port)[0] == 200
            status, headers, body = request(port, "/syntax.php")
            assert status == 500 and b"Parse error" not in body and b"syntax.php" not in body
            assert "X-Powered-By" not in headers

    print("HTTP integration checks passed.")


if __name__ == "__main__":
    main()
