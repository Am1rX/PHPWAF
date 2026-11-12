"""Exercise setup, the operator UI and managed PHP entry points on loopback."""

import json
import os
from hashlib import sha256
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlencode

from http_integration import PHP, ROOT, request, server


PASSWORD = "Example-Moss.Trail-48!"
NEW_PASSWORD = "Winter-Lantern.River-28!"
PANEL = "/firewall-admin/"


def setup(site, *args, password=PASSWORD, success=True):
    result = subprocess.run(
        [PHP, str(site / "waf/admin/setup.php"), f"--state={site / 'private'}", *args],
        input=f"{password}\n{password}\n", text=True, capture_output=True,
    )
    assert (result.returncode == 0) == success, (result.stdout, result.stderr)
    return result


class Operator:
    def __init__(self, port):
        self.port = port
        self.cookie = ""

    def call(self, path=PANEL, data=None):
        headers = {"Cookie": self.cookie} if self.cookie else {}
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, response, body = request(
            self.port, path, "POST" if data is not None else "GET",
            urlencode(data) if data is not None else None, headers,
        )
        if "Set-Cookie" in response:
            cookie = response["Set-Cookie"]
            assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
            self.cookie = cookie.split(";", 1)[0]
        return status, response, body.decode("utf-8")

    def action(self, action, path=PANEL, password=PASSWORD, **fields):
        status, _, body = self.call(path)
        assert status == 200, (status, body)
        csrf = re.search(r'name="csrf" value="([a-f0-9]{64})"', body)
        assert csrf, body[:400]
        return self.call(path, {"action": action, "password": password, "csrf": csrf[1], **fields})


def main():
    with tempfile.TemporaryDirectory() as directory:
        site = Path(directory)
        waf = site / "waf"
        waf.mkdir()
        for name in ("src", "admin", "waf_storage"):
            shutil.copytree(ROOT / name, waf / name)
        for name in ("autoload.php", "guard.php", "config.php"):
            shutil.copyfile(ROOT / name, waf / name)
        shutil.copyfile(ROOT / "config.php", waf / "base-config.php")
        public = site / "public"
        public.mkdir()
        index = public / "index.php"
        second = public / "other.php"
        original = b"<?php\r\ndeclare(strict_types=1);\r\necho 'home';\r\n"
        namespaced = b"<?php\nnamespace Demo {\n    echo 'other';\n}\n"
        index.write_bytes(original)
        second.write_bytes(namespaced)
        install = [f"--root={public}", "--entry=index.php", "--entry=other.php"]
        setup(site, *install, "--user=admin", password="password", success=False)
        initial = setup(site, *install)
        assert "Initial login: admin / admin" in initial.stdout
        setup_code = re.search(r"First sign-in setup code for HTTPS: ([a-f0-9]{48})", initial.stdout)
        assert setup_code
        state = site / "private"
        settings = lambda: json.loads((state / "settings.json").read_text())
        assert not settings()["active"]
        assert settings()["engine"]["mode"] == "filter"
        assert json.loads((state / "auth.json").read_text())["trusted"] == []
        assert json.loads((state / "auth.json").read_text())["setup_hash"] == sha256(setup_code[1].encode()).hexdigest()

        with server(site) as port:
            _, _, proxied_login = request(port, PANEL, headers={"X-Forwarded-For": "192.0.2.15"})
            assert b'name="setup_code"' in proxied_login
            first = Operator(port)
            assert '<html lang="en" dir="ltr">' in first.call()[2]
            language_link = first.call(PANEL + "?lang=fa")[2]
            assert '<html lang="fa" dir="rtl">' in language_link and "ورود به پنل" in language_link
            assert first.action("login", username="admin", password="admin")[0] == 303
            forced = first.call(PANEL + "?view=attacks")[2]
            assert "تغییر رمز اولیه" in forced and '<nav aria-label=' not in forced
            first.action("enable", password="admin")
            assert not settings()["active"]
            first.action("credentials", password="admin", username="admin", new_password="admin", confirm_password="admin")
            assert json.loads((state / "auth.json").read_text())["must_rotate"] is True
            first.action("credentials", password="admin", username="admin", new_password=NEW_PASSWORD, confirm_password=NEW_PASSWORD)
            rotated = json.loads((state / "auth.json").read_text())
            assert not rotated.get("must_rotate") and "setup_hash" not in rotated
            farsi_dashboard = first.call()[2]
            assert all(label in farsi_dashboard for label in ("پایش", "سیاست فایروال", "سیستم"))
            english_dashboard = first.call(PANEL + "?lang=en")[2]
            assert all(label in english_dashboard for label in ("Monitoring", "Firewall Policy", "System"))
            assert '<html lang="en" dir="ltr">' in english_dashboard
            first.action("logout")
            first.action("login", username="admin", password="admin")
            assert "Sign in to the console" in first.call()[2]
            first.action("login", username="admin", password=NEW_PASSWORD)
            assert "Installation Status" in first.call()[2]

        setup(site, *install, "--user=operator-case", "--settings=keep")
        with server(site) as port:
            admin = Operator(port)
            status, headers, page = admin.call()
            assert status == 200 and "Sign in to the console" in page
            assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
            assert headers["Referrer-Policy"] == "same-origin"
            assert admin.call(PANEL, {"action": "enable", "csrf": "invalid"})[0] == 403
            assert admin.action("login", username="operator-case")[0] == 303
            assert "Installation Status" in admin.call()[2]
            assert admin.action("enable", password="wrong")[0] == 303
            assert not settings()["active"] and index.read_bytes() == original
            second.unlink()
            admin.action("enable")
            assert not settings()["active"] and index.read_bytes() == original
            assert "Unavailable" in admin.call()[2]
            second.write_bytes(namespaced)
            assert admin.action("enable")[0] == 303
            assert settings()["active"]
            for entry in (index, second):
                contents = entry.read_bytes()
                assert contents.count(b"PHPWAF-MANAGED") == 2
                subprocess.run([PHP, "-l", str(entry)], check=True, capture_output=True)
            assert request(port)[2] == b"home"
            assert request(port, "/other.php")[2] == b"other"
            signatures = PANEL + "?view=signatures"
            signed_page = admin.call(signatures)[2]
            assert "XSS-002" in signed_page and "PROBE-001" in signed_page and "Observe only" in signed_page
            selected_signature = signatures + "&rule=XSS-002&q=XSS-002"
            selection = admin.call(selected_signature)[2]
            assert 'class="stack signature-form"' in selection and "XSS-003" not in selection
            marker = "/?" + urlencode({"text": "<svg>"})
            assert request(port, marker)[0] == 403
            admin.action("signature", signatures, password="wrong", signature="XSS-002", target="off")
            assert "XSS-002" not in settings()["signatures"] and request(port, marker)[0] == 403
            status, headers, _ = admin.action("signature", selected_signature, signature="XSS-002", target="off")
            assert status == 303 and "rule=XSS-002" in headers["Location"] and "q=XSS-002" in headers["Location"]
            assert settings()["signatures"]["XSS-002"] is False
            assert request(port, marker)[0] == 200
            admin.action("signature", signatures, signature="XSS-002", target="on")
            assert request(port, marker)[0] == 403
            admin.action("signature", signatures, signature="NONEXISTENT", target="off")
            assert "NONEXISTENT" not in settings()["signatures"]
            test_probe = "/?" + urlencode({"text": ".."})
            assert request(port, test_probe)[0] == 200
            events_path = state / "events.jsonl"
            observation = json.loads(events_path.read_text().splitlines()[-1])
            assert observation["rule_ids"] == ["PROBE-001"] and observation["evidence"][0]["sample"] == ".."
            admin.action("signature", signatures, signature="PROBE-001", target="off")
            earlier = events_path.read_bytes()
            assert request(port, test_probe)[0] == 200 and events_path.read_bytes() == earlier
            admin.action("signature", signatures, signature="PROBE-001", target="on")
            assert request(port, test_probe)[0] == 200 and events_path.read_bytes() != earlier
            admin.action("enable")
            assert index.read_bytes().count(b"PHPWAF-MANAGED") == 2

            flagged = "/?" + urlencode({"text": "<svg>"})
            status, _, body = request(port, flagged)
            assert status == 403
            reference = body.decode().split()[-1]
            event_page = PANEL + "?view=attacks&event=" + reference
            details = admin.call(event_page)[2]
            assert "127.0.0.1" in details and "XSS-002" in details and "&lt;svg&gt;" in details and "<svg>" not in details
            assert "Add exception for this match" in details
            filtered_details = admin.call(event_page + "&q=XSS-002&method=GET")[2]
            assert 'class="master-detail with-inspector"' in filtered_details and 'class="selected-row"' in filtered_details
            assert "method=GET" in filtered_details and "q=XSS-002" in filtered_details
            snapshots = os.getenv("PHPWAF_TEST_SNAPSHOTS")
            if snapshots:
                folder = Path(snapshots)
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "dashboard.html").write_text(admin.call()[2], encoding="utf-8")
                (folder / "attack-details.html").write_text(details, encoding="utf-8")
            admin.action("add-exception", event_page, reference=reference, evidence="0", days="7")
            assert len(settings()["exceptions"]) == 1
            assert request(port, flagged)[0] == 200
            assert request(port, "/other.php?" + urlencode({"text": "<svg>"}))[0] == 403
            assert request(port, "/?" + urlencode({"name": "<svg>"}))[0] == 403
            assert request(port, "/?" + urlencode({"text": "<svg> with additional text"}))[0] == 403
            assert request(port, "/?" + urlencode({"password": "<svg>"}))[0] == 403
            events = [json.loads(line) for line in (state / "events.jsonl").read_text().splitlines()]
            assert events[-1]["evidence"][0]["sample"] is None
            assert "fingerprint" not in events[-1]["evidence"][0]
            exceptions = PANEL + "?view=exceptions"
            assert "XSS-002" in admin.call(exceptions)[2]
            assert "Remove exception" in admin.call(exceptions + "&exception=" + settings()["exceptions"][0]["id"])[2]
            admin.action("remove-exception", exceptions, id=settings()["exceptions"][0]["id"])
            assert not settings()["exceptions"]
            assert request(port, flagged)[0] == 403

            access = PANEL + "?view=access"
            admin.action("trusted-hosts", access, trusted="127.0.0.1\n192.0.2.9")
            assert json.loads((state / "auth.json").read_text())["trusted"] == ["127.0.0.1", "192.0.2.9"]
            admin.action("trusted-hosts", access, trusted="127.0.0.1")
            assert json.loads((state / "auth.json").read_text())["trusted"] == ["127.0.0.1"]
            admin.action("trusted-hosts", access, trusted="")
            assert json.loads((state / "auth.json").read_text())["trusted"] == []
            assert admin.action("credentials", access, username="operator-next", new_password=NEW_PASSWORD, confirm_password=NEW_PASSWORD)[0] == 303
            assert "operator-next" in admin.call(access)[2]

            # Simulate a compatible application edit after installation.
            with index.open("ab") as file:
                file.write(b"// application edit\n")
            assert admin.action("disable", password=NEW_PASSWORD)[0] == 303
            assert not settings()["active"]
            assert index.read_bytes() == original + b"// application edit\n"
            assert second.read_bytes() == namespaced
            assert request(port, flagged)[0] == 200

            setup(site, "--reset-admin", "--user=operator-recovered", "--trust=192.0.2.9")
            assert admin.call()[0] == 404
            setup(site, "--reset-admin", "--user=operator-recovered", "--trust=127.0.0.1")
            assert "Sign in to the console" in admin.call()[2]
            assert admin.action("login", username="operator-recovered")[0] == 303
            admin.action("enable")
            assert settings()["active"]
            status, _, body = request(port, flagged)
            assert status == 403
            reference = body.decode().split()[-1]
            admin.action("add-exception", PANEL + "?view=attacks&event=" + reference, reference=reference, evidence="0", days="7")
            assert len(settings()["exceptions"]) == 1
            before = settings()
            found = setup(site, *install, "--user=operator-recovered", success=False)
            assert "Found existing firewall settings" in found.stderr
            setup(site, *install, "--user=operator-recovered", "--settings=keep")
            assert before == settings()
            setup(site, *install, "--user=operator-recovered", "--settings=reset")
            assert not settings()["active"] and not settings()["exceptions"]
            assert index.read_bytes() == original + b"// application edit\n"
            assert second.read_bytes() == namespaced

    print("Panel setup, activation, logs, scoped exceptions and recovery checks passed.")


if __name__ == "__main__":
    main()
