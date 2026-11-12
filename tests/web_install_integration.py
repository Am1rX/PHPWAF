"""Verify the File Manager installation path without running the CLI installer."""

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
from urllib.parse import urlencode

from http_integration import ROOT, request, server
from panel_integration import Operator, PASSWORD


def install_request(port, route, key, profile="php", entries=""):
    fields = urlencode({"owner_key": key, "profile": profile, "entries": entries})
    return request(port, route, "POST", fields, {"Content-Type": "application/x-www-form-urlencoded"})


def run_fixture(wordpress):
    with tempfile.TemporaryDirectory() as directory:
        site = Path(directory)
        waf = site / "waf"
        waf.mkdir()
        for name in ("src", "admin", "waf_storage"):
            shutil.copytree(ROOT / name, waf / name)
        for name in ("autoload.php", "guard.php"):
            shutil.copyfile(ROOT / name, waf / name)
        shutil.copyfile(ROOT / "config.php", waf / "base-config.php")
        public = site / "public"
        target = public / "blog" if wordpress else public
        target.mkdir(parents=True)
        entries = ["index.php", "status.php"]
        if wordpress:
            entries += ["wp-load.php", "wp-login.php", "wp-admin/index.php", "wp-admin/post.php", "wp-admin/admin-ajax.php", "wp-cron.php", "xmlrpc.php"]
        for path in entries:
            entry = target / path
            entry.parent.mkdir(parents=True, exist_ok=True)
            entry.write_text("<?php echo 'Application response';\n", encoding="utf-8")
        key = secrets.token_urlsafe(36)
        (site / "phpwaf-setup.key").write_text(key + "\n", encoding="utf-8")
        wrapper = (ROOT / "examples/phpwaf-install.php").read_text(encoding="utf-8")
        if wordpress:
            wrapper = wrapper.replace("dirname(__DIR__)", "dirname(__DIR__, 2)", 1)
        (target / "phpwaf-install.php").write_text(wrapper, encoding="utf-8")
        prefix = "/blog" if wordpress else ""
        setup_url = prefix + "/phpwaf-install.php"
        panel_url = prefix + "/firewall-admin/"
        state = site / "waf-private"
        snapshot_root = os.getenv("PHPWAF_TEST_SNAPSHOTS")
        snapshots = Path(snapshot_root) if snapshot_root and not wordpress else None
        if snapshots is not None:
            snapshots.mkdir(parents=True, exist_ok=True)

        with server(site) as port:
            status, headers, body = request(port, setup_url)
            assert status == 200 and b"Install from File Manager" in body
            assert "no-store" in headers["Cache-Control"] and key.encode() not in body
            assert b'lang="fa" dir="rtl"' in request(port, setup_url + "?lang=fa")[2]
            if snapshots is not None:
                (snapshots / "file-manager-install.html").write_bytes(body)
            assert install_request(port, setup_url, "wrong")[0] == 403
            assert not state.exists()
            assert install_request(port, setup_url, key, "invalid")[0] == 400
            assert not (state / "auth.json").exists()
            if not wordpress:
                assert install_request(port, setup_url, key, "wordpress")[0] == 400
                assert not (state / "auth.json").exists()

            status, headers, result = install_request(
                port, setup_url, key, "wordpress" if wordpress else "php", "status.php" if wordpress else "index.php\nstatus.php",
            )
            assert status == 200 and b"Installation complete" in result and key.encode() not in result
            assert "no-store" in headers["Cache-Control"]
            code = re.search(rb"<pre dir=\"ltr\">([a-f0-9]{48})</pre>", result)
            assert code
            auth = json.loads((state / "auth.json").read_text())
            assert auth["must_rotate"] is True and auth["setup_hash"] == sha256(code[1]).hexdigest()
            assert request(port, setup_url)[0] == 404
            assert install_request(port, setup_url, key)[0] == 404

            managed = json.loads((state / "deployment.json").read_text())["entries"]
            expected = set(entries) - {"wp-load.php"}
            assert {Path(path).relative_to(target).as_posix() for path in managed} == expected
            original = {Path(path): Path(path).read_bytes() for path in managed}
            admin = Operator(port)
            admin.action("login", panel_url, username="admin", password="admin")
            rotation = admin.call(panel_url)[2]
            assert "Change initial password" in rotation and code[1].decode() not in rotation
            if snapshots is not None:
                (snapshots / "first-sign-in.html").write_text(rotation, encoding="utf-8")
            admin.action("credentials", panel_url, password="admin", username="admin", new_password=PASSWORD, confirm_password=PASSWORD)
            admin.action("mode", panel_url, mode="monitor")
            assert json.loads((state / "settings.json").read_text())["engine"]["mode"] == "monitor"
            admin.action("enable", panel_url)
            assert json.loads((state / "settings.json").read_text())["active"] is True
            assert all(path.read_bytes().count(b"PHPWAF-MANAGED") == 2 for path in original)
            assert request(port, prefix + "/status.php")[0] == 200
            admin.action("mode", panel_url, mode="filter")
            assert json.loads((state / "settings.json").read_text())["engine"]["mode"] == "filter"
            if snapshots is not None:
                # These markers are inert input sent only to the disposable echo fixture.
                for route, sample in (("/status.php", "/"), ("/index.php", "<svg>"), ("/status.php", "<svg>")):
                    request(port, route + "?" + urlencode({"sample": sample}))
                event = json.loads((state / "events.jsonl").read_text().splitlines()[-1])
                assert event["decision"] == "block"
                for name, view in (
                    ("dashboard", "?view=overview"),
                    ("attack-log", "?view=attacks&event=" + event["reference"]),
                    ("signatures", "?view=signatures&rule=PROBE-001"),
                ):
                    (snapshots / (name + ".html")).write_text(admin.call(panel_url + view)[2], encoding="utf-8")
            admin.action("disable", panel_url)
            assert all(path.read_bytes() == contents for path, contents in original.items())
            assert request(port, "/waf-private/auth.json")[0] == 404


if __name__ == "__main__":
    run_fixture(False)
    run_fixture(True)
    print("File Manager installation, WordPress profile, initial rotation, private state and reversible hooks passed.")
