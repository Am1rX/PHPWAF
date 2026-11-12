"""Check the example response policy on an actual Caddy HTTP and TLS hop."""

from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

from http_integration import ROOT, request, server


PRIVATE_HEADERS = {
    "server", "host", "x-powered-by", "x-php", "x-php-version", "x-aspnet-version", "x-aspnetmvc-version",
    "x-waf-version", "x-version", "x-runtime", "x-runtime-version", "x-application-version",
    "x-framework-version", "x-server-version", "x-backend-version", "x-generator", "x-debug-token",
    "x-debug-token-link", "x-profiler", "x-backend-server", "x-served-by",
}


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def check(port, path, expected, context=None):
    if context is None:
        connection = HTTPConnection("127.0.0.1", port, timeout=5)
    else:
        connection = HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        headers = dict(response.getheaders())
        body = response.read()
        assert response.status == expected, (path, response.status, expected)
        assert not {name.lower() for name in headers} & PRIVATE_HEADERS, (path, list(headers))
        assert not any(marker in body for marker in (b"private-debug-marker", b"PHP Parse error", b"syntax.php on line", b"X-Powered-By"))
        return headers, body
    finally:
        connection.close()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python tests/edge_integration.py PATH_TO_CADDY PATH_TO_OPENSSL")
    caddy, openssl = [str(Path(path).resolve()) for path in sys.argv[1:]]
    with tempfile.TemporaryDirectory() as folder:
        site = Path(folder)
        waf = site / "waf"
        waf.mkdir()
        for name in ("src", "waf_storage"):
            shutil.copytree(ROOT / name, waf / name)
        for name in ("autoload.php", "guard.php"):
            shutil.copyfile(ROOT / name, waf / name)
        shutil.copyfile(ROOT / "config.php", waf / "base-config.php")
        public = site / "public"
        public.mkdir()
        sample_headers = "\n".join(
            f"header('{name}: private-debug-marker');" for name in sorted(PRIVATE_HEADERS)
        )
        (public / "index.php").write_text(
            "<?php require __DIR__ . '/../waf/guard.php';\n" + sample_headers + "\necho 'app-ok';",
            encoding="utf-8",
        )
        (public / "upstream.php").write_text("<?php\n" + sample_headers + "\necho 'upstream-ok';", encoding="utf-8")
        (public / "syntax.php").write_text("<?php echo ;", encoding="utf-8")
        (public / "static.txt").write_text("static-ok", encoding="utf-8")
        (site / "openssl.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n")
        certificate = site / "cert.pem"
        key = site / "key.pem"
        subprocess.run([
            openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-config", str(site / "openssl.cnf"), "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(certificate),
        ], check=True, capture_output=True)
        context = ssl.create_default_context(cafile=str(certificate))
        snippet = (ROOT / "examples" / "Caddyfile").read_text().split("\nhttp://example.com {", 1)[0]

        with server(site, php_options=("-d", "display_errors=0", "-d", "display_startup_errors=0")) as origin:
            baseline = request(origin, "/upstream.php")
            assert baseline[0] == 200 and {"server", "x-powered-by", "x-debug-token"} <= {name.lower() for name in baseline[1]}
            http_port, tls_port, unused = free_port(), free_port(), free_port()
            assert len({http_port, tls_port, unused}) == 3
            config = site / "Caddyfile"
            config.write_text(f"""{{
    admin off
    auto_https disable_redirects
}}
{snippet}
(test_routes) {{
    route {{
        import phpwaf_privacy
        @redirect path /to-https
        redir @redirect https://127.0.0.1:{tls_port}/ 308
        @unavailable path /edge-down
        reverse_proxy @unavailable 127.0.0.1:{unused}
        reverse_proxy 127.0.0.1:{origin}
    }}
    import phpwaf_edge_errors
}}
http://127.0.0.1:{http_port} {{
    bind 127.0.0.1
    import test_routes
}}
https://127.0.0.1:{tls_port} {{
    bind 127.0.0.1
    tls "{certificate.as_posix()}" "{key.as_posix()}"
    import test_routes
}}
""", encoding="utf-8")
            subprocess.run([caddy, "adapt", "--adapter", "caddyfile", "--config", str(config)], check=True, capture_output=True)
            with (site / "caddy.log").open("wb") as log:
                proxy = subprocess.Popen(
                    [caddy, "run", "--adapter", "caddyfile", "--config", str(config)],
                    stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                try:
                    for _ in range(50):
                        try:
                            with socket.create_connection(("127.0.0.1", tls_port), timeout=0.1):
                                break
                        except OSError:
                            if proxy.poll() is not None:
                                raise RuntimeError((site / "caddy.log").read_text(errors="replace"))
                            time.sleep(0.05)
                    else:
                        raise RuntimeError("Caddy did not start.")
                    for port, ssl_context in ((http_port, None), (tls_port, context)):
                        for path, status in (
                            ("/", 200), ("/upstream.php", 200), ("/static.txt", 200), ("/missing.php", 404),
                            ("/syntax.php", 500), ("/edge-down", 502), ("/to-https", 308),
                            ("/?" + urlencode({"sample": "<svg>"}), 403),
                        ):
                            check(port, path, status, ssl_context)
                finally:
                    proxy.terminate()
                    proxy.wait(timeout=5)
    print("16 HTTP/TLS response checks passed with final-hop header removal and verified TLS.")


if __name__ == "__main__":
    main()
