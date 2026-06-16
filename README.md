# PHP Lightweight Firewall (WAF)

A lightweight, single-file Web Application Firewall (WAF) for PHP applications. It inspects every incoming request — query string, POST body, JSON payload, cookies, and the User-Agent header — scores it against a set of attack signatures, and blocks IPs that cross a risk threshold, either instantly or after repeated suspicious behavior within a time window.

No external dependencies, no database required — just drop the file in and include it.

https://www.youtube.com/watch?v=VtVZKqtjjnk

## Features

- **Signature-based detection** for common attack classes: XSS (script tags, event handlers, dangerous HTML elements, `javascript:`/`data:` URIs), SQL injection (tautologies, `UNION SELECT`, comment injection), path traversal, and basic command injection.
- **Two-tier blocking**:
  - *Immediate block* — a single request scoring above the risk threshold is blocked right away.
  - *Behavioral block* — smaller suspicious scores accumulate per IP over a rolling time window; once the accumulated score crosses the suspicion threshold, the IP gets blocked.
- **Double-decoding + HTML entity decoding** before pattern matching, to catch payloads obfuscated with URL or entity encoding.
- **Atomic, lock-protected storage** — all reads/writes to the block list and suspicion log happen inside a single file lock, eliminating race conditions under concurrent requests from the same IP.
- **Self-protective input limits** — caps on JSON nesting depth, total flattened keys, and per-value length, so a malicious request can't be used to exhaust CPU/memory before it's even evaluated.
- **Automatic periodic cleanup** of expired block/suspicion records, so storage files don't grow unbounded.
- **CIDR-aware whitelist** for trusted IPs or IP ranges.
- **Optional trusted-proxy support** to resolve the real client IP from `X-Forwarded-For` when running behind a reverse proxy or CDN you control.
- **Protected storage directory** — `.htaccess` rules compatible with both Apache 2.2 and 2.4, plus an `index.php` guard, to keep logs and block lists from being served directly.

## How It Works

Every request is flattened into a flat list of `key => value` pairs (including nested array/JSON fields) and each value is checked against a list of weighted regex rules. Matches add to a risk score:

| Score | Examples of triggers |
|---|---|
| 25 | `<script>` tags, shell command injection patterns |
| 20 | Dangerous HTML tags (`<svg>`, `<iframe>`, `<object>`...), `javascript:`/`data:` URIs, classic SQL injection (`UNION SELECT`, tautologies) |
| 15 | Inline event handlers (`onerror=`, `onload=`...), JS function calls (`eval(`, `alert(`...), path traversal sequences |
| 10 | Quote-then-semicolon context breaks, SQL comment markers right after a quote |

If a single request's total score reaches the **risk threshold**, the IP is blocked immediately. If the score is lower but nonzero, it's added to that IP's running total for the current time window; crossing the **suspicion threshold** within that window triggers a behavioral block. Blocked IPs receive a 403 page until their block expires.

## Installation

1. Copy `Firewall.php` into your project (a common location is your bootstrap file or a `security/` folder).
2. Define the access guard constant and include it at the very top of your application's entry point, before any other logic runs:

```php
<?php
define('PREVENT_DIRECT_ACCESS', true);
require_once __DIR__ . '/Firewall.php';

// ... rest of your application
```

3. Make sure the directory containing `Firewall.php` is writable by PHP — the script will create a `waf_storage/` subfolder on first run to hold the block list, suspicion log, and attack log.

## Configuration

All settings are class properties/constants at the top of `Firewall.php`:

```php
private $whitelist = ['203.0.113.10', '198.51.100.0/24']; // exact IPs or CIDR ranges

private $trust_proxy_header = false;   // only enable behind a proxy YOU control
private $trusted_proxies = [];         // IP(s) of that reverse proxy

const RISK_THRESHOLD = 15;       // score for an instant block
const SUSPICION_THRESHOLD = 20;  // accumulated score for a behavioral block
const TIME_WINDOW = 60;          // seconds, window for accumulating suspicion
const BLOCK_DURATION = 300;      // seconds an IP stays blocked
```

> **Proxy/CDN warning:** only set `trust_proxy_header = true` if requests can *only* reach PHP through a reverse proxy you control that overwrites `X-Forwarded-For` itself. If clients can reach your server directly, enabling this lets attackers spoof their IP and bypass blocking entirely.

## Storage

State is kept as JSON files inside `waf_storage/`:

- `blocked_ips.json` — currently blocked IPs, block reason, and expiry time.
- `suspicion_log.json` — per-IP accumulated scores within the current time window.
- `attacks.log` — append-only log of every block event with the detected patterns.

This directory is protected at the web-server level (`.htaccess`) and via a guard `index.php`, but it's still good practice to keep it outside your public web root if your hosting setup allows it.

## Limitations

This is a regex-signature WAF, which means it's a useful additional layer but **not a substitute** for secure coding practices. Determined attackers can often bypass signature-based filters through encoding tricks, alternate syntax, or context-specific evasion that a generic blocklist can't anticipate. Pair this with:

- Parameterized queries / prepared statements for all database access.
- Proper output encoding for any user-controlled data rendered in HTML.
- A Content Security Policy (CSP) header.
- Framework-level input validation.

At higher traffic volumes, file-based JSON storage with locking can become an I/O bottleneck; consider migrating to SQLite (WAL mode) or Redis for the block list and suspicion tracking if you're handling significant request volume.

## License

MIT — use, modify, and distribute freely.
