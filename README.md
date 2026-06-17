# PHP-WAF

A lightweight, dependency-free Web Application Firewall for PHP applications. Drop in **one line** and every request is inspected for XSS, SQL injection, command injection, path traversal, and scanner behavior before it reaches your code.

It is designed to be **operationally honest**: it can run in monitor mode before it ever blocks anything, it logs every decision in a machine-readable format, and it can push blocks all the way out to nginx or your firewall so blocked traffic never costs you a PHP worker.

> This is a focused, embeddable layer — not a replacement for [ModSecurity + the OWASP Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/). Use it where you want signature + behavioral protection inside the app with near-zero setup, or as defense-in-depth alongside a full WAF.

---

## Why this exists

Most hand-rolled PHP firewalls share three problems. This project fixes each:

| Common problem | What this does instead |
| --- | --- |
| Blocked IPs still hit PHP on every request (a self-inflicted DoS) | Optionally writes blocks to an **nginx denylist** / **fail2ban**, dropping them at the edge |
| State stored in JSON files that lock and grow under load | **Redis / APCu** backends with native TTLs; file storage only as a fallback |
| Rules ship straight to "block" and break real users | **Monitor mode** + per-rule IDs + a **benchmark** that measures false positives |

---

## Features

- **Layered detection** — signature rules *plus* a behavioral model that accumulates a suspicion score across requests, so slow scanners get caught even when no single request crosses the line.
- **Monitor vs. enforce** — run in `monitor` to log decisions without blocking while you tune, then flip to `enforce`.
- **Pluggable storage** — `auto` selects Redis → APCu → file. Redis uses `INCRBY`+`EXPIRE` (atomic, no locks, no GC, multi-server).
- **Edge blocking** — optional nginx `geo` denylist and fail2ban filter so bans happen before PHP-FPM.
- **Honeypot fields** — hidden form inputs that bots fill and humans never see → instant block, zero false positives.
- **Structured logging** — JSON Lines for SIEM/ELK + a fail2ban-friendly text log. Every block records which rule IDs fired.
- **Evasion-aware normalization** — multi-layer URL decoding, HTML-entity decoding, comment stripping, null-byte removal, Unicode-safe lowercasing.
- **ReDoS-hardened rules** — patterns match openers, not unbounded bodies; input is capped by length/depth/key count.
- **IPv4 + IPv6** throughout, including CIDR whitelists and trusted-proxy handling.

---

## Architecture

```
            ┌──────────────┐   blocked?   ┌─────────────────────┐
  request → │  nginx (geo) │ ───────────→ │  403 at the edge     │
            └──────┬───────┘   (optional) └─────────────────────┘
                   │ allowed
                   ▼
            ┌──────────────┐
            │   guard.php  │   ← one require() in your front controller
            └──────┬───────┘
                   ▼
   Normalizer → Detector (signatures) → score
                   │
                   ├─ score ≥ block_threshold ───────────┐
                   ├─ accumulated ≥ suspicion_threshold ──┤→ block + log + denylist
                   └─ honeypot touched ───────────────────┘
                   │
   Storage (Redis │ APCu │ File)   Logger (JSONL + text)
```

---

## Requirements

- PHP **8.0+** with `mbstring` and `json`
- Optional: `redis` extension (recommended in production) or `apcu`
- No Composer, no third-party packages

---

## Install

Copy the `waf/` folder into your project, then add a single line at the very top of your front controller (e.g. `public/index.php`), **before any other code**:

```php
require __DIR__ . '/waf/guard.php';
```

That's it. Defaults are safe. Everything else is configuration.

> **Tip:** deploy with `mode => 'monitor'` first (see below), watch `waf_storage/events.jsonl` for a day, then switch to `filter` or `enforce`.

---

## Activate it everywhere automatically (no per-file editing)

If you have a lot of PHP files and don't want to add the `require` line to each one, turn it on for the **whole site at once** with PHP's `auto_prepend_file`. Pick the one that matches your host — ready-made files are in [`examples/auto_prepend/`](examples/auto_prepend/):

| Your host | Use this file | Put it where |
| --- | --- | --- |
| Shared hosting (cPanel/Plesk, PHP-FPM) | `.user.ini` | your web root (e.g. `public_html/`) |
| Apache with mod_php | `.htaccess` | your web root |
| VPS / dedicated (you control PHP) | `php.ini` snippet | your `php.ini`, then restart PHP |

Each file just needs the **absolute path** to `guard.php`. To find it, drop a file containing `<?php echo __DIR__;` in your web root, open it in the browser (it prints e.g. `/home/youruser/public_html`), add `/waf/guard.php`, then delete that file.

With auto-prepend on, the WAF runs before every page automatically and you **don't** add any `require` line yourself. Use **either** auto-prepend **or** the manual `require` — not both.

> `.user.ini` changes can take a few minutes to take effect and don't affect CLI scripts (which is what you want).

---

## Configuration

All settings live in [`config.php`](config.php). The important ones:

```php
'mode' => 'enforce',           // 'monitor' to log only, 'enforce' to block

'scoring' => [
    'block_threshold'      => 15,   // single-request score that blocks immediately
    'suspicion_threshold'  => 20,   // accumulated score (per window) that blocks
    'time_window'          => 60,   // suspicion window, seconds
    'block_duration'       => 300,  // how long a block lasts, seconds
],

'storage'  => ['driver' => 'auto'], // auto → redis → apcu → file
'whitelist'=> ['203.0.113.0/24', '::1'],
'honeypot_fields' => ['website_url'],
'disabled_rules'  => [],            // e.g. ['SQLI-002'] if it's noisy for you
```

### Modes

- **`monitor`** — inspects and logs the decision it *would* make, but never blocks. Use this to find false positives against real traffic before enforcing.
- **`filter`** — blocks each malicious request with a 403, but **never bans the IP**. The same client can immediately send a clean request and be served. Stateless: it needs no storage and keeps no block list. Use this when you don't want to risk locking anyone out.
- **`enforce`** — blocks the request *and* bans the offending IP for `block_duration`, with behavioral accumulation and optional edge denylist.

| | logs | blocks the bad request | bans the IP | needs storage |
| --- | :---: | :---: | :---: | :---: |
| `monitor` | ✅ | ❌ | ❌ | ❌ |
| `filter`  | ✅ | ✅ | ❌ | ❌ |
| `enforce` | ✅ | ✅ | ✅ | ✅ |

### Storage backends

| Driver | Best for | Notes |
| --- | --- | --- |
| `redis` | Production, multi-server | `INCRBY`+`EXPIRE`, atomic, no locks, no manual cleanup |
| `apcu`  | Single server | In-memory, fast, native TTLs |
| `file`  | Anywhere / fallback | Atomic locked read-modify-write + GC; slowest under load |

`auto` (default) picks the best available and **degrades gracefully** — if Redis is configured but unreachable, it falls back to file storage and logs a notice.

---

## Edge blocking (recommended)

Blocking inside PHP still means a blocked attacker wakes up a PHP worker on every request. Push the block outward.

Set in config:

```php
'edge' => ['enabled' => true, 'denylist_file' => __DIR__ . '/waf_storage/denylist.conf'],
```

**Option A — nginx `geo` denylist.** See [`examples/nginx.conf`](examples/nginx.conf). The WAF appends `1.2.3.4 1;` lines; nginx returns 403 before PHP. Reload nginx on a cron to pick up new entries.

**Option B — fail2ban (instant, reload-free).** Point fail2ban at the WAF's text log; it bans at iptables/nftables. See [`examples/fail2ban/`](examples/fail2ban/):

```
examples/fail2ban/phpwaf.conf  →  /etc/fail2ban/filter.d/phpwaf.conf
examples/fail2ban/jail.local   →  append to /etc/fail2ban/jail.local
```

---

## Honeypot fields

Add a hidden input no human will ever fill, and list its name in `honeypot_fields`. Any request that submits it non-empty is blocked instantly with zero false positives — bots fill every field they find. See the markup in [`public/index.php`](public/index.php):

```html
<div style="position:absolute;left:-9999px" aria-hidden="true">
  <input name="website_url" tabindex="-1" autocomplete="off">
</div>
```

---

## Logging

Two logs are written to `waf_storage/`:

- **`events.jsonl`** — one JSON object per line, ready for ELK/Grafana/Splunk:
  ```json
  {"ts":"2026-06-16T12:00:00+00:00","ip":"1.2.3.4","decision":"block","mode":"enforce","score":40,"rule_ids":["XSS-001","XSS-005"],"types":["Script tag","JS sink/function"],"method":"POST","uri":"/login"}
  ```
- **`attacks.log`** — human- and fail2ban-readable plaintext.

Every decision records the rule IDs that fired, so you can see exactly *why* something was blocked and disable a noisy rule via `disabled_rules`.

---

## Testing

A benchmark ships with the project. It scores a corpus of real attack strings and benign strings and reports the two numbers that actually matter:

```bash
php tests/run.php
```

```
Detection rate:      100.0%  (20/20 attacks caught)
False-positive rate:   0.0%  (0/20 benign flagged)
```

Add your own real traffic samples to the benign list before enforcing — that's the fastest way to catch a rule that would hurt your users.

---

## Rule reference

| ID | Category | What it catches |
| --- | --- | --- |
| `XSS-001..005` | XSS | script tags, dangerous elements, event handlers, `javascript:`/`data:` protocols, JS sinks |
| `SQLI-001..004` | SQL injection | `UNION SELECT`, `information_schema`, tautologies, comment truncation, stacked queries |
| `LFI-001..002` | Traversal / LFI | `../`, `/etc/passwd`, PHP wrappers (`php://`, `phar://`) |
| `RCE-001..002` | Command injection | shell verbs after metacharacters, `$()`, backticks, pipes to a shell |
| `GEN-001..002` | Generic | context-break sequences, backtick exec |

Each rule has a stable ID used in logs and in `disabled_rules`.

---

## Tuning false positives

1. Start in `monitor` mode.
2. Watch `events.jsonl` for `decision:"monitor"` entries on legitimate traffic.
3. Note the offending `rule_ids`.
4. Either add the source to `whitelist`, or add the rule ID to `disabled_rules`.
5. Re-run `php tests/run.php` after adding the false-positive string to the benign corpus.
6. Switch to `enforce`.

Endpoints that legitimately accept HTML/markup (rich-text editors) should be whitelisted or handled before `guard.php`.

---

## Project layout

```
waf/
├── guard.php             # one-line entry point
├── autoload.php          # tiny PSR-4-style autoloader (no Composer)
├── config.php            # all settings
├── src/
│   ├── Firewall.php      # orchestrator
│   ├── Normalizer.php    # decode/canonicalize input
│   ├── Detector.php      # signature rules (stable IDs)
│   ├── Logger.php        # JSONL + text logging
│   ├── DenyList.php      # nginx edge denylist writer
│   └── Storage/
│       ├── StorageInterface.php
│       ├── RedisStorage.php
│       ├── ApcuStorage.php
│       ├── FileStorage.php
│       └── StorageFactory.php
├── public/
│   ├── index.php         # demo protected page + honeypot form
│   └── block.php         # generic 403 page (see below)
├── tests/run.php         # detection + false-positive benchmark
├── examples/             # nginx + fail2ban + auto_prepend (site-wide) configs
└── waf_storage/          # runtime data (git-ignored)
```

---

## The block page

[`public/block.php`](public/block.php) is intentionally generic. It returns a clean 403 and a reference code, and it **says nothing about a firewall** — telling an attacker they hit a WAF just helps them tune a bypass. Honest users can quote the reference code to support.

---

## Limitations (read these)

- **Signatures are bypassable by design.** This catches commodity attacks and scanners, not a determined, custom-tailored attacker. Layer it with a real WAF and good app-level validation.
- **IP-based blocking has collateral** on shared/CGNAT addresses. Whitelist known-good ranges; consider blocking at session level for sensitive flows.
- **Not a substitute for fixing the bug.** A WAF buys time; parameterized queries, output encoding, and input validation are the actual fix.

---

## License

MIT. Use it, fork it, ship it.
