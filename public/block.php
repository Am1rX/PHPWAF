<?php
/**
 * Generic 403 block page. Intentionally says nothing about a firewall or why
 * the request was flagged — revealing that tips off attackers and helps them
 * tune bypasses. It just states the request was stopped and gives a reference
 * code an honest user can quote to support.
 */
if (!headers_sent()) {
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
}
$ref = $GLOBALS['waf_ref'] ?? strtoupper(substr(bin2hex(random_bytes(4)), 0, 8));
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Request blocked</title>
<style>
  :root {
    --bg: #0e1014;
    --panel: #15181f;
    --line: #262b36;
    --ink: #e6e9ef;
    --muted: #7e8796;
    --accent: #4ea1ff;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    background: var(--bg);
    color: var(--ink);
    font-family: var(--sans);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    width: 100%;
    max-width: 440px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 40px 34px;
  }
  .status {
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 0.18em;
    color: var(--accent);
    text-transform: uppercase;
    margin: 0 0 18px;
  }
  h1 {
    font-size: 22px;
    font-weight: 600;
    line-height: 1.3;
    margin: 0 0 12px;
    letter-spacing: -0.01em;
  }
  p {
    color: var(--muted);
    font-size: 14.5px;
    line-height: 1.65;
    margin: 0 0 26px;
  }
  .ref {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    border-top: 1px solid var(--line);
    padding-top: 18px;
  }
  .ref span { font-size: 12px; color: var(--muted); }
  .ref code {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--ink);
    background: #0c0e12;
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 6px 10px;
    user-select: all;
  }
  @media (prefers-reduced-motion: no-preference) {
    .card { animation: rise .35s ease both; }
    @keyframes rise { from { opacity: 0; transform: translateY(8px); } }
  }
</style>
</head>
<body>
  <main class="card" role="alert">
    <p class="status">403 &middot; Blocked</p>
    <h1>We couldn't process this request.</h1>
    <p>Something about it looked unsafe, so we stopped it before it reached the site. If you believe this was a mistake, wait a few minutes and try again, or contact support with the reference below.</p>
    <div class="ref">
      <span>Reference</span>
      <code><?= htmlspecialchars($ref, ENT_QUOTES, 'UTF-8') ?></code>
    </div>
  </main>
</body>
</html>
