<?php
// Demo of a protected application entry point.
// The single require below is the ONLY thing you add to your own app.
require __DIR__ . '/../guard.php';

// --- your normal application code runs only if the request passed the WAF ---
?><!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Protected demo</title></head>
<body style="font-family:system-ui;max-width:520px;margin:60px auto">
  <h1>This page is protected</h1>
  <p>The request reached your app, which means the WAF allowed it.</p>

  <form method="post" action="">
    <label>Name <input name="name"></label><br><br>
    <label>Message <textarea name="message"></textarea></label><br><br>

    <!-- HONEYPOT: hidden from humans, irresistible to bots.
         List its name in config.php -> honeypot_fields to arm it. -->
    <div style="position:absolute;left:-9999px" aria-hidden="true">
      <label>Website <input name="website_url" tabindex="-1" autocomplete="off"></label>
    </div>

    <button type="submit">Send</button>
  </form>
</body>
</html>
