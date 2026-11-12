<?php

declare(strict_types=1);

use Waf\Admin\Deployment;
use Waf\Admin\Installer;
use Waf\Admin\Locale;
use Waf\Admin\State;
use Waf\Response;

if (!defined('PHPWAF_WEB_INSTALL_ROOT') || !defined('PHPWAF_WEB_INSTALL_STATE') || !defined('PHPWAF_WEB_INSTALL_KEY')) {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../autoload.php';
Response::protectHeaders();
header('Cache-Control: no-store, private');
header('Referrer-Policy: same-origin');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');
header('X-Frame-Options: DENY');

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$https = in_array(strtolower($_SERVER['HTTPS'] ?? ''), ['on', '1'], true);
$local = PHP_SAPI === 'cli-server' && in_array($ip, ['127.0.0.1', '::1'], true)
    && !isset($_SERVER['HTTP_FORWARDED']) && !isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !isset($_SERVER['HTTP_X_FORWARDED_PROTO']);
$root = realpath(PHPWAF_WEB_INSTALL_ROOT);
$documentRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
$publicRoot = $documentRoot !== '' ? realpath($documentRoot) : false;
$package = realpath(__DIR__ . '/..');
$parent = realpath(dirname(PHPWAF_WEB_INSTALL_STATE));
$keyFile = realpath(PHPWAF_WEB_INSTALL_KEY);
if ((!$https && !$local) || !$root || !$publicRoot || !$package || !$parent || !$keyFile
    || !Deployment::within($root, $publicRoot) || Deployment::within($package, $publicRoot)
    || Deployment::within($keyFile, $publicRoot) || !is_file($keyFile) || is_link(PHPWAF_WEB_INSTALL_STATE)) {
    http_response_code(404);
    exit;
}
$statePath = realpath(PHPWAF_WEB_INSTALL_STATE) ?: $parent . '/' . basename(PHPWAF_WEB_INSTALL_STATE);
if (Deployment::within($statePath, $publicRoot) || is_file($statePath . '/auth.json')) {
    http_response_code(404);
    exit;
}

$key = trim((string) @file_get_contents($keyFile, false, null, 0, 257));
if (!preg_match('/\A[A-Za-z0-9_-]{32,128}\z/', $key) || count(array_unique(str_split($key))) < 10) {
    http_response_code(404);
    exit;
}
$method = $_SERVER['REQUEST_METHOD'] ?? '';
if (!in_array($method, ['GET', 'POST'], true)) {
    header('Allow: GET, POST');
    http_response_code(405);
    exit;
}

$language = ($_GET['lang'] ?? '') === 'fa' ? 'fa' : 'en';
$label = static fn (string $text): string => htmlspecialchars(Locale::text($language, $text), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$escape = static fn (string $text): string => htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$profile = 'php';
$entryText = '';
$setupCode = null;
$errorMessage = null;

if ($method === 'POST') {
    $submitted = $_POST['owner_key'] ?? null;
    if (($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') === 'cross-site' || !is_string($submitted) || !hash_equals($key, $submitted)) {
        http_response_code(403);
        exit('Setup could not be authorized.');
    }

    try {
        $profile = is_string($_POST['profile'] ?? null) ? $_POST['profile'] : '';
        $entryText = is_string($_POST['entries'] ?? null) ? trim($_POST['entries']) : '';
        if (!in_array($profile, ['php', 'wordpress'], true) || strlen($entryText) > 8192) {
            throw new InvalidArgumentException('Choose a valid profile and a shorter entry point list.');
        }
        $entries = $entryText !== '' ? preg_split('/\R/u', $entryText, -1, PREG_SPLIT_NO_EMPTY) : [];
        if ($entries === false) {
            throw new InvalidArgumentException('Enter one PHP entry point per line.');
        }
        $entries = array_values(array_filter(array_map('trim', $entries), static fn ($entry) => $entry !== ''));
        if ($profile === 'wordpress') {
            $entries = array_merge(Installer::wordpressEntries($root), $entries);
        } elseif ($entries === []) {
            $entries = ['index.php'];
        }
        if (!is_dir($statePath) && !@mkdir($statePath, 0700)) {
            throw new RuntimeException('Cannot create the private firewall directory.');
        }
        $state = new State($statePath);
        if (Deployment::within($state->dir, $publicRoot)) {
            throw new RuntimeException('The firewall directory must be outside the document root.');
        }
        $setupCode = $state->locked(static fn () => Installer::initializeWeb($state, $root, $entries));
    } catch (InvalidArgumentException | RuntimeException $error) {
        $errorMessage = $error->getMessage();
        http_response_code(400);
    } catch (Throwable $error) {
        error_log('[PHPWAF] File Manager installation failed: ' . get_class($error));
        $errorMessage = 'Installation could not finish. Check the PHP error log.';
        http_response_code(500);
    }
}

$nonce = base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
?>
<!doctype html>
<html lang="<?= $language ?>" dir="<?= $language === 'fa' ? 'rtl' : 'ltr' ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $label('PHPWAF installation') ?></title>
<style nonce="<?= $escape($nonce) ?>"><?= file_get_contents(__DIR__ . '/panel.css') ?></style>
</head>
<body>
<main class="login">
  <section class="login-box" aria-labelledby="install-title">
    <header class="login-head">
      <bdi class="brand">PHPWAF</bdi>
      <a class="button quiet language-link" href="?lang=<?= $language === 'en' ? 'fa' : 'en' ?>" lang="<?= $language === 'en' ? 'fa' : 'en' ?>"><?= $language === 'en' ? 'فارسی' : 'English' ?></a>
    </header>
    <div class="login-content">
      <?php if ($setupCode !== null): ?>
        <h1 id="install-title"><?= $label('Installation complete') ?></h1>
        <div class="stack">
          <p><?= $label('Initial sign-in') ?> <bdi class="mono">admin / admin</bdi></p>
          <p><?= $label('Copy this setup code for the first sign-in. It is shown only here.') ?></p>
          <pre dir="ltr"><?= $escape($setupCode) ?></pre>
          <p class="subtle"><?= $label('After saving the code, delete the installer and its private key in File Manager.') ?></p>
          <a class="button primary" href="./firewall-admin/index.php?lang=<?= $language ?>"><?= $label('Open firewall panel') ?></a>
        </div>
      <?php else: ?>
        <h1 id="install-title"><?= $label('Install from File Manager') ?></h1>
        <?php if ($errorMessage !== null): ?><p class="notice error" role="alert"><?= $label($errorMessage) ?></p><?php endif; ?>
        <form method="post" class="stack">
          <label><?= $label('Private installation key') ?><input name="owner_key" type="password" maxlength="128" autocomplete="off" required></label>
          <label><?= $label('Site type') ?><select name="profile">
            <option value="php"<?= $profile === 'php' ? ' selected' : '' ?>><?= $label('PHP website') ?></option>
            <option value="wordpress"<?= $profile === 'wordpress' ? ' selected' : '' ?>>WordPress</option>
          </select></label>
          <label><?= $label('PHP entry points, one per line') ?><textarea dir="ltr" name="entries" maxlength="8192" rows="3" placeholder="index.php"><?= $escape($entryText) ?></textarea></label>
          <p class="subtle"><?= $label('The PHP profile uses index.php if left blank. WordPress adds its standard entry points and any extra files listed here.') ?></p>
          <button class="button primary" type="submit"><?= $label('Install') ?></button>
        </form>
      <?php endif; ?>
    </div>
  </section>
</main>
</body>
</html>
