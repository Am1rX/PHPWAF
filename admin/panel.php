<?php

declare(strict_types=1);

use Waf\Admin\Auth;
use Waf\Admin\Deployment;
use Waf\Admin\Locale;
use Waf\Admin\Policy;
use Waf\Admin\State;
use Waf\Detector;
use Waf\Response;

if (!defined('PHPWAF_PRIVATE_STATE')) {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../autoload.php';
Response::protectHeaders();

function input(array $data, string $key, int $limit = 512): string
{
    $value = $data[$key] ?? '';
    return is_string($value) && strlen($value) <= $limit ? $value : '';
}

function t(string $message, int|string ...$values): string
{
    return Locale::text($_SESSION['language'] ?? 'en', $message, ...$values);
}

function redirect(string $view, array $filters = []): void
{
    header('Location: ?' . http_build_query(['view' => $view] + $filters, '', '&', PHP_QUERY_RFC3986), true, 303);
    exit;
}

function findEvent(array $events, string $reference): ?array
{
    if (!preg_match('/\A[A-F0-9]{16}\z/', $reference)) {
        return null;
    }
    foreach ($events as $event) {
        if (($event['reference'] ?? '') === $reference) {
            return $event;
        }
    }
    return null;
}

function signatureCatalog(array $settings): array
{
    $engine = $settings['engine'] ?? [];
    return Detector::catalog($engine['disabled_rules'] ?? [], $engine['shadow_rule_ids'] ?? [], $settings['signatures'] ?? []);
}

try {
    $state = new State(PHPWAF_PRIVATE_STATE);
    $auth = $state->read('auth');
    $deployment = $state->read('deployment');
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $secure = in_array(strtolower($_SERVER['HTTPS'] ?? ''), ['on', '1'], true);
    if (!$auth || !$deployment) {
        throw new RuntimeException('Admin setup is incomplete.');
    }
    $localDevelopment = PHP_SAPI === 'cli-server' && in_array($ip, ['127.0.0.1', '::1'], true);
    $allowLocalSetup = $localDevelopment && !$secure
        && !isset($_SERVER['HTTP_FORWARDED']) && !isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !isset($_SERVER['HTTP_X_FORWARDED_PROTO']);
    if ((!$secure && !$localDevelopment) || !Auth::allows($ip, $auth['trusted'])) {
        http_response_code(404);
        exit;
    }
    $nonce = base64_encode(random_bytes(18));
    header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    header('Cache-Control: no-store, private');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header('X-Frame-Options: DENY');
    header('X-Robots-Tag: noindex, nofollow');

    $cookiePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/firewall-admin/index.php')), '/') . '/';
    Auth::session($state, $secure, $cookiePath);
    $requestedLanguage = input($_GET, 'lang', 2);
    if (in_array($requestedLanguage, ['en', 'fa'], true)) {
        $_SESSION['language'] = $requestedLanguage;
    }
    $language = ($_SESSION['language'] ?? '') === 'fa' ? 'fa' : 'en';
    $_SESSION['language'] = $language;
    $now = time();
    $signedIn = ($_SESSION['generation'] ?? '') === $auth['generation']
        && ($_SESSION['ip'] ?? '') === $ip
        && $now - ($_SESSION['started'] ?? 0) < 28800
        && $now - ($_SESSION['seen'] ?? 0) < 1200;
    if ($signedIn) {
        $_SESSION['seen'] = $now;
    }
    $view = input($_GET, 'view', 24);
    $view = in_array($view, ['overview', 'attacks', 'signatures', 'exceptions', 'access'], true) ? $view : 'overview';
    $mustRotate = !empty($auth['must_rotate']);
    if ($signedIn && $mustRotate) {
        $view = 'rotate';
    }
    $showSetupCode = $mustRotate && !$allowLocalSetup;
    $reference = input($_GET, 'event', 16);
    $viewFilters = match ($view) {
        'attacks' => ['q' => 128, 'decision' => 12, 'method' => 12, 'page' => 3, 'event' => 16],
        'signatures' => ['q' => 64, 'status' => 12, 'rule' => 24],
        'exceptions' => ['exception' => 16],
        default => [],
    };
    $context = [];
    foreach ($viewFilters as $key => $limit) {
        $value = input($_GET, $key, $limit);
        if ($value !== '') {
            $context[$key] = $value;
        }
    }
    $message = $_SESSION['notice'] ?? null;
    unset($_SESSION['notice']);

    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        $action = input($_POST, 'action', 24);
        if (!hash_equals($_SESSION['csrf'], input($_POST, 'csrf', 64))) {
            http_response_code(403);
            exit;
        }
        try {
            if ($action === 'login' && !$signedIn) {
                $username = input($_POST, 'username', 40);
                $password = input($_POST, 'password', 72);
                $setupCode = input($_POST, 'setup_code', 48);
                $loggedIn = $state->locked(static function () use ($state, $ip, $username, $password, $setupCode, $allowLocalSetup): ?array {
                    $current = $state->read('auth');
                    $attempt = Auth::setupCodeAccepted($current, $allowLocalSetup, $setupCode) ? $password : '';
                    if (!Auth::allows($ip, $current['trusted']) || !Auth::authenticate($state, $current, $ip, $attempt, $username)) {
                        return null;
                    }
                    $state->audit('Signed in', $current['username'], $ip);
                    return $current;
                });
                if ($loggedIn === null) {
                    throw new InvalidArgumentException(t('Invalid username or password, or sign-in is temporarily restricted.'));
                }
                session_regenerate_id(true);
                $_SESSION = ['csrf' => bin2hex(random_bytes(32)), 'generation' => $loggedIn['generation'],
                    'ip' => $ip, 'started' => $now, 'seen' => $now, 'language' => $language];
                redirect('overview');
            }
            if (!$signedIn) {
                http_response_code(403);
                exit;
            }
            if ($action === 'logout') {
                $_SESSION = ['language' => $language];
                session_regenerate_id(true);
                redirect('overview');
            }

            $state->locked(static function () use ($action, $state, $ip, $deployment): void {
                $current = $state->read('auth');
                if (!hash_equals($current['generation'], (string) ($_SESSION['generation'] ?? ''))
                    || !Auth::allows($ip, $current['trusted'])
                    || !Auth::authenticate($state, $current, $ip, input($_POST, 'password', 72), null)) {
                    throw new InvalidArgumentException(t('Check your current password. Failed attempts are temporarily limited.'));
                }
                if (!empty($current['must_rotate']) && $action !== 'credentials') {
                    throw new InvalidArgumentException(t('Change the initial password before managing the firewall.'));
                }
                $settings = $state->read('settings');
                switch ($action) {
                    case 'enable':
                    case 'disable':
                        (new Deployment($state, $deployment))->setActive($action === 'enable');
                        $audit = $action === 'enable' ? 'Firewall enabled' : 'Firewall disabled';
                        break;
                    case 'mode':
                        $mode = input($_POST, 'mode', 12);
                        if (!in_array($mode, ['monitor', 'filter', 'enforce'], true)) {
                            throw new InvalidArgumentException(t('Choose a valid inspection mode.'));
                        }
                        $settings['engine']['mode'] = $mode;
                        $state->write('settings', $settings);
                        $audit = 'Inspection mode set to ' . $mode;
                        break;
                    case 'signature':
                        $id = input($_POST, 'signature', 24);
                        $target = input($_POST, 'target', 8);
                        if (!isset(signatureCatalog($settings)[$id]) || !in_array($target, ['on', 'off'], true)) {
                            throw new InvalidArgumentException(t('The selected signature or status is invalid.'));
                        }
                        $settings['signatures'][$id] = $target === 'on';
                        $state->write('settings', $settings);
                        $audit = 'Signature ' . $id . ' set to ' . $target;
                        break;
                    case 'add-exception':
                        $event = findEvent($state->recent('events'), input($_POST, 'reference', 16));
                        $evidence = input($_POST, 'evidence', 2);
                        $days = input($_POST, 'days', 2);
                        if ($event === null || !ctype_digit($evidence) || !ctype_digit($days)) {
                            throw new InvalidArgumentException(t('The event or evidence was not found in the recent log.'));
                        }
                        $state->write('settings', Policy::add($settings, $event, (int) $evidence, (int) $days));
                        $audit = 'Exception added for ' . $event['reference'];
                        break;
                    case 'remove-exception':
                        $id = input($_POST, 'id', 16);
                        $settings['exceptions'] = array_values(array_filter($settings['exceptions'], static fn ($item) => $item['id'] !== $id));
                        $state->write('settings', $settings);
                        $audit = 'Exception removed';
                        break;
                    case 'trusted-hosts':
                        $rawHosts = $_POST['trusted'] ?? null;
                        if (!is_string($rawHosts) || strlen($rawHosts) > 4096) {
                            throw new InvalidArgumentException(t('The IP list is invalid.'));
                        }
                        $newHosts = Auth::addresses(preg_split('/[\r\n,]+/', $rawHosts) ?: []);
                        if (!Auth::allows($ip, $newHosts)) {
                            throw new InvalidArgumentException(t('Keep the IP for this session in the allowlist.'));
                        }
                        $current['trusted'] = $newHosts;
                        $state->write('auth', $current);
                        $audit = $newHosts === [] ? 'IP restrictions cleared' : 'Trusted hosts updated';
                        break;
                    case 'credentials':
                        $newPassword = input($_POST, 'new_password', 72);
                        if (!hash_equals($newPassword, input($_POST, 'confirm_password', 72))
                            || password_verify($newPassword, $current['hash'])) {
                            throw new InvalidArgumentException(t('Choose a different password and confirm it correctly.'));
                        }
                        $updated = Auth::identity(input($_POST, 'username', 40), $newPassword, $current['trusted']);
                        $state->write('auth', $updated);
                        session_regenerate_id(true);
                        $_SESSION['generation'] = $updated['generation'];
                        $_SESSION['csrf'] = bin2hex(random_bytes(32));
                        $audit = 'Administrator credentials rotated';
                        break;
                    default:
                        throw new InvalidArgumentException(t('Unknown request.'));
                }
                $state->audit($audit, $current['username'], $ip);
            });
            $_SESSION['notice'] = ['ok', t('Changes saved.')];
        } catch (InvalidArgumentException | RuntimeException $error) {
            if ($signedIn) {
                $state->audit('Action rejected: ' . preg_replace('/[^a-z-]/', '', $action), $auth['username'], $ip);
            }
            $_SESSION['notice'] = ['error', $error->getMessage()];
        }
        if ($action === 'remove-exception') {
            unset($context['exception']);
        }
        redirect($view === 'rotate' ? 'overview' : $view, $context);
    }

    $settings = $signedIn && !$mustRotate ? $state->read('settings') : [];
    $events = $signedIn && in_array($view, ['overview', 'attacks'], true) ? $state->recent('events') : [];
    $event = $signedIn ? findEvent($events, $reference) : null;
    $entries = $signedIn && $view === 'overview' ? (new Deployment($state, $deployment))->entries() : [];
    $audit = $signedIn && $view === 'access' ? $state->recent('audit', 30) : [];
    $signatures = $signedIn && $view === 'signatures' ? signatureCatalog($settings) : [];
    require __DIR__ . '/view.php';
} catch (Throwable $error) {
    $reference = Response::reference();
    error_log('[PHPWAF] Admin request failed ' . $reference . ' ' . get_class($error));
    Response::reject(503, $reference);
}
