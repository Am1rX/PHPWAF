<?php

declare(strict_types=1);

use Waf\Admin\Auth;
use Waf\Admin\Deployment;
use Waf\Admin\Installer;
use Waf\Admin\State;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../autoload.php';

$options = getopt('', ['state:', 'root:', 'entry:', 'trust:', 'user:', 'settings:', 'reset-admin', 'disable', 'reload-engine', 'help']);
if (isset($options['help'])) {
    echo <<<'HELP'
Initial installation:
  php admin/setup.php --root=/site/public --state=/site/waf-private --entry=index.php
  Repeat --entry as needed. --trust is optional and can be repeated.
  Sign in as admin / admin, then replace the password. Use the printed setup code over HTTPS.
  To set strong credentials at installation, supply --user and enter the password twice on stdin.
Recovery:
  php admin/setup.php --state=/site/waf-private --reset-admin --user=unique-operator [--trust=192.0.2.20]
  With a previous settings file, reinstall with --settings=keep or --settings=reset.
Emergency disable:
  php admin/setup.php --state=/site/waf-private --disable
Reload engine settings from the package's config.php:
  php admin/setup.php --state=/site/waf-private --reload-engine

HELP;
    exit;
}

try {
    $statePath = $options['state'] ?? '';
    if (!is_string($statePath) || !preg_match('~^(?:/|[A-Za-z]:[/\\\\])~', $statePath)) {
        throw new RuntimeException('Pass an absolute private directory with --state.');
    }
    $root = isset($options['root']) && is_string($options['root']) ? realpath($options['root']) : false;
    if (!$root && !isset($options['reset-admin']) && !isset($options['disable']) && !isset($options['reload-engine'])) {
        throw new RuntimeException('Pass an existing public document root with --root.');
    }
    if ($root && !is_dir($root)) {
        throw new RuntimeException('The public root must be a directory.');
    }
    if ($root && (Deployment::within(__DIR__, $root) || Deployment::within($statePath, $root))) {
        throw new RuntimeException('Put the firewall package and private state outside the public root.');
    }
    if (!is_dir($statePath) && (!$root || !@mkdir($statePath, 0700, true))) {
        throw new RuntimeException('Cannot open or create the private directory.');
    }
    $state = new State($statePath);
    $state->locked(static function () use ($options, $root, $state): void {
        $oldDeploy = $state->read('deployment');
        $oldSettings = $state->read('settings');
        if (isset($options['reload-engine'])) {
            if (!$oldDeploy || !$oldSettings) {
                throw new RuntimeException('No installed configuration was found.');
            }
            $oldSettings['engine'] = Installer::engine();
            $state->write('settings', $oldSettings);
            $state->audit('Engine configuration reloaded from CLI', 'server-owner', '-');
            echo "Engine settings reloaded.\n";
            return;
        }
        if (isset($options['disable'])) {
            if (!$oldDeploy || !$oldSettings) {
                throw new RuntimeException('No installed configuration was found.');
            }
            (new Deployment($state, $oldDeploy))->setActive(false);
            $state->audit('Disabled from CLI', 'server-owner', '-');
            echo "Firewall disabled. Managed includes removed.\n";
            return;
        }

        $recover = isset($options['reset-admin']);
        if ($recover && !$oldDeploy) {
            throw new RuntimeException('No existing installation was found.');
        }
        $oldAuth = $state->read('auth');
        $trusted = Auth::addresses(isset($options['trust']) ? (array) $options['trust'] : ($oldAuth['trusted'] ?? []));
        $deploy = $oldDeploy;
        if (!$recover) {
            $deploy = Installer::plan($state, $root, (array) ($options['entry'] ?? ['index.php']));
            if ($oldDeploy && ($oldDeploy['root'] !== $root || $oldDeploy['entries'] !== $deploy['entries'])) {
                throw new RuntimeException('Existing entry-point manifest differs. Disable the old installation and use a fresh private directory for a different manifest.');
            }
        }
        unset($deploy['trust_limit']);

        $choice = $options['settings'] ?? null;
        if (!$recover && $oldSettings && !in_array($choice, ['keep', 'reset'], true)) {
            throw new RuntimeException('Found existing firewall settings. Use --settings=keep to reuse them or --settings=reset for fresh settings.');
        }
        if ($choice !== null && !in_array($choice, ['keep', 'reset'], true)) {
            throw new RuntimeException('--settings accepts only keep or reset.');
        }

        $setupCode = null;
        if (isset($options['user'])) {
            $username = $options['user'];
            if (!is_string($username)) {
                throw new RuntimeException('Choose one administrator username.');
            }
            fwrite(STDERR, "Provide the new password and confirmation on two lines of stdin.\n");
            $password = rtrim((string) fgets(STDIN, 256), "\r\n");
            $confirm = rtrim((string) fgets(STDIN, 256), "\r\n");
            if (!hash_equals($password, $confirm)) {
                throw new RuntimeException('The password confirmation does not match.');
            }
            $identity = Auth::identity($username, $password, $trusted);
        } elseif ($recover || !$oldAuth) {
            [$identity, $setupCode] = Auth::initialIdentity($trusted);
        } else {
            $identity = $oldAuth;
            $identity['trusted'] = $trusted;
        }
        Installer::ensureSessions($state);

        if (!$recover) {
            $settings = $choice === 'keep' && $oldSettings ? $oldSettings : State::defaults(Installer::engine());
            if ($oldSettings && $choice === 'reset') {
                (new Deployment($state, $oldDeploy))->setActive(false);
            }
            Installer::writeHooks($state, $root);
            $state->write('settings', $settings);
        }
        $state->write('deployment', $deploy);
        $state->write('auth', $identity);
        $state->write('rate', []);
        $state->audit($recover ? 'Administrator recovered from CLI' : 'Panel installed from CLI', 'server-owner', '-');
        echo "Administrator saved. Open /firewall-admin/index.php from a trusted host.\n";
        if ($setupCode !== null) {
            echo "Initial login: admin / admin. Change the password before using the console.\n";
            echo "First sign-in setup code for HTTPS: $setupCode\n";
        }
    });
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . "\n");
    exit(1);
}
