<?php

declare(strict_types=1);

namespace Waf\Admin;

use RuntimeException;
use Throwable;

final class Installer
{
    public static function wordpressEntries(string $root): array
    {
        if (!is_file($root . '/wp-load.php') || !is_dir($root . '/wp-admin')) {
            throw new RuntimeException('WordPress was not found in this directory.');
        }
        return array_values(array_filter([
            'index.php', 'wp-login.php', 'wp-admin/index.php', 'wp-admin/post.php',
            'wp-admin/admin-ajax.php', 'wp-cron.php', 'xmlrpc.php',
        ], static fn (string $entry): bool => is_file($root . '/' . $entry)));
    }

    public static function plan(State $state, string $root, array $requested): array
    {
        $root = realpath($root);
        $package = dirname(__DIR__, 2);
        if ($root === false || !is_dir($root)) {
            throw new RuntimeException('Choose an existing site directory.');
        }
        if (Deployment::within($state->dir, $root) || Deployment::within($package, $root)) {
            throw new RuntimeException('Keep the firewall package and private state outside the site directory.');
        }
        foreach (['.user.ini', '.htaccess'] as $name) {
            $path = $root . '/' . $name;
            if (is_file($path) && preg_match('/^\s*(?:php_value\s+)?auto_prepend_file\b[^\r\n]*guard\.php/im',
                (string) file_get_contents($path, false, null, 0, 131072))) {
                throw new RuntimeException('Remove the existing PHPWAF auto-prepend setting before using managed activation.');
            }
        }

        $panel = self::panelPath($state, $root);
        $entries = [];
        foreach ($requested as $entry) {
            if (!is_string($entry) || $entry === '' || strlen($entry) > 260 || strpos($entry, "\0") !== false) {
                throw new RuntimeException('Enter relative paths to existing PHP entry points.');
            }
            $path = realpath($root . '/' . $entry);
            if ($path === false || !is_file($path) || !Deployment::within($path, $root)
                || Deployment::within($path, dirname($panel)) || !str_ends_with(strtolower($path), '.php')) {
                throw new RuntimeException('Each entry must name an existing PHP file within the site directory.');
            }
            $entries[$path] = $path;
        }
        if ($entries === [] || count($entries) > 64) {
            throw new RuntimeException('Select between 1 and 64 PHP entry points.');
        }
        return ['root' => $root, 'entries' => array_values($entries)];
    }

    public static function engine(): array
    {
        $engine = require dirname(__DIR__, 2) . '/config.php';
        if (!in_array($engine['mode'] ?? null, ['monitor', 'filter', 'enforce'], true)) {
            throw new RuntimeException('Set a valid mode in config.php before installing.');
        }
        return $engine;
    }

    public static function ensureSessions(State $state): void
    {
        $path = $state->dir . '/sessions';
        if (is_link($path) || (!is_dir($path) && !@mkdir($path, 0700))) {
            throw new RuntimeException('Cannot create the private session directory.');
        }
    }

    public static function writeHooks(State $state, string $root): void
    {
        $panel = self::panelPath($state, $root);
        if (!is_dir(dirname($panel)) && !@mkdir(dirname($panel), 0755)) {
            throw new RuntimeException('Cannot create the public panel entry directory.');
        }
        $package = dirname(__DIR__, 2);
        $dir = self::phpPath($state->dir);
        $guard = self::phpPath($package . '/guard.php');
        $controller = self::phpPath($package . '/admin/panel.php');
        State::replace($state->dir . '/managed-loader.php', "<?php\n\\define('PHPWAF_PRIVATE_STATE', $dir);\nrequire_once $guard;\n", 0600);
        State::replace($panel, "<?php\n/* PHPWAF admin entry */\n\\define('PHPWAF_PRIVATE_STATE', $dir);\nrequire $controller;\n", 0644);
    }

    /**
     * Call under the management lock. The web installer may initialize empty state only.
     * Returns the setup code exactly once, after all install files have been published.
     */
    public static function initializeWeb(State $state, string $root, array $entries): string
    {
        $deployment = self::plan($state, $root, $entries);
        $privateFiles = ['auth.json', 'deployment.json', 'settings.json', 'rate.json', 'managed-loader.php'];
        foreach ($privateFiles as $name) {
            $path = $state->dir . '/' . $name;
            if (file_exists($path) || is_link($path)) {
                throw new RuntimeException('This private directory already contains firewall state.');
            }
        }
        if (is_file(self::panelPath($state, $root))) {
            throw new RuntimeException('A firewall panel entry already exists.');
        }

        self::ensureSessions($state);
        [$identity, $code] = Auth::initialIdentity([]);
        try {
            $state->write('settings', State::defaults(self::engine()));
            $state->write('deployment', $deployment);
            $state->write('auth', $identity);
            $state->write('rate', []);
            self::writeHooks($state, $deployment['root']);
        } catch (Throwable $error) {
            foreach ($privateFiles as $name) {
                $path = $state->dir . '/' . $name;
                if (is_file($path)) {
                    @unlink($path);
                }
            }
            throw $error;
        }
        $state->audit('Panel installed from File Manager', 'server-owner', '-');
        return $code;
    }

    private static function panelPath(State $state, string $root): string
    {
        $directory = $root . DIRECTORY_SEPARATOR . 'firewall-admin';
        if (is_link($directory) || (file_exists($directory) && realpath($directory) !== $directory)) {
            throw new RuntimeException('The panel directory must be a real directory under the site root.');
        }
        $path = $directory . DIRECTORY_SEPARATOR . 'index.php';
        if (is_link($path)) {
            throw new RuntimeException('The panel entry must be a real file.');
        }
        if (file_exists($path)) {
            $existing = is_file($path) ? (string) file_get_contents($path, false, null, 0, 8192) : '';
            if (!str_starts_with($existing, "<?php\n/* PHPWAF admin entry */")
                || !str_contains($existing, "'PHPWAF_PRIVATE_STATE', " . self::phpPath($state->dir))) {
                throw new RuntimeException('A different installation already owns /firewall-admin/index.php.');
            }
        }
        return $path;
    }

    private static function phpPath(string $path): string
    {
        return var_export(str_replace('\\', '/', $path), true);
    }
}
