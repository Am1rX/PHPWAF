<?php

declare(strict_types=1);

namespace Waf\Admin;

use InvalidArgumentException;
use RuntimeException;

final class Auth
{
    public static function identity(string $username, string $password, array $trusted): array
    {
        if (($username !== 'admin' && !preg_match('/\A[a-zA-Z][a-zA-Z0-9_.-]{5,39}\z/', $username))
            || in_array(strtolower($username), ['administrator', 'webadmin', 'phpwaf', 'firewall', 'default', 'superadmin', 'admin123'], true)) {
            throw new InvalidArgumentException('Use admin or choose a username of 6–40 characters.');
        }
        $folded = strtolower($password);
        $groups = (int) (preg_match('/[a-z]/', $password) === 1) + (int) (preg_match('/[A-Z]/', $password) === 1)
            + (int) (preg_match('/[0-9]/', $password) === 1) + (int) (preg_match('/[^A-Za-z0-9]/', $password) === 1);
        if (strlen($password) < 16 || strlen($password) > 72 || strpos($password, "\0") !== false
            || ($groups < 3 && preg_match_all('/[\p{L}\p{N}]+/u', $password) < 4) || strpos($folded, strtolower($username)) !== false
            || preg_match('/password|changeme|123456|qwerty|letmein/i', $password)) {
            throw new InvalidArgumentException('Use 16–72 bytes, with three character groups or four words. Avoid defaults and your username.');
        }
        return [
            'username' => $username, 'hash' => self::passwordHash($password),
            'generation' => bin2hex(random_bytes(16)), 'trusted' => $trusted,
        ];
    }

    public static function initialIdentity(array $trusted): array
    {
        $code = bin2hex(random_bytes(24));
        return [[
            'username' => 'admin', 'hash' => self::passwordHash('admin'),
            'generation' => bin2hex(random_bytes(16)), 'trusted' => $trusted,
            'must_rotate' => true, 'setup_hash' => hash('sha256', $code),
        ], $code];
    }

    public static function setupCodeAccepted(array $auth, bool $localDevelopment, string $code): bool
    {
        return empty($auth['must_rotate']) || $localDevelopment
            || (isset($auth['setup_hash']) && hash_equals($auth['setup_hash'], hash('sha256', $code)));
    }

    private static function passwordHash(string $password): string
    {
        $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        return password_hash($password, $algorithm);
    }

    public static function addresses(array $raw): array
    {
        $entries = [];
        foreach ($raw as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            [$address, $bits] = self::network($entry);
            $entries[] = inet_ntop($address) . ($bits === strlen($address) * 8 ? '' : '/' . $bits);
        }
        $entries = array_values(array_unique($entries));
        if (count($entries) > 32) {
            throw new InvalidArgumentException('Enter at most 32 trusted IP addresses or CIDR ranges.');
        }
        return $entries;
    }

    public static function allows(string $address, array $entries): bool
    {
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        return $entries === [] || self::contained($address, $entries);
    }

    public static function contained(string $candidate, array $entries): bool
    {
        [$address, $size] = self::network($candidate);
        foreach ($entries as $entry) {
            [$network, $prefix] = self::network($entry);
            if (strlen($address) !== strlen($network) || $prefix > $size) {
                continue;
            }
            $bytes = intdiv($prefix, 8);
            $bits = $prefix % 8;
            if (substr($address, 0, $bytes) === substr($network, 0, $bytes)
                && ($bits === 0 || (((ord($address[$bytes]) ^ ord($network[$bytes])) & (255 << (8 - $bits))) === 0))) {
                return true;
            }
        }
        return false;
    }

    private static function network(string $entry): array
    {
        $parts = explode('/', $entry, 2);
        if (filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException('Trusted hosts must be valid IP addresses or CIDR ranges.');
        }
        $address = inet_pton($parts[0]);
        $max = strlen($address) * 8;
        if (isset($parts[1]) && (!ctype_digit($parts[1]) || (int) $parts[1] < 1 || (int) $parts[1] > $max)) {
            throw new InvalidArgumentException('A trusted network must have a valid, nonzero CIDR prefix.');
        }
        return [$address, isset($parts[1]) ? (int) $parts[1] : $max];
    }

    public static function session(State $state, bool $secure, string $path): void
    {
        if (session_status() !== PHP_SESSION_NONE) {
            throw new RuntimeException('The panel needs its own session.');
        }
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.gc_maxlifetime', '28800');
        session_save_path($state->dir . '/sessions');
        session_name('PHPWAFADMIN');
        session_set_cookie_params(['lifetime' => 0, 'path' => $path, 'secure' => $secure, 'httponly' => true, 'samesite' => 'Strict']);
        if (!session_start()) {
            throw new RuntimeException('The private session directory is unavailable.');
        }
        $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    }

    public static function authenticate(State $state, array $auth, string $ip, string $password, ?string $username): bool
    {
        $now = time();
        $rate = $state->read('rate');
        $rate = array_filter($rate, static fn ($row) => is_array($row) && ($row['until'] ?? 0) > $now);
        $key = hash('sha256', $ip);
        $client = $rate[$key] ?? ['count' => 0, 'until' => $now + 300];
        $global = $rate['global'] ?? ['count' => 0, 'until' => $now + 300];
        if ($client['count'] >= 6 || $global['count'] >= 40) {
            return false;
        }
        $valid = strlen($password) <= 72 && password_verify($password, $auth['hash']);
        if ($valid && ($username === null || hash_equals($auth['username'], $username))) {
            unset($rate[$key]);
            $state->write('rate', $rate);
            return true;
        }
        ++$client['count'];
        ++$global['count'];
        $rate[$key] = $client;
        $rate['global'] = $global;
        $state->write('rate', $rate);
        return false;
    }
}
