<?php

declare(strict_types=1);

namespace Waf\Storage;

use Throwable;

/**
 * Picks a backend based on config and what's actually installed.
 * 'auto' order of preference: redis -> apcu -> file.
 * Any failure (e.g. Redis unreachable) degrades gracefully to the file driver.
 */
final class StorageFactory
{
    /**
     * @param array<string,mixed> $cfg the 'storage' config block
     */
    public static function create(array $cfg, int $gcProbability = 20): StorageInterface
    {
        $driver = $cfg['driver'] ?? 'auto';
        $prefix = $cfg['redis']['prefix'] ?? 'waf:';

        $tryRedis = static function () use ($cfg): ?StorageInterface {
            if (!extension_loaded('redis')) {
                return null;
            }
            try {
                return new RedisStorage($cfg['redis']);
            } catch (Throwable $e) {
                error_log('[WAF] Redis unavailable, falling back: ' . $e->getMessage());
                return null;
            }
        };

        $tryApcu = static function () use ($prefix): ?StorageInterface {
            if (!function_exists('apcu_enabled') || !apcu_enabled()) {
                return null;
            }
            return new ApcuStorage($prefix);
        };

        switch ($driver) {
            case 'redis':
                return $tryRedis() ?? new FileStorage($cfg['dir'], $gcProbability);
            case 'apcu':
                return $tryApcu() ?? new FileStorage($cfg['dir'], $gcProbability);
            case 'file':
                return new FileStorage($cfg['dir'], $gcProbability);
            case 'auto':
            default:
                return $tryRedis()
                    ?? $tryApcu()
                    ?? new FileStorage($cfg['dir'], $gcProbability);
        }
    }
}
