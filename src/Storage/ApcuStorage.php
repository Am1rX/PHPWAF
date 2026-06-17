<?php

declare(strict_types=1);

namespace Waf\Storage;

/**
 * In-memory single-server backend. Very fast, no external service.
 * Counters and blocks live in shared memory with native TTLs.
 */
final class ApcuStorage implements StorageInterface
{
    private string $prefix;

    public function __construct(string $prefix = 'waf:')
    {
        $this->prefix = $prefix;
    }

    public function incrementSuspicion(string $ip, int $amount, int $windowSeconds): int
    {
        $key = $this->prefix . 'susp:' . $ip;
        $success = false;
        // apcu_inc seeds the entry with its TTL when it does not yet exist.
        $total = apcu_inc($key, $amount, $success, $windowSeconds);
        return is_int($total) ? $total : $amount;
    }

    public function resetSuspicion(string $ip): void
    {
        apcu_delete($this->prefix . 'susp:' . $ip);
    }

    public function block(string $ip, int $ttl, string $reason): void
    {
        apcu_store(
            $this->prefix . 'block:' . $ip,
            ['reason' => $reason, 'expires' => time() + $ttl],
            $ttl
        );
    }

    public function isBlocked(string $ip): bool
    {
        return apcu_exists($this->prefix . 'block:' . $ip);
    }

    public function getBlock(string $ip): ?array
    {
        $data = apcu_fetch($this->prefix . 'block:' . $ip);
        if (!is_array($data) || !isset($data['reason'], $data['expires'])) {
            return null;
        }
        return ['reason' => (string) $data['reason'], 'expires' => (int) $data['expires']];
    }

    public function name(): string
    {
        return 'apcu';
    }
}
