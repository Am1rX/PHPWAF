<?php

declare(strict_types=1);

namespace Waf\Storage;

interface StorageInterface
{
    /**
     * Atomically add $amount to the IP's suspicion counter within a sliding window.
     * Returns the new accumulated total.
     */
    public function incrementSuspicion(string $ip, int $amount, int $windowSeconds): int;

    /** Clear an IP's accumulated suspicion (called once it has been blocked). */
    public function resetSuspicion(string $ip): void;

    /** Record a block for $ttl seconds with a human-readable reason. */
    public function block(string $ip, int $ttl, string $reason): void;

    /** True if the IP is currently blocked. */
    public function isBlocked(string $ip): bool;

    /**
     * Block metadata or null if not blocked.
     * @return array{reason:string, expires:int}|null
     */
    public function getBlock(string $ip): ?array;

    /** Short label identifying the active backend (for logs/diagnostics). */
    public function name(): string;
}
