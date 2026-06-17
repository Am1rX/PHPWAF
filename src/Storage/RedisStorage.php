<?php

declare(strict_types=1);

namespace Waf\Storage;

use Redis;
use RedisException;

/**
 * Preferred backend. INCRBY + EXPIRE is the textbook atomic rate limiter:
 * no locks, no manual garbage collection, shared across every web node.
 */
final class RedisStorage implements StorageInterface
{
    private Redis $redis;
    private string $prefix;

    /**
     * @param array{host:string,port:int,auth:?string,db:int,prefix:string,timeout:float} $cfg
     * @throws RedisException
     */
    public function __construct(array $cfg)
    {
        $this->redis = new Redis();
        $this->redis->connect($cfg['host'], $cfg['port'], $cfg['timeout']);
        if (!empty($cfg['auth'])) {
            $this->redis->auth($cfg['auth']);
        }
        if (!empty($cfg['db'])) {
            $this->redis->select($cfg['db']);
        }
        $this->prefix = $cfg['prefix'];
    }

    public function incrementSuspicion(string $ip, int $amount, int $windowSeconds): int
    {
        $key = $this->prefix . 'susp:' . $ip;
        $total = (int) $this->redis->incrBy($key, $amount);
        if ($total === $amount) {
            // First hit in this window: start the TTL.
            $this->redis->expire($key, $windowSeconds);
        }
        return $total;
    }

    public function resetSuspicion(string $ip): void
    {
        $this->redis->del($this->prefix . 'susp:' . $ip);
    }

    public function block(string $ip, int $ttl, string $reason): void
    {
        $payload = json_encode(['reason' => $reason, 'expires' => time() + $ttl]);
        $this->redis->setex($this->prefix . 'block:' . $ip, $ttl, (string) $payload);
    }

    public function isBlocked(string $ip): bool
    {
        return (bool) $this->redis->exists($this->prefix . 'block:' . $ip);
    }

    public function getBlock(string $ip): ?array
    {
        $raw = $this->redis->get($this->prefix . 'block:' . $ip);
        if (!is_string($raw) || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['reason'], $data['expires'])) {
            return null;
        }
        return ['reason' => (string) $data['reason'], 'expires' => (int) $data['expires']];
    }

    public function name(): string
    {
        return 'redis';
    }
}
