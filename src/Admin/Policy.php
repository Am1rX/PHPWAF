<?php

declare(strict_types=1);

namespace Waf\Admin;

use InvalidArgumentException;

final class Policy
{
    private string $key;
    private ?string $epoch = null;
    private string $method;
    private string $path;
    private array $allowed = [];

    public function __construct(array $settings, string $method, string $path)
    {
        $this->key = $settings['key'];
        $this->method = $method;
        $this->path = $path;
        $now = time();
        foreach ($settings['exceptions'] as $item) {
            if (($item['expires'] ?? 0) > $now && $item['method'] === $method && $item['path'] === $path) {
                $this->allowed[$item['fingerprint']] = true;
            }
        }
    }

    /** A null result means an existing exception matched the exact field value. */
    public function match(string $rule, string $source, string $field, string $value, string $match): ?array
    {
        $safe = in_array($source, ['query', 'form', 'json'], true) && strlen($field) <= 200
            && strlen($this->path) <= 512 && strlen($this->method) <= 16
            && !preg_match('/pass|secret|token|credential|auth|cookie|nonce|session|key|signature|card|cvv|otp|pin|email|phone/i', $field);
        if (!$safe) {
            return ['rule' => $rule, 'source' => $source, 'field' => '[redacted]', 'sample' => null];
        }
        $fingerprint = hash_hmac('sha256', serialize([$rule, $this->method, $this->path, $source, $field, $value]), $this->key);
        if (isset($this->allowed[$fingerprint])) {
            return null;
        }
        $sample = preg_replace('/[\x00-\x1F\x7F]/', ' ', substr($match, 0, 96));
        return [
            'rule' => $rule, 'source' => $source, 'field' => $field, 'sample' => $sample,
            'fingerprint' => $fingerprint, 'epoch' => $this->epoch ??= hash_hmac('sha256', 'exception-epoch', $this->key),
        ];
    }

    public static function add(array $settings, array $event, int $index, int $days): array
    {
        $evidence = $event['evidence'][$index] ?? [];
        $now = time();
        if (($event['decision'] ?? '') !== 'block' || $days < 1 || $days > 30
            || !preg_match('/\A[0-9a-f]{64}\z/', $evidence['fingerprint'] ?? '')
            || !hash_equals(hash_hmac('sha256', 'exception-epoch', $settings['key']), $evidence['epoch'] ?? '')
            || empty($event['uri']) || empty($event['method']) || empty($evidence['rule'])) {
            throw new InvalidArgumentException('This event does not have eligible evidence. Exceptions expire after 1–30 days.');
        }
        $exceptions = array_values(array_filter($settings['exceptions'], static fn ($item) =>
            $item['expires'] > $now && $item['fingerprint'] !== $evidence['fingerprint']));
        if (count($exceptions) >= 100) {
            throw new InvalidArgumentException('Remove an existing exception before adding another.');
        }
        $exceptions[] = [
            'id' => bin2hex(random_bytes(8)), 'reference' => $event['reference'], 'rule' => $evidence['rule'],
            'method' => $event['method'], 'path' => $event['uri'], 'source' => $evidence['source'], 'field' => $evidence['field'],
            'fingerprint' => $evidence['fingerprint'], 'expires' => $now + $days * 86400,
        ];
        $settings['exceptions'] = $exceptions;
        return $settings;
    }
}
