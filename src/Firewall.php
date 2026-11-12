<?php

declare(strict_types=1);

namespace Waf;

use LengthException;
use Throwable;
use UnexpectedValueException;
use Waf\Admin\Policy;
use Waf\Storage\StorageInterface;

final class Firewall
{
    /** @var array<string,mixed> */
    private array $config;
    private ?StorageInterface $storage;
    private Detector $detector;
    private Normalizer $normalizer;
    private Logger $logger;
    private ?DenyList $denyList;
    private ?Policy $policy;
    private array $evidence = [];

    /**
     * @param array<string,mixed> $config
     */
    public function __construct(
        array $config,
        ?StorageInterface $storage,
        Detector $detector,
        Normalizer $normalizer,
        Logger $logger,
        ?DenyList $denyList = null,
        ?Policy $policy = null
    ) {
        $this->config     = $config;
        $this->storage    = $storage;
        $this->detector   = $detector;
        $this->normalizer = $normalizer;
        $this->logger     = $logger;
        $this->denyList   = $denyList;
        $this->policy     = $policy;
    }

    public function run(): void
    {
        $ip = $this->clientIp();
        $mode = (string) $this->config['mode'];
        if ($ip !== null && $this->isWhitelisted($ip)) {
            return;
        }

        $storage = $mode === 'enforce' && $ip !== null ? $this->storage : null;
        if ($storage !== null) {
            try {
                if ($storage->isBlocked($ip)) {
                    $this->act($ip, $mode, 0, ['IP-BAN'], ['An existing IP ban is active'], 403);
                }
            } catch (Throwable $error) {
                error_log('[PHPWAF] IP storage read failed. Inspecting without IP state.');
                $storage = null;
            }
        }

        $limits = $this->config['limits'];
        $score = 0;
        $rules = [];
        $types = [];
        $shadowRules = [];
        try {
            $json = RequestInput::jsonBody($limits);
            if ($this->honeypotTriggered($json)) {
                $this->act($ip, $mode, 999, ['HONEYPOT'], ['Honeypot field touched'], 403, $storage);
                return;
            }

            $input = new RequestInput($limits);
            $sources = ['query' => $_GET, 'form' => $_POST, 'cookie' => $_COOKIE, 'json' => $json, 'path' => RequestInput::path(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '', 'referer' => $_SERVER['HTTP_REFERER'] ?? ''];
            foreach ($sources as $name => $source) {
                if ($source === [] || $source === null || $source === '') {
                    continue;
                }
                foreach ($input->values($source, 0, $this->policy === null ? null : '') as $field => $value) {
                    $result = $this->detector->inspect($this->normalizer->normalize($value), $this->policy === null ? null
                        : function (string $rule, string $match) use ($name, $field, $value): bool {
                            $evidence = $this->policy->match($rule, $name, $field, $value, $match);
                            if ($evidence === null) {
                                return false;
                            }
                            if (count($this->evidence) < 16) {
                                $this->evidence[] = $evidence;
                            }
                            return true;
                        }, in_array($name, ['query', 'form', 'json'], true) && !str_ends_with($field, '/@key'));
                    $score += $result['score'];
                    foreach ($result['rules'] as $index => $id) {
                        $rules[$id] = $result['types'][$index];
                    }
                    foreach ($result['shadow_rules'] as $id) {
                        $shadowRules[$id] = true;
                    }
                }
            }
        } catch (LengthException $error) {
            $this->act($ip, $mode, 0, ['INPUT-LIMIT'], ['Inspection budget exceeded'], 413);
            return;
        } catch (UnexpectedValueException $error) {
            $this->act($ip, $mode, 0, ['INPUT-INVALID'], ['Invalid request body'], 400);
            return;
        }

        if ($shadowRules !== []) {
            $evidence = array_values(array_filter($this->evidence, static fn ($item) => isset($shadowRules[$item['rule']])));
            $this->logger->logDecision($ip ?? '-', 'shadow', 0, array_keys($shadowRules), ['Observation-only match'],
                $mode, Response::reference(), $evidence);
        }
        if ($score >= (int) $this->config['scoring']['block_threshold']) {
            $this->act($ip, $mode, $score, array_keys($rules), array_values($rules), 403, $storage);
            return;
        }

        if ($storage !== null && $score > 0) {
            try {
                $total = $storage->incrementSuspicion($ip, $score, (int) $this->config['scoring']['time_window']);
                if ($total >= (int) $this->config['scoring']['suspicion_threshold']) {
                    $this->act($ip, $mode, $total, array_keys($rules), array_values($rules), 403, $storage);
                }
            } catch (Throwable $error) {
                error_log('[PHPWAF] IP storage write failed. Inspecting without IP state.');
            }
        }
    }

    private function act(?string $ip, string $mode, int $score, array $rules, array $types, int $status, ?StorageInterface $storage = null): void
    {
        $reference = Response::reference();
        $monitor = $mode === 'monitor';
        $decision = $monitor ? 'monitor' : ($status === 403 ? 'block' : 'reject');
        $evidence = array_values(array_filter($this->evidence, static fn ($item) => in_array($item['rule'], $rules, true)));
        $this->logger->logDecision($ip ?? '-', $decision, $score, $rules, $types, $mode, $reference, $evidence);
        if ($monitor) {
            return;
        }
        if ($storage !== null && $ip !== null) {
            try {
                $storage->block($ip, (int) $this->config['scoring']['block_duration'], "Rule decision (score $score)");
                $storage->resetSuspicion($ip);
                if ($this->denyList !== null) {
                    $this->denyList->add($ip);
                }
            } catch (Throwable $error) {
                error_log('[PHPWAF] IP ban persistence failed.');
            }
        }
        Response::reject($status, $reference);
    }

    private function honeypotTriggered(mixed $json): bool
    {
        foreach ((array) $this->config['honeypot_fields'] as $field) {
            foreach ([$_GET[$field] ?? null, $_POST[$field] ?? null, is_array($json) ? ($json[$field] ?? null) : null] as $value) {
                if (is_array($value) ? $value !== [] : trim((string) $value) !== '') {
                    return true;
                }
            }
        }
        return false;
    }

    private function clientIp(): ?string
    {
        $peer = $_SERVER['REMOTE_ADDR'] ?? '';
        if (filter_var($peer, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $proxy = $this->config['proxy'];
        $trusted = (array) $proxy['trusted_proxies'];
        if (empty($proxy['trust_forwarded_header']) || !$this->ipMatchesAny($peer, $trusted)) {
            return $peer;
        }

        $forwarded = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if (strlen($forwarded) > 2048) {
            return null;
        }
        $parts = explode(',', $forwarded);
        for ($index = count($parts) - 1; $index >= 0; --$index) {
            $candidate = trim($parts[$index]);
            if (filter_var($candidate, FILTER_VALIDATE_IP) === false) {
                return null;
            }
            if (!$this->ipMatchesAny($candidate, $trusted)) {
                return $candidate;
            }
        }
        return null;
    }

    private function isWhitelisted(string $ip): bool
    {
        return $this->ipMatchesAny($ip, (array) $this->config['whitelist']);
    }

    /**
     * @param array<int,string> $entries exact IPs or CIDR ranges (v4/v6)
     */
    private function ipMatchesAny(string $ip, array $entries): bool
    {
        foreach ($entries as $entry) {
            if ($entry === $ip) {
                return true;
            }
            if (strpos($entry, '/') !== false && $this->ipInCidr($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    /** CIDR match supporting both IPv4 and IPv6. */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bitsRaw] = array_pad(explode('/', $cidr, 2), 2, '');
        $ipBin     = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false; // mixed families or invalid
        }

        if ($bitsRaw === '' || !ctype_digit($bitsRaw)) {
            return false;
        }
        $bits = (int) $bitsRaw;
        $maxBits = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;

        if ($bytes > 0 && strncmp($ipBin, $subnetBin, $bytes) !== 0) {
            return false;
        }
        if ($rem === 0) {
            return true;
        }
        $mask = chr(0xFF << (8 - $rem) & 0xFF);
        return (($ipBin[$bytes] ^ $subnetBin[$bytes]) & $mask) === "\0";
    }
}
