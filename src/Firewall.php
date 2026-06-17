<?php

declare(strict_types=1);

namespace Waf;

use Waf\Storage\StorageInterface;

final class Firewall
{
    /** @var array<string,mixed> */
    private array $config;
    private StorageInterface $storage;
    private Detector $detector;
    private Normalizer $normalizer;
    private Logger $logger;
    private ?DenyList $denyList;

    /**
     * @param array<string,mixed> $config
     */
    public function __construct(
        array $config,
        StorageInterface $storage,
        Detector $detector,
        Normalizer $normalizer,
        Logger $logger,
        ?DenyList $denyList = null
    ) {
        $this->config     = $config;
        $this->storage    = $storage;
        $this->detector   = $detector;
        $this->normalizer = $normalizer;
        $this->logger     = $logger;
        $this->denyList   = $denyList;
    }

    public function run(): void
    {
        $ip   = $this->clientIp();
        $mode = (string) $this->config['mode'];

        if ($this->isWhitelisted($ip)) {
            return;
        }

        // Mode capabilities:
        //   monitor -> log only.
        //   filter  -> reject the bad request (403) but never ban the IP. Stateless:
        //              no block list, no behavioral accumulation, no storage needed.
        //   enforce -> reject the request AND ban the IP, with behavioral accumulation.
        $banning  = ($mode === 'enforce');                      // persist IP bans + accumulate
        $blocking = ($mode === 'enforce' || $mode === 'filter'); // reject this request

        // Only enforce keeps a persistent block list, so only enforce checks it.
        if ($banning && $this->storage->isBlocked($ip)) {
            $this->reject();
        }

        $inputs = $this->gatherInputs();

        // Honeypot: hidden fields no real user fills. High confidence, zero false positives.
        if ($this->honeypotTriggered($inputs)) {
            $this->logger->logDecision($ip, $blocking ? 'block' : 'monitor', 999, ['HONEYPOT'], ['Honeypot field touched'], $mode);
            if ($banning) {
                $this->enforceBlock($ip, 'Honeypot field touched');
            }
            if ($blocking) {
                $this->reject();
            }
            return;
        }

        $score = 0;
        $rules = [];
        $types = [];

        foreach ($this->flatten($inputs) as $value) {
            $result = $this->detector->inspect($this->normalizer->normalize($value));
            if ($result['score'] > 0) {
                $score += $result['score'];
                array_push($rules, ...$result['rules']);
                array_push($types, ...$result['types']);
            }
        }

        $threshold = (int) $this->config['scoring']['block_threshold'];

        // A single request at/above the threshold is rejected on its own (in filter/enforce).
        if ($score >= $threshold) {
            $this->logger->logDecision($ip, $blocking ? 'block' : 'monitor', $score, $rules, $types, $mode);
            if ($banning) {
                $this->enforceBlock($ip, "Immediate block (score $score)");
            }
            if ($blocking) {
                $this->reject();
            }
            return;
        }

        // Behavioral accumulation exists only to drive an IP ban, so it is enforce-only.
        // In filter/monitor there is no per-IP state to keep.
        if ($banning && $score > 0) {
            $total = $this->storage->incrementSuspicion(
                $ip,
                $score,
                (int) $this->config['scoring']['time_window']
            );

            if ($total >= (int) $this->config['scoring']['suspicion_threshold']) {
                $this->storage->resetSuspicion($ip);
                $this->logger->logDecision($ip, 'block', $total, $rules, $types, $mode);
                $this->enforceBlock($ip, "Behavioral block (accumulated $total)");
                $this->reject();
            }
        }
    }

    private function enforceBlock(string $ip, string $reason): void
    {
        $this->storage->block($ip, (int) $this->config['scoring']['block_duration'], $reason);
        if ($this->denyList !== null) {
            $this->denyList->add($ip);
        }
    }

    private function reject(): void
    {
        http_response_code(403);
        $ref = strtoupper(substr(bin2hex(random_bytes(4)), 0, 8));
        // Generic page; does not advertise that a WAF is in place.
        $page = __DIR__ . '/../public/block.php';
        if (is_file($page)) {
            $GLOBALS['waf_ref'] = $ref;
            require $page;
        } else {
            echo 'Access denied. Reference: ' . $ref;
        }
        exit;
    }

    // ---- input collection ------------------------------------------------

    /**
     * @return array<string,mixed>
     */
    private function gatherInputs(): array
    {
        $data = $_REQUEST;

        $raw = file_get_contents('php://input');
        if ($raw !== false && $raw !== '') {
            $json = json_decode($raw, true);
            if (is_array($json)) {
                $data = array_merge($data, $json);
            }
        }

        // A few high-signal headers (kept narrow to limit false positives).
        foreach (['HTTP_USER_AGENT' => 'User-Agent', 'HTTP_REFERER' => 'Referer'] as $srv => $label) {
            if (!empty($_SERVER[$srv])) {
                $data[$label] = $_SERVER[$srv];
            }
        }

        return $data;
    }

    /**
     * @param array<string,mixed> $inputs
     */
    private function honeypotTriggered(array $inputs): bool
    {
        foreach ((array) $this->config['honeypot_fields'] as $field) {
            if (isset($inputs[$field]) && trim((string) $inputs[$field]) !== '') {
                return true;
            }
        }
        return false;
    }

    /**
     * Flatten nested input into "a.b.c" => value pairs, with self-protection caps.
     *
     * @param array<mixed> $array
     * @return array<string,string>
     */
    private function flatten(array $array, string $prefix = '', int $depth = 0): array
    {
        $limits = $this->config['limits'];
        if ($depth > (int) $limits['max_depth']) {
            return [];
        }
        $result = [];
        foreach ($array as $key => $value) {
            if (count($result) >= (int) $limits['max_keys']) {
                break;
            }
            $newKey = $prefix === '' ? (string) $key : $prefix . '.' . $key;
            if (is_array($value)) {
                $result += $this->flatten($value, $newKey, $depth + 1);
            } else {
                $result[$newKey] = substr((string) $value, 0, (int) $limits['max_value_length']);
            }
        }
        return $result;
    }

    // ---- client IP / whitelist ------------------------------------------

    private function clientIp(): string
    {
        $proxy = $this->config['proxy'];
        if (
            !empty($proxy['trust_forwarded_header'])
            && isset($_SERVER['REMOTE_ADDR'])
            && $this->ipMatchesAny($_SERVER['REMOTE_ADDR'], (array) $proxy['trusted_proxies'])
            && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])
        ) {
            $parts     = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']);
            $candidate = trim($parts[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
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
