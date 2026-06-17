<?php

declare(strict_types=1);

/**
 * Central configuration for the WAF.
 * Everything tunable lives here so the code never has to be edited for ops changes.
 */

return [

    // How the WAF reacts when it detects an attack:
    //   'monitor' = log only, never block. Use this first to tune rules safely.
    //   'filter'  = block each malicious request (403) but never ban the IP. The same
    //               client can immediately send a clean request and be served normally.
    //               Stateless: needs no storage and keeps no block list.
    //   'enforce' = block the request AND ban the IP for block_duration, with behavioral
    //               accumulation and optional edge denylist.
    'mode' => 'enforce',

    'scoring' => [
        // A single request scoring at/above this is blocked immediately.
        'block_threshold' => 15,
        // Accumulated score (across the time window) at/above this triggers a behavioral block.
        'suspicion_threshold' => 20,
        // Sliding window for accumulating suspicion, in seconds.
        'time_window' => 60,
        // How long a block lasts, in seconds.
        'block_duration' => 300,
    ],

    'storage' => [
        // 'auto' picks the best available: redis -> apcu -> file.
        'driver' => 'auto',
        'redis' => [
            'host'    => '127.0.0.1',
            'port'    => 6379,
            'auth'    => null,        // string password, or null
            'db'      => 0,
            'prefix'  => 'waf:',
            'timeout' => 0.5,
        ],
        // Used by the file driver only.
        'dir' => __DIR__ . '/waf_storage',
    ],

    'proxy' => [
        // Only enable if a TRUSTED reverse proxy/CDN overwrites X-Forwarded-For.
        // If clients can reach PHP directly, leave this false (the header is spoofable).
        'trust_forwarded_header' => false,
        'trusted_proxies'        => [],   // e.g. ['10.0.0.1', '172.16.0.0/12']
    ],

    // Exact IPs or CIDR ranges that bypass inspection entirely (IPv4 and IPv6).
    'whitelist' => [],

    // Honeypot fields: hidden form inputs no real user ever fills.
    // If any of these arrive non-empty, the client is blocked instantly (zero false positives).
    // Render them hidden in your forms (see README).
    'honeypot_fields' => [],

    // Self-protection against oversized / deeply nested payloads.
    'limits' => [
        'max_depth'        => 15,
        'max_keys'         => 1000,
        'max_value_length' => 8192,
    ],

    'logging' => [
        // Structured JSON Lines log (one JSON object per line) for SIEM/ELK ingestion.
        'json_log' => __DIR__ . '/waf_storage/events.jsonl',
        // Human/fail2ban-friendly plaintext log.
        'text_log' => __DIR__ . '/waf_storage/attacks.log',
    ],

    'edge' => [
        // When true, every blocked IP is appended to a denylist file that nginx can read
        // (via the `geo` directive) so blocked traffic dies at the edge, before PHP-FPM.
        // See README for the nginx + fail2ban snippets.
        'enabled'       => false,
        'denylist_file' => __DIR__ . '/waf_storage/denylist.conf',
    ],

    // Rule IDs to switch off (e.g. ['SQLI-002'] if it proves noisy on your traffic).
    'disabled_rules' => [],

    // Probability (1 in N) of running garbage collection on the file driver per request.
    'gc_probability' => 20,
];
