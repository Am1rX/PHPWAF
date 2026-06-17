<?php

declare(strict_types=1);

namespace Waf;

/**
 * Turns obfuscated input into a single canonical form so the detector
 * sees what the browser/DB would ultimately see. Closes common bypasses:
 * multi-layer URL encoding, HTML entities, null bytes, mixed case.
 */
final class Normalizer
{
    private const MAX_URL_DECODE_PASSES = 3;

    public function normalize(string $input): string
    {
        $decoded = $input;

        // Peel up to N layers of URL encoding (e.g. %2527 -> %27 -> ').
        for ($i = 0; $i < self::MAX_URL_DECODE_PASSES; $i++) {
            $next = rawurldecode($decoded);
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
        }

        // Decode HTML entities (named, decimal, hex).
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Strip null bytes used to truncate/confuse downstream parsers.
        $decoded = str_replace("\0", '', $decoded);

        // Collapse whitespace runs so "union/**/select" style padding is less effective
        // once comments are removed below.
        $decoded = preg_replace('/\/\*.*?\*\//s', ' ', $decoded) ?? $decoded;

        return mb_strtolower($decoded, 'UTF-8');
    }
}
