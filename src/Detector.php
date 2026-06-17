<?php

declare(strict_types=1);

namespace Waf;

/**
 * Signature layer. Each rule has a stable ID so it can be referenced in logs,
 * disabled individually, and tracked for false-positive tuning.
 *
 * Patterns are written to avoid catastrophic backtracking (no nested quantifiers
 * over unbounded `.*`); openers are matched rather than full element bodies.
 */
final class Detector
{
    /** @var array<int, array{id:string,pattern:string,score:int,type:string}> */
    private array $rules;

    /** @var array<string, bool> rule IDs disabled by config */
    private array $disabled;

    /**
     * @param array<int, string> $disabledRuleIds
     */
    public function __construct(array $disabledRuleIds = [])
    {
        $this->disabled = array_fill_keys($disabledRuleIds, true);
        $this->rules = self::defaultRules();
    }

    /**
     * @return array{score:int, rules:array<int,string>, types:array<int,string>}
     */
    public function inspect(string $normalized): array
    {
        $score = 0;
        $ruleIds = [];
        $types = [];

        foreach ($this->rules as $rule) {
            if (isset($this->disabled[$rule['id']])) {
                continue;
            }
            if (preg_match($rule['pattern'], $normalized) === 1) {
                $score += $rule['score'];
                $ruleIds[] = $rule['id'];
                $types[]   = $rule['type'];
            }
        }

        return ['score' => $score, 'rules' => $ruleIds, 'types' => $types];
    }

    /**
     * @return array<int, array{id:string,pattern:string,score:int,type:string}>
     */
    private static function defaultRules(): array
    {
        return [
            // ---- XSS -------------------------------------------------------
            [
                'id' => 'XSS-001', 'score' => 25, 'type' => 'Script tag',
                // Match the opener only -> no backtracking over the body.
                'pattern' => '/<\s*script[\s\/>]/i',
            ],
            [
                'id' => 'XSS-002', 'score' => 20, 'type' => 'Dangerous HTML element',
                'pattern' => '/<\s*(details|summary|svg|math|object|iframe|embed|audio|video|keygen|marquee|base|form|input|link|style)[\s\/>]/i',
            ],
            [
                'id' => 'XSS-003', 'score' => 15, 'type' => 'Event handler',
                // Curated handler list keeps false positives low vs. a blanket /on\w+=/.
                'pattern' => '/\bon(error|load|click|mouseover|mouseenter|mouseleave|focus|blur|submit|change|input|key(down|up|press)|abort|toggle|animationstart|animationend|transitionend|pointerover|wheel|scroll)\s*=/i',
            ],
            [
                'id' => 'XSS-004', 'score' => 20, 'type' => 'Dangerous protocol',
                'pattern' => '/(javascript|vbscript)\s*:|data\s*:\s*[^,]*?(text\/html|application\/xml|image\/svg)/i',
            ],
            [
                'id' => 'XSS-005', 'score' => 15, 'type' => 'JS sink/function',
                'pattern' => '/\b(alert|prompt|confirm|eval|settimeout|setinterval|fetch|document\.cookie|document\.write|window\.location)\s*(\(|`)/i',
            ],

            // ---- SQL injection --------------------------------------------
            [
                'id' => 'SQLI-001', 'score' => 20, 'type' => 'Critical SQLi',
                'pattern' => '/\b(union[\s\(]+select|information_schema|load_file\s*\(|into\s+(out|dump)file|sleep\s*\(|benchmark\s*\()/i',
            ],
            [
                'id' => 'SQLI-002', 'score' => 18, 'type' => 'SQLi tautology',
                // Quote, boolean operator, then a comparison with a quoted/number operand.
                'pattern' => '/[\'"]\s*(or|and)\s+[\'"\d][^=<>]{0,40}?(=|<|>|like\b)/i',
            ],
            [
                'id' => 'SQLI-003', 'score' => 10, 'type' => 'SQL comment after quote',
                'pattern' => '/[\'"]\s*(--|#)/',
            ],
            [
                'id' => 'SQLI-004', 'score' => 18, 'type' => 'Stacked query',
                'pattern' => '/;\s*(select\s|insert\s+into|update\s|delete\s+from|drop\s+(table|database)|alter\s+table|truncate\s+table|create\s+(table|database))/i',
            ],

            // ---- Traversal / LFI ------------------------------------------
            [
                'id' => 'LFI-001', 'score' => 15, 'type' => 'Path traversal',
                'pattern' => '/(\.\.\/|\.\.\\\\|%2e%2e(%2f|%5c)|\/etc\/passwd|\/proc\/self\/)/i',
            ],
            [
                'id' => 'LFI-002', 'score' => 18, 'type' => 'PHP wrapper',
                'pattern' => '/php:\/\/(filter|input|data)|expect:\/\/|phar:\/\//i',
            ],

            // ---- Command injection ----------------------------------------
            [
                'id' => 'RCE-001', 'score' => 25, 'type' => 'Command injection',
                'pattern' => '/(^|[;&|`]|\$\()\s*(cat|nc|ncat|wget|curl|bash|sh|python|perl|powershell|chmod|chown|whoami|id|uname)\b/i',
            ],
            [
                'id' => 'RCE-002', 'score' => 18, 'type' => 'Shell metacharacters',
                'pattern' => '/\$\(.+?\)|`[^`]+`|\|\s*(sh|bash)\b/i',
            ],

            // ---- Generic obfuscation / context break ----------------------
            [
                'id' => 'GEN-001', 'score' => 10, 'type' => 'Context break',
                'pattern' => '/[\'"]\s*;\s*\S/',
            ],
            [
                'id' => 'GEN-002', 'score' => 20, 'type' => 'JS backtick exec',
                'pattern' => '/(alert|prompt|confirm|print|eval)\s*`/i',
            ],
        ];
    }
}
