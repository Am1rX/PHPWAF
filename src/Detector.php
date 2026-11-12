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
    private const REQUIRED_CHARACTERS = [
        'XSS-001' => '<',
        'XSS-002' => '<',
        'XSS-003' => '=',
        'XSS-004' => ':',
        'XSS-005' => '(`',
        'SQLI-002' => "'\"",
        'SQLI-003' => "'\"",
        'SQLI-004' => ';',
        'PROBE-001' => "'\"/.-",
        'LFI-001' => '/\\%',
        'LFI-002' => ':',
        'RCE-002' => '$`|',
        'GEN-001' => ';',
        'GEN-002' => '`',
    ];

    /** @var array<int, array{id:string,pattern:string,score:int,type:string,observe_only?:bool}> */
    private array $rules;

    /** @var array<string, bool> rule IDs evaluated in shadow mode */
    private array $shadow;

    /**
     * @param array<int, string> $disabledRuleIds
     * @param array<int, string> $shadowRuleIds
     */
    public function __construct(array $disabledRuleIds = [], array $shadowRuleIds = [], array $overrides = [])
    {
        [$disabled, $this->shadow] = self::states($disabledRuleIds, $shadowRuleIds, $overrides);
        $this->rules = $disabled === []
            ? self::defaultRules()
            : array_filter(self::defaultRules(), static fn (array $rule): bool => !isset($disabled[$rule['id']]));
    }

    public static function catalog(array $disabledRuleIds = [], array $shadowRuleIds = [], array $overrides = []): array
    {
        [$disabled, $shadow] = self::states($disabledRuleIds, $shadowRuleIds, $overrides);
        $catalog = [];
        foreach (self::defaultRules() as $rule) {
            $id = $rule['id'];
            $observe = !empty($rule['observe_only']);
            $status = isset($disabled[$id]) ? 'off' : ($observe ? 'observe' : (isset($shadow[$id]) ? 'shadow' : 'on'));
            $catalog[$id] = ['id' => $id, 'label' => $rule['type'], 'score' => $rule['score'], 'status' => $status];
        }
        return $catalog;
    }

    private static function states(array $disabledRuleIds, array $shadowRuleIds, array $overrides): array
    {
        $disabled = array_fill_keys($disabledRuleIds, true);
        $shadow = array_fill_keys($shadowRuleIds, true);
        foreach ($overrides as $id => $enabled) {
            if ($enabled === true) {
                unset($disabled[$id], $shadow[$id]);
            } elseif ($enabled === false) {
                $disabled[$id] = true;
            }
        }
        return [$disabled, $shadow];
    }

    /**
     * @return array{score:int, rules:array<int,string>, types:array<int,string>, shadow_rules:array<int,string>}
     */
    public function inspect(string $normalized, ?callable $matched = null, bool $inspectProbes = false): array
    {
        $score = 0;
        $ruleIds = [];
        $types = [];
        $shadowRules = [];

        foreach ($this->rules as $rule) {
            $observeOnly = !empty($rule['observe_only']);
            if ($observeOnly && !$inspectProbes) {
                continue;
            }
            $required = self::REQUIRED_CHARACTERS[$rule['id']] ?? null;
            if ($required !== null && strpbrk($normalized, $required) === false) {
                continue;
            }
            $hit = $matched === null
                ? preg_match($rule['pattern'], $normalized)
                : preg_match($rule['pattern'], $normalized, $matches);
            if ($hit === 1) {
                if ($matched !== null && !$matched($rule['id'], $matches[0])) {
                    continue;
                }
                if ($observeOnly || isset($this->shadow[$rule['id']])) {
                    $shadowRules[] = $rule['id'];
                    continue;
                }
                $score += $rule['score'];
                $ruleIds[] = $rule['id'];
                $types[]   = $rule['type'];
            }
        }

        return ['score' => $score, 'rules' => $ruleIds, 'types' => $types, 'shadow_rules' => $shadowRules];
    }

    /**
     * @return array<int, array{id:string,pattern:string,score:int,type:string,observe_only?:bool}>
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
                // Native details/summary markup is also used by the WordPress editor.
                'pattern' => '/<\s*(svg|math|object|iframe|embed|audio|video|keygen|marquee|base|form|input|link|style)[\s\/>]/i',
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
            [
                'id' => 'PROBE-001', 'score' => 0, 'type' => 'Punctuation-only input',
                'observe_only' => true,
                'pattern' => '~\A\s*(?:["\']|/|\.\.|--\+?)\s*\z~D',
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
                // A tool name followed by version punctuation is ordinary client metadata.
                'pattern' => '/(^|[;&|`]|\$\()\s*(cat|nc|ncat|wget|curl|bash|sh|python|perl|powershell|chmod|chown|whoami|id|uname)(?=\s|$|[;&|<>()\x60])/i',
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
