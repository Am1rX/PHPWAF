<?php

declare(strict_types=1);

namespace Waf;

/**
 * Writes two logs:
 *  - JSON Lines (one object per line) for SIEM/ELK/Grafana ingestion.
 *  - Plaintext, fail2ban-friendly, so the edge firewall can ban offenders.
 */
final class Logger
{
    private string $jsonLog;
    private string $textLog;
    private int $maxBytes;

    public function __construct(string $jsonLog, string $textLog, int $maxBytes = 0)
    {
        $this->jsonLog = $jsonLog;
        $this->textLog = $textLog;
        $this->maxBytes = $maxBytes;
    }

    /**
     * @param array<int,string> $rules
     * @param array<int,string> $types
     */
    public function logDecision(
        string $ip,
        string $decision,
        int $score,
        array $rules,
        array $types,
        string $mode,
        ?string $reference = null,
        array $evidence = []
    ): void {
        $now = time();

        $record = [
            'ts'        => gmdate('c', $now),
            'ip'        => $ip,
            'decision'  => $decision,
            'mode'      => $mode,
            'score'     => $score,
            'rule_ids'  => $rules,
            'types'     => $types,
            'method'    => substr($_SERVER['REQUEST_METHOD'] ?? '-', 0, 16),
            'uri'       => substr(RequestInput::path(), 0, 512),
            'reference' => $reference,
            'evidence'  => $evidence,
        ];

        $this->append($this->jsonLog, json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
        if ($decision === 'shadow') {
            return;
        }

        // fail2ban regex target: matches "WAF BLOCK ... IP: <ip>"
        $text = sprintf(
            "%s | WAF %s | IP: %s | Score: %d | Rules: %s | Reference: %s\n",
            date('Y-m-d H:i:s', $now),
            strtoupper($decision),
            $ip,
            $score,
            implode(',', $rules) ?: '-',
            $reference ?? '-'
        );
        $this->append($this->textLog, $text);
    }

    private function append(string $file, string $line): void
    {
        if ($this->maxBytes > 0) {
            $lock = @fopen($file . '.lock', 'c+b');
            if ($lock !== false) {
                try {
                    if (flock($lock, LOCK_EX)) {
                        clearstatcache(true, $file);
                        if (is_file($file) && filesize($file) >= $this->maxBytes) {
                            @rename($file, $file . '.previous');
                        }
                        $this->writeLine($file, $line);
                    }
                    return;
                } finally {
                    fclose($lock);
                }
            }
        }
        $this->writeLine($file, $line);
    }

    private function writeLine(string $file, string $line): void
    {
        if (@file_put_contents($file, $line, FILE_APPEND | LOCK_EX) === false) {
            error_log('[PHPWAF] Could not write a firewall event.');
        }
    }
}
