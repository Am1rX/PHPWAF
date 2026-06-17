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

    public function __construct(string $jsonLog, string $textLog)
    {
        $this->jsonLog = $jsonLog;
        $this->textLog = $textLog;
    }

    /**
     * @param array<int,string> $rules
     * @param array<int,string> $types
     */
    public function logDecision(
        string $ip,
        string $decision,   // 'block' | 'monitor' | 'honeypot'
        int $score,
        array $rules,
        array $types,
        string $mode
    ): void {
        $now = time();

        $record = [
            'ts'        => date('c', $now),
            'ip'        => $ip,
            'decision'  => $decision,
            'mode'      => $mode,
            'score'     => $score,
            'rule_ids'  => $rules,
            'types'     => $types,
            'method'    => $_SERVER['REQUEST_METHOD'] ?? '-',
            'uri'       => $_SERVER['REQUEST_URI'] ?? '-',
            'host'      => $_SERVER['HTTP_HOST'] ?? '-',
            'ua'        => $_SERVER['HTTP_USER_AGENT'] ?? '-',
            'ref'       => $_SERVER['HTTP_REFERER'] ?? '-',
        ];

        $this->append($this->jsonLog, json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");

        // fail2ban regex target: matches "WAF BLOCK ... IP: <ip>"
        $text = sprintf(
            "%s | WAF %s | IP: %s | Score: %d | Rules: %s | URI: %s\n",
            date('Y-m-d H:i:s', $now),
            strtoupper($decision),
            $ip,
            $score,
            implode(',', $rules) ?: '-',
            $_SERVER['REQUEST_URI'] ?? '-'
        );
        $this->append($this->textLog, $text);
    }

    private function append(string $file, string $line): void
    {
        $fp = fopen($file, 'a');
        if ($fp === false) {
            return;
        }
        if (flock($fp, LOCK_EX)) {
            fwrite($fp, $line);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }
}
