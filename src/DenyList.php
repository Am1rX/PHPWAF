<?php

declare(strict_types=1);

namespace Waf;

/**
 * Maintains an nginx-readable denylist so blocked IPs are dropped at the edge,
 * before they ever reach PHP-FPM. Without this, a blocked attacker still costs
 * you a PHP worker on every request (a self-inflicted DoS amplifier).
 *
 * The file is consumed by nginx via the `geo` directive (see README).
 * Each line: `<ip> 1;`
 */
final class DenyList
{
    private string $file;

    public function __construct(string $file)
    {
        $this->file = $file;
    }

    public function add(string $ip): void
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return;
        }

        $fp = fopen($this->file, 'c+');
        if ($fp === false) {
            return;
        }
        if (flock($fp, LOCK_EX)) {
            $size     = (int) (fstat($fp)['size'] ?? 0);
            $existing = $size > 0 ? (string) fread($fp, $size) : '';
            if (strpos($existing, $ip . ' 1;') === false) {
                fseek($fp, 0, SEEK_END);
                fwrite($fp, $ip . " 1;\n");
                fflush($fp);
            }
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }
}
