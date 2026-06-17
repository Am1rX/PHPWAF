<?php

declare(strict_types=1);

namespace Waf\Storage;

/**
 * Zero-dependency fallback. Uses atomic read-modify-write under an exclusive
 * lock. Slower than Redis/APCu under load, but works anywhere.
 */
final class FileStorage implements StorageInterface
{
    private string $blockFile;
    private string $suspicionFile;
    private int $gcProbability;

    public function __construct(string $dir, int $gcProbability = 20)
    {
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $this->hardenDir($dir);
        $this->blockFile     = $dir . '/blocked_ips.json';
        $this->suspicionFile = $dir . '/suspicion_log.json';
        $this->gcProbability = max(1, $gcProbability);

        if (random_int(1, $this->gcProbability) === 1) {
            $this->garbageCollect();
        }
    }

    public function incrementSuspicion(string $ip, int $amount, int $windowSeconds): int
    {
        $total = 0;
        $this->withLock($this->suspicionFile, function (array &$data) use ($ip, $amount, $windowSeconds, &$total): void {
            $now = time();
            if (!isset($data[$ip]) || ($now - $data[$ip]['start']) > $windowSeconds) {
                $data[$ip] = ['score' => 0, 'start' => $now];
            }
            $data[$ip]['score'] += $amount;
            $total = $data[$ip]['score'];
        });
        return $total;
    }

    public function resetSuspicion(string $ip): void
    {
        $this->withLock($this->suspicionFile, function (array &$data) use ($ip): void {
            unset($data[$ip]);
        });
    }

    public function block(string $ip, int $ttl, string $reason): void
    {
        $this->withLock($this->blockFile, function (array &$data) use ($ip, $ttl, $reason): void {
            $data[$ip] = [
                'reason'  => $reason,
                'expires' => time() + $ttl,
                'time'    => date('Y-m-d H:i:s'),
            ];
        });
    }

    public function isBlocked(string $ip): bool
    {
        return $this->getBlock($ip) !== null;
    }

    public function getBlock(string $ip): ?array
    {
        $result = null;
        $this->withLock($this->blockFile, function (array &$data) use ($ip, &$result): void {
            if (isset($data[$ip])) {
                if (time() < $data[$ip]['expires']) {
                    $result = ['reason' => (string) $data[$ip]['reason'], 'expires' => (int) $data[$ip]['expires']];
                } else {
                    unset($data[$ip]); // expired -> clean up opportunistically
                }
            }
        });
        return $result;
    }

    public function name(): string
    {
        return 'file';
    }

    private function garbageCollect(): void
    {
        $now = time();
        $this->withLock($this->blockFile, function (array &$data) use ($now): void {
            foreach ($data as $ip => $info) {
                if (!isset($info['expires']) || $now >= $info['expires']) {
                    unset($data[$ip]);
                }
            }
        });
        $this->withLock($this->suspicionFile, function (array &$data) use ($now): void {
            foreach ($data as $ip => $info) {
                if (!isset($info['start']) || ($now - $info['start']) > 3600) {
                    unset($data[$ip]);
                }
            }
        });
    }

    /**
     * Open a JSON file, lock it exclusively, decode -> mutate -> encode,
     * and write back atomically. Eliminates read/write race conditions.
     *
     * @param callable(array<mixed>):void $mutator
     */
    private function withLock(string $file, callable $mutator): void
    {
        $fp = fopen($file, 'c+');
        if ($fp === false) {
            return;
        }
        if (flock($fp, LOCK_EX)) {
            $size    = (int) (fstat($fp)['size'] ?? 0);
            $content = $size > 0 ? (string) fread($fp, $size) : '';
            $data    = json_decode($content, true);
            if (!is_array($data)) {
                $data = [];
            }

            $mutator($data);

            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, (string) json_encode($data));
            fflush($fp);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }

    private function hardenDir(string $dir): void
    {
        $htaccess = $dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents(
                $htaccess,
                "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                . "<IfModule !mod_authz_core.c>\n    Order Deny,Allow\n    Deny from all\n</IfModule>\n"
            );
        }
        $index = $dir . '/index.php';
        if (!file_exists($index)) {
            file_put_contents($index, "<?php http_response_code(403); exit('Access Denied');");
        }
    }
}
