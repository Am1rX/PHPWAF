<?php

declare(strict_types=1);

namespace Waf\Admin;

use RuntimeException;

final class State
{
    public string $dir;

    public function __construct(string $dir)
    {
        $resolved = realpath($dir);
        if ($resolved === false || !is_dir($resolved)) {
            throw new RuntimeException('The private firewall directory is missing.');
        }
        $this->dir = $resolved;
    }

    public function read(string $name, array $default = []): array
    {
        $path = $this->dir . '/' . $name . '.json';
        if (!is_file($path)) {
            return $default;
        }
        $data = json_decode((string) @file_get_contents($path, false, null, 0, 1048576), true);
        if (!is_array($data)) {
            throw new RuntimeException('Private firewall settings could not be read.');
        }
        return $data;
    }

    public function write(string $name, array $data): void
    {
        self::replace($this->dir . '/' . $name . '.json', json_encode($data, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE) . "\n", 0600);
    }

    public function locked(callable $work): mixed
    {
        $path = $this->dir . '/management.lock';
        $lock = @fopen($path, 'c+b');
        if ($lock === false) {
            throw new RuntimeException('Cannot open the management lock.');
        }
        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Cannot lock firewall settings.');
            }
            return $work();
        } finally {
            fclose($lock);
        }
    }

    public static function replace(string $path, string $contents, int $mode): void
    {
        $parent = dirname($path);
        $temporary = $parent . '/.phpwaf-' . bin2hex(random_bytes(12)) . '.tmp.php';
        $umask = umask(0077);
        try {
            $handle = @fopen($temporary, 'xb');
        } finally {
            umask($umask);
        }
        if ($handle === false) {
            throw new RuntimeException('Cannot stage the file in its destination directory.');
        }
        try {
            $written = @fwrite($handle, $contents);
            $flushed = @fflush($handle);
            fclose($handle);
            if ($written !== strlen($contents) || !$flushed || !@chmod($temporary, $mode) || !@rename($temporary, $path)) {
                throw new RuntimeException('Cannot publish the file. Check write and directory permissions.');
            }
            clearstatcache(true, $path);
            if (str_ends_with($path, '.php') && function_exists('opcache_invalidate')) {
                @opcache_invalidate($path, true);
            }
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }

    public function audit(string $action, string $actor, string $ip): void
    {
        self::appendEvent($this->dir . '/audit.jsonl', [
            'time' => gmdate('c'), 'action' => $action, 'actor' => $actor, 'ip' => $ip,
        ]);
    }

    public static function appendEvent(string $path, array $data): void
    {
        $line = json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($line === false || @file_put_contents($path, $line . "\n", FILE_APPEND | LOCK_EX) === false) {
            error_log('[PHPWAF] Could not append a management event.');
        }
    }

    public function recent(string $name, int $limit = 300): array
    {
        $file = @fopen($this->dir . '/' . $name . '.jsonl', 'rb');
        if ($file === false) {
            return [];
        }
        try {
            if (!flock($file, LOCK_SH)) {
                return [];
            }
            $size = (int) fstat($file)['size'];
            $skip = max(0, $size - 2097152);
            fseek($file, $skip);
            if ($skip > 0) {
                fgets($file);
            }
            $lines = explode("\n", (string) stream_get_contents($file, 2097152));
            $rows = [];
            foreach (array_reverse($lines) as $line) {
                $event = json_decode($line, true);
                if (is_array($event)) {
                    $rows[] = $event;
                    if (count($rows) >= $limit) {
                        break;
                    }
                }
            }
            return $rows;
        } finally {
            fclose($file);
        }
    }

    public static function defaults(array $engine): array
    {
        return ['active' => false, 'exceptions' => [], 'signatures' => [], 'key' => bin2hex(random_bytes(32)), 'engine' => $engine];
    }
}
