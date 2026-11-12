<?php

declare(strict_types=1);

namespace Waf;

final class Response
{
    private const DISCLOSURE_HEADERS = [
        'Server', 'X-Powered-By', 'X-PHP', 'X-PHP-Version', 'X-AspNet-Version', 'X-AspNetMvc-Version',
        'X-WAF-Version', 'X-Version', 'X-Runtime', 'X-Runtime-Version', 'X-Application-Version',
        'X-Framework-Version', 'X-Server-Version', 'X-Backend-Version', 'X-Generator', 'X-Debug-Token',
        'X-Debug-Token-Link', 'X-Profiler', 'X-Backend-Server', 'X-Served-By',
    ];

    private static bool $started = false;

    public static function protectHeaders(): bool
    {
        if (self::$started) {
            return false;
        }
        self::$started = true;
        ini_set('display_errors', '0');
        ini_set('log_errors', '1');
        if (!headers_sent()) {
            header_remove('X-Powered-By');
            header_register_callback(static function (): void {
                foreach (self::DISCLOSURE_HEADERS as $name) {
                    header_remove($name);
                }
            });
        }
        return true;
    }

    public static function reference(): string
    {
        return strtoupper(bin2hex(random_bytes(8)));
    }

    public static function reject(int $status, string $reference): void
    {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: text/plain; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox");
        }

        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'HEAD') {
            echo "Request could not be processed. Reference: $reference\n";
        }
        exit;
    }
}
