<?php

declare(strict_types=1);

/**
 * Minimal autoloader so the package works with zero Composer setup.
 * Maps the Waf\ namespace to the src/ directory.
 */
spl_autoload_register(static function (string $class): void {
    $prefix  = 'Waf\\';
    $baseDir = __DIR__ . '/src/';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path     = $baseDir . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require $path;
    }
});
