<?php

declare(strict_types=1);

/**
 * WAF entry point.
 *
 * Protect any PHP application by adding this one line at the very top
 * of your front controller (e.g. index.php), BEFORE any other code:
 *
 *     require __DIR__ . '/waf/guard.php';
 *
 * That's it. Configuration lives in config.php.
 */

use Waf\Detector;
use Waf\DenyList;
use Waf\Firewall;
use Waf\Logger;
use Waf\Normalizer;
use Waf\Storage\StorageFactory;

require __DIR__ . '/autoload.php';

$config = require __DIR__ . '/config.php';

$storage = StorageFactory::create(
    $config['storage'],
    (int) $config['gc_probability']
);

$detector = new Detector($config['disabled_rules'] ?? []);

$logger = new Logger(
    $config['logging']['json_log'],
    $config['logging']['text_log']
);

$denyList = !empty($config['edge']['enabled'])
    ? new DenyList($config['edge']['denylist_file'])
    : null;

(new Firewall(
    $config,
    $storage,
    $detector,
    new Normalizer(),
    $logger,
    $denyList
))->run();
