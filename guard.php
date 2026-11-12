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
use Waf\Admin\Policy;
use Waf\DenyList;
use Waf\Firewall;
use Waf\Logger;
use Waf\Normalizer;
use Waf\Response;
use Waf\RequestInput;
use Waf\Storage\StorageFactory;

require_once __DIR__ . '/autoload.php';

(static function (): void {
    try {
        $privateDir = defined('PHPWAF_PRIVATE_STATE') ? PHPWAF_PRIVATE_STATE : null;
        $settings = null;
        if ($privateDir !== null) {
            $settings = json_decode((string) @file_get_contents($privateDir . '/settings.json', false, null, 0, 1048576), true);
            if (!is_array($settings) || !is_bool($settings['active'] ?? null)) {
                throw new UnexpectedValueException('Managed firewall settings are unavailable.');
            }
            if (!$settings['active']) {
                return;
            }
        }
        if (!Response::protectHeaders()) {
            return;
        }
        $config = $settings['engine'] ?? (require __DIR__ . '/config.php');
        if (!in_array($config['mode'] ?? null, ['monitor', 'filter', 'enforce'], true)) {
            throw new UnexpectedValueException('Invalid firewall mode.');
        }
        if ($privateDir !== null) {
            $config['storage']['dir'] = $privateDir . '/ip-state';
        }

        $storage = null;
        if ($config['mode'] === 'enforce') {
            try {
                $storage = StorageFactory::create($config['storage'], (int) $config['gc_probability']);
            } catch (Throwable $error) {
                error_log('[PHPWAF] IP storage initialization failed. Inspecting without IP state.');
            }
        }

        $detector = new Detector($config['disabled_rules'] ?? [], $config['shadow_rule_ids'] ?? [], $settings['signatures'] ?? []);
        $logger = $privateDir !== null
            ? new Logger($privateDir . '/events.jsonl', $privateDir . '/attacks.log', 8388608)
            : new Logger($config['logging']['json_log'], $config['logging']['text_log']);
        $policy = $settings !== null
            ? new Policy($settings, $_SERVER['REQUEST_METHOD'] ?? '-', RequestInput::path())
            : null;

        $denyList = $storage !== null && !empty($config['edge']['enabled'])
            ? new DenyList($config['edge']['denylist_file'])
            : null;

        (new Firewall($config, $storage, $detector, new Normalizer(), $logger, $denyList, $policy))->run();
    } catch (Throwable $error) {
        Response::protectHeaders();
        $reference = Response::reference();
        error_log(sprintf('[PHPWAF] %s %s at %s:%d', $reference, get_class($error), $error->getFile(), $error->getLine()));
        Response::reject(503, $reference);
    }
})();
