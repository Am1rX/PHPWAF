<?php

declare(strict_types=1);

// Copy this file into the site's directory. Adjust this path if the site
// lives in a subdirectory, or use your account's absolute private path.
$private = dirname(__DIR__);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
header_remove('X-Powered-By');
header('Cache-Control: no-store');

define('PHPWAF_WEB_INSTALL_ROOT', __DIR__);
define('PHPWAF_WEB_INSTALL_STATE', $private . '/waf-private');
define('PHPWAF_WEB_INSTALL_KEY', $private . '/phpwaf-setup.key');

$installer = $private . '/waf/admin/web-install.php';
if (!@is_file($installer)) {
    http_response_code(503);
    exit('PHPWAF installer could not start. Check the private package path.');
}
require $installer;
