<?php

declare(strict_types=1);

use Waf\Response;

require_once __DIR__ . '/../autoload.php';

Response::protectHeaders();
Response::reject(403, Response::reference());
