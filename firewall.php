<?php

if (!defined('PREVENT_DIRECT_ACCESS')) {
    http_response_code(403);
    exit('Direct access not allowed.');
}

class Firewall {
    private $log_dir;
    private $block_file;
    private $suspicion_file;
    private $attack_log_file;


    private $whitelist = [];

    // Only set to true if you are behind a trusted reverse proxy/CDN
    // (like Nginx or your own Cloudflare) that will create and overwrite the X-Forwarded-For header.
    // If clients can reach PHP directly,
    // don't set this because the IP can be spoofed.
    private $trust_proxy_header = false;
    private $trusted_proxies = [];

    // WAF self-protection limitations against bulk/nested inputs
    private $max_depth = 15;
    private $max_keys = 1000;
    private $max_value_length = 8192; 

    const RISK_THRESHOLD = 15;       
    const SUSPICION_THRESHOLD = 20; 
    const TIME_WINDOW = 60;          
    const BLOCK_DURATION = 300;      
    const GC_PROBABILITY = 20;       

    public function __construct() {
        $this->log_dir = __DIR__ . '/waf_storage';
        $this->block_file = $this->log_dir . '/blocked_ips.json';
        $this->suspicion_file = $this->log_dir . '/suspicion_log.json';
        $this->attack_log_file = $this->log_dir . '/attacks.log';

        if (!file_exists($this->log_dir)) {
            mkdir($this->log_dir, 0700, true);
        }

        $htaccess_path = $this->log_dir . '/.htaccess';
        if (!file_exists($htaccess_path)) {
            $htaccess = "<IfModule mod_authz_core.c>\n"
                      . "    Require all denied\n"
                      . "</IfModule>\n"
                      . "<IfModule !mod_authz_core.c>\n"
                      . "    Order Deny,Allow\n"
                      . "    Deny from all\n"
                      . "</IfModule>\n";
            file_put_contents($htaccess_path, $htaccess);
        }

        $index_path = $this->log_dir . '/index.php';
        if (!file_exists($index_path)) {
            file_put_contents($index_path, "<?php http_response_code(403); exit('Access Denied'); ?>");
        }
    }

    public function run() {
        $ip = $this->getClientIp();

        if ($this->isWhitelisted($ip)) {
            return;
        }

        if ($this->isBlocked($ip)) {
            $this->renderBlockPage();
            exit();
        }

        $all_inputs = $this->gatherAndFlattenInputs();

        $risk_score = 0;
        $detected_patterns = [];

        foreach ($all_inputs as $key => $value) {
            $result = $this->analyzeInput($value);
            if ($result['score'] > 0) {
                $risk_score += $result['score'];
                foreach ($result['patterns'] as $p) {
                    $detected_patterns[] = "Input [$key]: $p";
                }
            }
        }

        if ($risk_score >= self::RISK_THRESHOLD) {
            $this->blockIP($ip, "Immediate Block (Score: $risk_score)");
            $this->logAttack($ip, $risk_score, $detected_patterns);
            $this->renderBlockPage();
            exit();
        }

        if ($risk_score > 0) {
            $this->trackSuspicion($ip, $risk_score, $detected_patterns);
        }

        // پاکسازی دوره‌ای رکوردهای منقضی تا فایل‌های JSON بی‌نهایت رشد نکنن
        if (random_int(1, self::GC_PROBABILITY) === 1) {
            $this->garbageCollect();
        }
    }

    private function getClientIp() {
        if ($this->trust_proxy_header
            && in_array($_SERVER['REMOTE_ADDR'], $this->trusted_proxies, true)
            && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $candidate = trim($parts[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }
        return $_SERVER['REMOTE_ADDR'];
    }

    private function isWhitelisted($ip) {
        foreach ($this->whitelist as $entry) {
            if ($entry === $ip) {
                return true;
            }
            if (strpos($entry, '/') !== false && $this->ipInCidr($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    private function ipInCidr($ip, $cidr) {
        if (strpos($ip, ':') !== false || strpos($cidr, ':') !== false) {
            return false; 
        }
        [$subnet, $bits] = array_pad(explode('/', $cidr), 2, '32');
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        $bits = (int)$bits;
        if ($bits < 0 || $bits > 32) {
            return false;
        }
        $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
        return ($ip_long & $mask) === ($subnet_long & $mask);
    }

    private function gatherAndFlattenInputs() {
        $data = $_REQUEST;

        $input_raw = file_get_contents('php://input');
        if (!empty($input_raw)) {
            $json = json_decode($input_raw, true);
            if (is_array($json)) {
                $data = array_merge($data, $json);
            }
        }

        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $data['User-Agent'] = $_SERVER['HTTP_USER_AGENT'];
        }
        return $this->flattenArray($data);
    }

    private function flattenArray(array $array, $prefix = '', $depth = 0) {
        if ($depth > $this->max_depth) {
            return [];
        }
        $result = [];
        foreach ($array as $key => $value) {
            if (count($result) >= $this->max_keys) {
                break;
            }
            $new_key = $prefix . ($prefix ? '.' : '') . $key;
            if (is_array($value)) {
                $result = array_merge($result, $this->flattenArray($value, $new_key, $depth + 1));
            } else {
                $result[$new_key] = substr((string)$value, 0, $this->max_value_length);
            }
        }
        return $result;
    }

    private function normalize($input) {
        $decoded = (string)$input;
        for ($i = 0; $i < 2; $i++) {
            $next = urldecode($decoded);
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
        }
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5);
        return strtolower($decoded);
    }

    private function analyzeInput($input) {
        $normalized = $this->normalize($input);

        $score = 0;
        $patterns_found = [];

        $rules = [
            ['pattern' => '/<\s*(details|summary|svg|math|object|iframe|embed|audio|video|keygen|marquee)/i', 'score' => 20, 'type' => 'Critical HTML Tag'],

            ['pattern' => '/(alert|prompt|confirm|print)\s*[`]/', 'score' => 20, 'type' => 'JS Backtick Exec'],

            ['pattern' => '/[\'"]\s*;\s*/', 'score' => 10, 'type' => 'Context Break'],

            ['pattern' => '/<script.*?>.*?<\/script>/is', 'score' => 25, 'type' => 'Script Tag'],
            ['pattern' => '/\bon[a-z]+\s*=/i', 'score' => 15, 'type' => 'Event Handler'],
            ['pattern' => '/(javascript:|vbscript:|data:text)/i', 'score' => 20, 'type' => 'Protocol Handler'],
            ['pattern' => '/(alert|prompt|confirm|eval)\s*(\(|%28)/i', 'score' => 15, 'type' => 'JS Function'],
            ['pattern' => '/\b(union\s+select|information_schema)\b/i', 'score' => 20, 'type' => 'Critical SQLi'],
            ['pattern' => '/[\'"]\s*(or|and)\s+[\'"]?.*?(=|<|>)/i', 'score' => 20, 'type' => 'SQLi Tautology'],
            ['pattern' => '/[\'"]\s*(--|#|\/\*)/', 'score' => 10, 'type' => 'SQLi Comment After Quote'],

            ['pattern' => '/(\.\.\/|\.\.\\\\|%2e%2e(%2f|%5c))/i', 'score' => 15, 'type' => 'Path Traversal'],
            ['pattern' => '/(^|[;&|])\s*(cat|nc|wget|curl|bash|sh)\s+/i', 'score' => 25, 'type' => 'Command Injection'],
        ];

        foreach ($rules as $rule) {
            if (preg_match($rule['pattern'], $normalized)) {
                $score += $rule['score'];
                $patterns_found[] = $rule['type'];
            }
        }

        return ['score' => $score, 'patterns' => $patterns_found];
    }

    private function isBlocked($ip) {
        $blocked = false;
        $this->withLock($this->block_file, function (&$data) use ($ip, &$blocked) {
            if (isset($data[$ip])) {
                if (time() < $data[$ip]['expires']) {
                    $blocked = true;
                } else {
                    unset($data[$ip]);
                }
            }
        });
        return $blocked;
    }

    private function blockIP($ip, $reason) {
        $this->withLock($this->block_file, function (&$data) use ($ip, $reason) {
            $data[$ip] = [
                'expires' => time() + self::BLOCK_DURATION,
                'reason' => $reason,
                'time' => date('Y-m-d H:i:s'),
            ];
        });
    }

    private function trackSuspicion($ip, $score, $patterns) {
        $just_blocked = false;
        $total = 0;

        $this->withLock($this->suspicion_file, function (&$data) use ($ip, $score, &$just_blocked, &$total) {
            if (!isset($data[$ip]) || (time() - $data[$ip]['start_time'] > self::TIME_WINDOW)) {
                $data[$ip] = ['score' => 0, 'start_time' => time()];
            }

            $data[$ip]['score'] += $score;
            $total = $data[$ip]['score'];

            if ($data[$ip]['score'] >= self::SUSPICION_THRESHOLD) {
                $just_blocked = true;
                unset($data[$ip]);
            }
        });

    // blockIP and logAttack are intentionally called outside the above lock callback because
    // they themselves lock another file (block_file); holding two locks
    // nested does not risk deadlock since the files are different, but for simplicity
    // and better readability, we keep the logic separate.
        if ($just_blocked) {
            $this->blockIP($ip, "Behavioral Block (Accumulated Score: $total)");
            $this->logAttack($ip, $total, $patterns);
        }
    }

    /**
    * Opens a JSON file with an exclusive lock, decodes it into an array,
    * executes a callback on the array (by reference), and writes the result back before releasing
    * the lock. This makes the entire read-modify-write operation atomic
    * and eliminates the race condition of the previous version.
    */
    private function withLock($file, callable $mutator) {
        $fp = fopen($file, 'c+');
        if (!$fp) {
            return;
        }

        if (flock($fp, LOCK_EX)) {
            fseek($fp, 0, SEEK_END);
            $size = ftell($fp);
            fseek($fp, 0, SEEK_SET);

            $content = $size > 0 ? fread($fp, $size) : '';
            $data = json_decode($content, true);
            if (!is_array($data)) {
                $data = [];
            }

            $mutator($data);

            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, json_encode($data));
            fflush($fp);
            flock($fp, LOCK_UN);
        }

        fclose($fp);
    }

    private function garbageCollect() {
        $now = time();

        $this->withLock($this->block_file, function (&$data) use ($now) {
            foreach ($data as $ip => $info) {
                if (!isset($info['expires']) || $now >= $info['expires']) {
                    unset($data[$ip]);
                }
            }
        });

        $this->withLock($this->suspicion_file, function (&$data) use ($now) {
            foreach ($data as $ip => $info) {
                if (!isset($info['start_time']) || $now - $info['start_time'] > self::TIME_WINDOW) {
                    unset($data[$ip]);
                }
            }
        });
    }

    private function logAttack($ip, $score, $patterns) {
        $msg = date('Y-m-d H:i:s') . " | IP: $ip | Score: $score | Patterns: " . implode(', ', $patterns) . PHP_EOL;

        $fp = fopen($this->attack_log_file, 'a');
        if ($fp) {
            if (flock($fp, LOCK_EX)) {
                fwrite($fp, $msg);
                flock($fp, LOCK_UN);
            }
            fclose($fp);
        }
    }

    private function renderBlockPage() {
        http_response_code(403);
        echo '<!DOCTYPE html><html><body style="text-align:center;padding:50px;font-family:sans-serif;">';
        echo '<h1 style="color:red;">Access Denied</h1>';
        echo '<p>Your activity has been flagged as suspicious.</p>';
        echo '<small>IP: ' . htmlspecialchars($_SERVER['REMOTE_ADDR'], ENT_QUOTES, 'UTF-8') . '</small>';
        echo '</body></html>';
    }
}

$firewall = new Firewall();
$firewall->run();
