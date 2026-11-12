<?php

declare(strict_types=1);

namespace Waf\Admin;

use RuntimeException;
use Throwable;

final class Deployment
{
    private const MARKER = 'PHPWAF-MANAGED';
    private State $state;
    private array $config;

    public function __construct(State $state, array $config)
    {
        $this->state = $state;
        $this->config = $config;
    }

    public static function within(string $path, string $directory): bool
    {
        $path = str_replace('\\', '/', $path);
        $directory = rtrim(str_replace('\\', '/', $directory), '/');
        if (DIRECTORY_SEPARATOR === '\\') {
            $path = strtolower($path);
            $directory = strtolower($directory);
        }
        return $path === $directory || str_starts_with($path, $directory . '/');
    }

    public function entries(): array
    {
        $entries = [];
        foreach ($this->config['entries'] as $path) {
            try {
                $source = $this->readEntry($path);
                $status = substr_count($source, $this->block()) === 1 && substr_count($source, self::MARKER) === 2 ? 'installed' : 'ready';
                if ($status === 'ready' && strpos($source, self::MARKER) !== false) {
                    $status = 'conflict';
                }
            } catch (RuntimeException $error) {
                $status = 'unavailable';
            }
            $entries[] = ['file' => ltrim(substr($path, strlen($this->config['root'])), '/\\'), 'status' => $status];
        }
        return $entries;
    }

    public function setActive(bool $active): void
    {
        $settings = $this->state->read('settings');
        if (!$active && $settings['active']) {
            $settings['active'] = false;
            $this->state->write('settings', $settings);
        }

        $plan = [];
        $errors = [];
        foreach ($this->config['entries'] as $path) {
            try {
                $old = $this->readEntry($path);
                $new = $this->patch($old, $active);
                if ($old !== $new) {
                    $plan[$path] = [$old, $new, fileperms($path) & 0777];
                }
            } catch (Throwable $error) {
                $errors[] = basename($path) . ': ' . ($error instanceof RuntimeException ? $error->getMessage() : 'Unsupported PHP syntax.');
            }
        }
        if ($active && $errors !== []) {
            throw new RuntimeException(implode(' ', $errors));
        }

        $applied = [];
        try {
            foreach ($plan as $path => [$old, $new, $mode]) {
                try {
                    if ($this->readEntry($path) !== $old) {
                        throw new RuntimeException('An entry point changed during activation.');
                    }
                    State::replace($path, $new, $mode);
                    $applied[$path] = [$old, $new, $mode];
                } catch (Throwable $error) {
                    if ($active) {
                        throw $error;
                    }
                    $errors[] = basename($path) . ': Could not remove the managed block.';
                }
            }
            if ($active && !$settings['active']) {
                $settings['active'] = true;
                $this->state->write('settings', $settings);
            }
        } catch (Throwable $error) {
            foreach (array_reverse($applied, true) as $path => [$old, $new, $mode]) {
                try {
                    if ($this->readEntry($path) === $new) {
                        State::replace($path, $old, $mode);
                    }
                } catch (Throwable $rollbackError) {
                    error_log('[PHPWAF] A managed entry requires recovery.');
                }
            }
            throw $error;
        }
        if ($errors !== []) {
            throw new RuntimeException('Inspection is off. ' . implode(' ', $errors));
        }
    }

    private function readEntry(string $path): string
    {
        $real = realpath($path);
        if ($real !== $path || !self::within($path, $this->config['root']) || !is_file($path)) {
            throw new RuntimeException('Entry point is missing or no longer resolves to its approved path.');
        }
        $contents = @file_get_contents($path, false, null, 0, 1048577);
        if ($contents === false || strlen($contents) > 1048576) {
            throw new RuntimeException('Entry point is unreadable or larger than 1 MiB.');
        }
        return $contents;
    }

    private function block(): string
    {
        $loader = var_export(str_replace('\\', '/', $this->state->dir) . '/managed-loader.php', true);
        return "\n/* " . self::MARKER . " BEGIN */\nrequire_once " . $loader . ";\n/* " . self::MARKER . " END */\n";
    }

    private function patch(string $source, bool $active): string
    {
        $block = $this->block();
        $count = substr_count($source, $block);
        if ($count === 1 && substr_count($source, self::MARKER) === 2) {
            if ($active) {
                token_get_all($source, TOKEN_PARSE);
                return $source;
            }
            $updated = str_replace($block, '', $source);
            token_get_all($updated, TOKEN_PARSE);
            return $updated;
        }
        if (strpos($source, self::MARKER) !== false) {
            throw new RuntimeException('Existing managed marker was edited. Review the entry point manually.');
        }
        if (!$active) {
            return $source;
        }

        $tokens = token_get_all($source, TOKEN_PARSE);
        if (!isset($tokens[0][0]) || $tokens[0][0] !== T_OPEN_TAG || !str_starts_with(strtolower($tokens[0][1]), '<?php')) {
            throw new RuntimeException('Entry point must start with a full PHP opening tag.');
        }
        foreach ($tokens as $token) {
            if (is_array($token) && $token[0] === T_HALT_COMPILER) {
                throw new RuntimeException('Archive entry points cannot be managed.');
            }
            if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING && preg_match('~(?:guard|managed-loader)\.php[\'"]$~i', $token[1])) {
                throw new RuntimeException('Remove the existing manual firewall include before activating this entry.');
            }
        }

        $offset = strlen($tokens[0][1]);
        $index = 1;
        $this->skipTrivia($tokens, $index, $offset);
        while (($tokens[$index][0] ?? null) === T_DECLARE) {
            $this->advanceThrough($tokens, $index, $offset, [';'], ['{', ':']);
            $this->skipTrivia($tokens, $index, $offset);
        }
        if (($tokens[$index][0] ?? null) === T_NAMESPACE) {
            $this->advanceThrough($tokens, $index, $offset, [';', '{'], []);
        }
        $updated = substr($source, 0, $offset) . $block . substr($source, $offset);
        token_get_all($updated, TOKEN_PARSE);
        return $updated;
    }

    private function skipTrivia(array $tokens, int &$index, int &$offset): void
    {
        while (is_array($tokens[$index] ?? null) && in_array($tokens[$index][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            $offset += strlen($tokens[$index++][1]);
        }
    }

    private function advanceThrough(array $tokens, int &$index, int &$offset, array $ends, array $rejects): void
    {
        while (isset($tokens[$index])) {
            $token = $tokens[$index++];
            $offset += strlen(is_array($token) ? $token[1] : $token);
            if (in_array($token, $ends, true)) {
                return;
            }
            if (in_array($token, $rejects, true) || (is_array($token) && $token[0] === T_CLOSE_TAG)) {
                break;
            }
        }
        throw new RuntimeException('Unsupported PHP declaration before the entry point.');
    }
}
