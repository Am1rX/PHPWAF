<?php

declare(strict_types=1);

namespace Waf;

use Generator;
use JsonException;
use LengthException;
use UnexpectedValueException;

final class RequestInput
{
    private int $nodes = 0;
    private int $bytes = 0;
    private int $maxDepth;
    private int $maxKeys;
    private int $maxValueLength;
    private int $maxScanBytes;

    public function __construct(array $limits)
    {
        $this->maxDepth = min(64, max(1, (int) ($limits['max_depth'] ?? 15)));
        $this->maxKeys = max(1, (int) ($limits['max_keys'] ?? 1000));
        $this->maxValueLength = max(1, (int) ($limits['max_value_length'] ?? 8192));
        $this->maxScanBytes = max(1, (int) ($limits['max_scan_bytes'] ?? 262144));
    }

    public static function jsonBody(array $limits): mixed
    {
        $mediaType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '', 2)[0]));
        $isJson = $mediaType === 'application/json' || str_ends_with($mediaType, '+json');
        $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        $hasBody = $length > 0 || !empty($_SERVER['HTTP_TRANSFER_ENCODING']);
        if (!$isJson && ($mediaType !== '' || !$hasBody)) {
            return null;
        }

        $maxBytes = max(1, min(PHP_INT_MAX - 1, (int) ($limits['max_json_bytes'] ?? 131072)));
        if ($length > $maxBytes) {
            throw new LengthException('JSON body budget exceeded.');
        }
        $raw = @file_get_contents('php://input', false, null, 0, $maxBytes + 1);
        if ($raw === false) {
            throw new UnexpectedValueException('Request body unavailable.');
        }
        if (strlen($raw) > $maxBytes) {
            throw new LengthException('JSON body budget exceeded.');
        }
        if ($raw === '') {
            return null;
        }

        $depth = min(64, max(1, (int) ($limits['max_depth'] ?? 15))) + 2;
        try {
            return json_decode($raw, true, $depth, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            if ($error->getCode() === JSON_ERROR_DEPTH) {
                throw new LengthException('JSON nesting budget exceeded.');
            }
            if ($isJson) {
                throw new UnexpectedValueException('Invalid JSON body.');
            }
            return null;
        }
    }

    public static function path(): string
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        return substr($uri, 0, strcspn($uri, '?#'));
    }

    /** @return Generator<string, string> */
    public function values(mixed $value, int $depth = 0, ?string $field = null): Generator
    {
        if ($depth > $this->maxDepth || ++$this->nodes > $this->maxKeys) {
            throw new LengthException('Request structure budget exceeded.');
        }
        if (is_array($value)) {
            foreach ($value as $key => $item) {
                $key = (string) $key;
                $this->charge($key);
                $child = $field === null ? null : $field . '/' . str_replace(['~', '/'], ['~0', '~1'], $key);
                if (strspn($key, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-') !== strlen($key)) {
                    yield ($child ?? '') . '/@key' => $key;
                }
                yield from $this->values($item, $depth + 1, $child);
            }
        } elseif ($value !== null && $value !== '') {
            $text = (string) $value;
            $this->charge($text);
            yield $field ?: '/' => $text;
        }
    }

    private function charge(string $value): void
    {
        $length = strlen($value);
        $this->bytes += $length;
        if ($length > $this->maxValueLength || $this->bytes > $this->maxScanBytes) {
            throw new LengthException('Request scan budget exceeded.');
        }
    }
}
