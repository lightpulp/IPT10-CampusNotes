<?php
declare(strict_types=1);

/*
 * Shared start-up for public/index.php and public/api.php.
 * Errors are logged, never shown to the client.
 */
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
ini_set('zend.exception_ignore_args', '1');   // keep argument values (e.g. passwords) out of traces
error_reporting(E_ALL);

require __DIR__ . '/helpers.php';
require __DIR__ . '/session.php';
require __DIR__ . '/csrf.php';
require __DIR__ . '/Database.php';
require __DIR__ . '/UserRepository.php';
require __DIR__ . '/NoteRepository.php';

/**
 * Convert warnings to exceptions and replace any uncaught exception with a generic
 * response. Only a sanitized diagnostic (class, code, file, line) is logged:
 * no SQL text, user input, or credentials.
 */
function register_error_handlers(bool $json): void
{
    set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
        if (!(error_reporting() & $severity)) {
            return false;
        }
        throw new ErrorException($message, 0, $severity, $file, $line);
    });

    set_exception_handler(static function (Throwable $e) use ($json): void {
        error_log(sprintf(
            '[campus-notes] %s (code %s) at %s:%d',
            get_class($e),
            (string) $e->getCode(),
            basename($e->getFile()),
            $e->getLine()
        ));
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: ' . ($json ? 'application/json' : 'text/html') . '; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo $json
            ? '{"error":"Internal server error"}'
            : '<!doctype html><html lang="en"><meta charset="utf-8"><title>Error</title><p>Something went wrong. Please try again later.</p></html>';
    });
}

$config = require __DIR__ . '/config.php';
