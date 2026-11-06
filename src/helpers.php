<?php
declare(strict_types=1);

const TEMPLATE_DIR = __DIR__ . '/../templates';
const TITLE_MAX_CHARS = 120;     // matches notes.title VARCHAR(120)
const BODY_MAX_CHARS = 10000;    // well under the TEXT limit even for 4-byte characters

/** Escape a value for HTML text and attribute contexts. */
function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

/** Render a template inside the shared layout. Every value is escaped in the template with e(). */
function render(string $template, array $vars = [], int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    extract($vars, EXTR_SKIP);
    $contentTemplate = TEMPLATE_DIR . '/' . basename($template) . '.php';
    require TEMPLATE_DIR . '/layout.php';
}

/**
 * URL path of the folder that holds index.php, without a trailing slash.
 * "" when served from the web root (php -S ... -t public),
 * "/Insecure-PHP-Notes-Lab/public" when served from an XAMPP/Apache subfolder.
 * Derived from SCRIPT_NAME (set by the server), not from anything the client sends.
 */
function base_path(): string
{
    $dir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    return rtrim($dir, '/.');
}

/** Build an app-relative URL, e.g. url('/?edit=3'). */
function url(string $path): string
{
    return base_path() . $path;
}

/** Redirect to a fixed, same-site path only (never to user input). 303 forces a GET. */
function redirect(string $path): never
{
    header('Location: ' . url($path), true, 303);
    exit;
}

/** Store a one-time message chosen by the server (never echo request data). */
function flash(string $type, string $text): void
{
    $_SESSION['flash'] = ['type' => $type, 'text' => $text];
}

function take_flash(): ?array
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $flash;
}

/** Read a POST field as a string. Arrays or missing values become ''. */
function post_string(string $key): string
{
    $value = $_POST[$key] ?? '';
    return is_string($value) ? $value : '';
}

/** Parse a positive integer id; anything else returns null. */
function positive_int(mixed $value): ?int
{
    if (is_int($value)) {
        return $value > 0 ? $value : null;
    }
    if (!is_string($value) || !ctype_digit($value)) {
        return null;
    }
    $int = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    return $int === false ? null : $int;
}

/** Character length of a UTF-8 string, or null if the bytes are not valid UTF-8. */
function utf8_length(string $value): ?int
{
    if (preg_match('//u', $value) !== 1) {
        return null;
    }
    return preg_match_all('/./su', $value);
}

/** Validate a note's title and body. Returns a list of error messages (empty = valid). */
function validate_note(mixed $title, mixed $body): array
{
    $errors = [];
    if (!is_string($title) || trim($title) === '' || ($len = utf8_length($title)) === null || $len > TITLE_MAX_CHARS) {
        $errors[] = 'Title is required and must be at most ' . TITLE_MAX_CHARS . ' characters.';
    }
    if (!is_string($body) || trim($body) === '' || ($len = utf8_length($body)) === null || $len > BODY_MAX_CHARS) {
        $errors[] = 'Body is required and must be at most ' . BODY_MAX_CHARS . ' characters.';
    }
    return $errors;
}

/** Defensive response headers. */
function send_security_headers(bool $html): void
{
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header('X-Frame-Options: DENY');
    header('Cache-Control: no-store');
    if ($html) {
        header("Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    } else {
        header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    }
}
