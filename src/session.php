<?php
declare(strict_types=1);

const SESSION_NAME = 'campus_notes_sid';

/** Start the session with hardened cookie settings. */
function start_secure_session(int $idleSeconds): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    ini_set('session.use_strict_mode', '1');   // reject session ids the server did not create
    ini_set('session.use_only_cookies', '1');  // never accept ids from the URL
    ini_set('session.use_trans_sid', '0');
    session_name(SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $https,   // always true in production (HTTPS)
        'httponly' => true,     // JavaScript cannot read the cookie
        'samesite' => 'Lax',    // not sent on cross-site POST/fetch
    ]);
    session_start();

    // Idle timeout: drop an authenticated session that has not been used recently.
    $now = time();
    if (isset($_SESSION['user_id'], $_SESSION['last_activity']) && $now - $_SESSION['last_activity'] > $idleSeconds) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    $_SESSION['last_activity'] = $now;
}

/** Mark the session as authenticated. A new id prevents session fixation. */
function login_user(array $user): void
{
    session_regenerate_id(true);
    $_SESSION = [
        'user_id'       => (int) $user['id'],
        'email'         => (string) $user['email'],
        'role'          => (string) $user['role'],
        'last_activity' => time(),
    ];
    // A fresh CSRF token is created on the next csrf_token() call.
}

/** Fully end the session: clear data, expire the cookie, destroy server-side storage. */
function logout_user(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => $p['samesite'],
        ]);
    }
    session_destroy();
}

function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
}
