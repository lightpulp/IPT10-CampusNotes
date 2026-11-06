<?php
declare(strict_types=1);

/*
 * Application configuration.
 *
 * All secrets come from the environment. There is deliberately NO fallback to
 * "root" or an empty password: if credentials are missing, Database::connect()
 * refuses to start instead of silently using a privileged account.
 */

$env = static function (string $key): ?string {
    $value = getenv($key);
    return ($value === false || $value === '') ? null : $value;
};

// Optional git-ignored file for servers that cannot pass environment variables
// (e.g. XAMPP Apache). Copy config.local.example.php to config.local.php.
// Environment variables, when set, take priority.
$localFile = dirname(__DIR__) . '/config.local.php';
$local = is_file($localFile) ? (require $localFile) : [];
$localDb = is_array($local['db'] ?? null) ? $local['db'] : [];
$pick = static fn(?string $fromEnv, mixed $fromLocal): ?string =>
    $fromEnv ?? ((is_string($fromLocal) && $fromLocal !== '') ? $fromLocal : null);

return [
    'db' => [
        'host'     => $pick($env('LAB_DB_HOST'), $localDb['host'] ?? null) ?? 'localhost',
        'name'     => $pick($env('LAB_DB_NAME'), $localDb['name'] ?? null) ?? 'notes_lab',
        'user'     => $pick($env('LAB_DB_USER'), $localDb['user'] ?? null),
        'password' => $pick($env('LAB_DB_PASSWORD'), $localDb['password'] ?? null),
    ],
    // Origins allowed to call api.php with the session cookie. Same-origin only by default.
    'allowed_origins' => array_values(array_filter(array_map(
        'trim',
        explode(',', $env('LAB_ALLOWED_ORIGINS')
            ?? (is_string($local['allowed_origins'] ?? null) ? $local['allowed_origins'] : null)
            ?? 'http://127.0.0.1:8000,http://localhost:8000,http://localhost,http://127.0.0.1')
    ))),
    // Log out after this many seconds without activity.
    'session_idle_seconds' => 1800,
];
