<?php
declare(strict_types=1);

/*
 * CLI helper: set (or reset) a local account's password with password_hash().
 * Use it if you imported the old MD5 schema instead of re-importing schema.sql.
 *
 *   php scripts/set-password.php alex@example.test
 *   (type the new password, then Enter)
 *
 * The password is read from standard input so it never appears in shell history.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

$email = $argv[1] ?? '';
if ($email === '') {
    fwrite(STDERR, "Usage: php scripts/set-password.php <email>\n");
    exit(2);
}

fwrite(STDOUT, "New password for {$email}: ");
$password = rtrim((string) fgets(STDIN), "\r\n");
if (strlen($password) < 12 || strlen($password) > 72) {
    fwrite(STDERR, "\nPassword must be 12-72 bytes.\n");
    exit(2);
}

$users = new UserRepository(Database::connect($config['db']));
$user = $users->findByEmail($email);
if ($user === null) {
    fwrite(STDERR, "\nNo such user.\n");
    exit(1);
}
$users->updatePasswordHash((int) $user['id'], password_hash($password, PASSWORD_DEFAULT));
fwrite(STDOUT, "\nPassword updated.\n");
