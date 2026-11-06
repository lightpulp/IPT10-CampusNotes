<?php
declare(strict_types=1);

final class Database
{
    /**
     * Opens the PDO connection with safe defaults.
     * Native prepared statements (no emulation) keep SQL and data separate.
     */
    public static function connect(array $config): PDO
    {
        if ($config['user'] === null || $config['password'] === null) {
            throw new RuntimeException('Database credentials are not configured. Set LAB_DB_USER and LAB_DB_PASSWORD.');
        }

        $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $config['host'], $config['name']);

        return self::open($dsn, $config['user'], $config['password']);
    }

    private static function open(string $dsn, string $user, #[\SensitiveParameter] string $password): PDO
    {
        return new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
}
