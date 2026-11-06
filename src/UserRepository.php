<?php
declare(strict_types=1);

final class UserRepository
{
    public const DEFAULT_ROLE = 'student';

    public function __construct(private PDO $db)
    {
    }

    public function findByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?');
        $stmt->execute([$email]);
        return $stmt->fetch() ?: null;
    }

    /** New accounts always get the server-defined role; the client cannot choose it. */
    public function create(string $email, string $passwordHash): int
    {
        $stmt = $this->db->prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)');
        $stmt->execute([$email, $passwordHash, self::DEFAULT_ROLE]);
        return (int) $this->db->lastInsertId();
    }

    public function updatePasswordHash(int $id, string $passwordHash): void
    {
        $stmt = $this->db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $stmt->execute([$passwordHash, $id]);
    }
}
