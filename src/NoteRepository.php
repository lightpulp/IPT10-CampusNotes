<?php
declare(strict_types=1);

/**
 * Every query is scoped to the owner taken from the session.
 * A note that belongs to someone else behaves exactly like a note that does not exist.
 */
final class NoteRepository
{
    public function __construct(private PDO $db)
    {
    }

    public function listForOwner(int $ownerId): array
    {
        $stmt = $this->db->prepare('SELECT id, user_id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC');
        $stmt->execute([$ownerId]);
        return $stmt->fetchAll();
    }

    public function findForOwner(int $id, int $ownerId): ?array
    {
        $stmt = $this->db->prepare('SELECT id, user_id, title, body FROM notes WHERE id = ? AND user_id = ?');
        $stmt->execute([$id, $ownerId]);
        return $stmt->fetch() ?: null;
    }

    public function create(int $ownerId, string $title, string $body): int
    {
        $stmt = $this->db->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
        $stmt->execute([$ownerId, $title, $body]);
        return (int) $this->db->lastInsertId();
    }

    /** Returns false when the note does not exist or is not owned by $ownerId. */
    public function update(int $id, int $ownerId, string $title, string $body): bool
    {
        $stmt = $this->db->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
        $stmt->execute([$title, $body, $id, $ownerId]);
        // MySQL reports 0 affected rows when the new values equal the old ones,
        // so confirm ownership before reporting "not found".
        return $stmt->rowCount() > 0 || $this->findForOwner($id, $ownerId) !== null;
    }

    public function delete(int $id, int $ownerId): bool
    {
        $stmt = $this->db->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
        $stmt->execute([$id, $ownerId]);
        return $stmt->rowCount() > 0;
    }
}
