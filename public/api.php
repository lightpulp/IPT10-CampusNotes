<?php
declare(strict_types=1);

/*
 * JSON API for the signed-in user's own notes.
 *   GET  /api.php            -> list your notes (optional ?user_id= must equal your own id)
 *   POST /api.php            -> update one of your notes; JSON body {"id": int, "title": str, "body": str}
 *                               requires header X-CSRF-Token (value from the page's csrf-token meta tag)
 * Cookie-authenticated, same-origin only.
 */
require dirname(__DIR__) . '/src/bootstrap.php';

register_error_handlers(json: true);
send_security_headers(html: false);
header('Content-Type: application/json; charset=utf-8');
header('Vary: Origin');

const MAX_JSON_BYTES = 16384;

function json_response(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
    exit;
}

// 1. Cross-origin protection.
//    No Access-Control-Allow-* headers are ever sent, so browsers will not let other sites
//    read responses. Requests announcing a foreign origin are refused before the session is used.
$origin = $_SERVER['HTTP_ORIGIN'] ?? null;
if ($origin !== null && !in_array($origin, $config['allowed_origins'], true)) {
    json_response(403, ['error' => 'Origin not allowed']);
}
if (($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') === 'cross-site') {
    json_response(403, ['error' => 'Cross-site request refused']);
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'POST') {
    header('Allow: GET, POST');
    json_response(405, ['error' => 'Method not supported']);
}

// 2. Authentication.
start_secure_session($config['session_idle_seconds']);
$userId = current_user_id();
if ($userId === null) {
    json_response(401, ['error' => 'Authentication required']);
}

$notes = new NoteRepository(Database::connect($config['db']));

// 3. Read: only the caller's own notes.
if ($method === 'GET') {
    if (isset($_GET['user_id'])) {
        $requested = positive_int($_GET['user_id']);
        if ($requested === null) {
            json_response(400, ['error' => 'user_id must be a positive integer']);
        }
        if ($requested !== $userId) {
            json_response(403, ['error' => 'Forbidden']);
        }
    }
    json_response(200, $notes->listForOwner($userId));
}

// 4. Update: CSRF token, strict JSON validation, per-record ownership.
if (!csrf_is_valid($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
    json_response(403, ['error' => 'Missing or invalid CSRF token']);
}

$contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '', 2)[0]));
if ($contentType !== 'application/json') {
    json_response(415, ['error' => 'Content-Type must be application/json']);
}
if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > MAX_JSON_BYTES) {
    json_response(413, ['error' => 'Request body too large']);
}
$raw = file_get_contents('php://input', false, null, 0, MAX_JSON_BYTES + 1);
if ($raw === false || strlen($raw) > MAX_JSON_BYTES) {
    json_response(413, ['error' => 'Request body too large']);
}

try {
    $data = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
} catch (JsonException) {
    json_response(400, ['error' => 'Malformed JSON']);
}

if (!is_array($data) || array_is_list($data)) {
    json_response(400, ['error' => 'Expected a JSON object with id, title and body']);
}
$unexpected = array_diff(array_map('strval', array_keys($data)), ['id', 'title', 'body']);
if ($unexpected !== []) {
    json_response(400, ['error' => 'Unexpected fields', 'fields' => array_values($unexpected)]);
}

$id = is_int($data['id'] ?? null) ? positive_int($data['id']) : null;
$errors = validate_note($data['title'] ?? null, $data['body'] ?? null);
if ($id === null) {
    array_unshift($errors, 'id must be a positive integer.');
}
if ($errors !== []) {
    json_response(422, ['error' => 'Validation failed', 'details' => $errors]);
}

if (!$notes->update($id, $userId, $data['title'], $data['body'])) {
    json_response(404, ['error' => 'Note not found']);   // same answer for "missing" and "not yours"
}
json_response(200, ['updated' => 1]);
