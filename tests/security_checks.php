<?php
declare(strict_types=1);

/*
 * Black-box security checks for Campus Notes (no extra packages needed).
 *
 *   1. Start the app:  php -S 127.0.0.1:8000 -t public
 *   2. In another shell with the same LAB_DB_USER / LAB_DB_PASSWORD set:
 *        php tests/security_checks.php http://127.0.0.1:8000
 *
 * The two synthetic accounts are read from LAB_TEST_ALEX_PASSWORD / LAB_TEST_SAM_PASSWORD,
 * falling back to the public throwaway values documented in README.md.
 * The script creates a few test notes and one test account; run it only on the disposable lab database.
 * It never prints passwords, session ids or tokens.
 */
if (PHP_SAPI !== 'cli') {
    exit(1);
}

$base = rtrim($argv[1] ?? 'http://127.0.0.1:8000', '/');   // may include a subfolder, e.g. http://localhost/Insecure-PHP-Notes-Lab/public
$u = parse_url($base);
$origin = $u['scheme'] . '://' . $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');
$alexEmail = 'alex@example.test';
$samEmail = 'sam@example.test';
$alexPassword = getenv('LAB_TEST_ALEX_PASSWORD') ?: 'LabOnly-Alex-123';
$samPassword = getenv('LAB_TEST_SAM_PASSWORD') ?: 'LabOnly-Sam-456';

$cfg = require dirname(__DIR__) . '/src/config.php';
$pdo = new PDO(
    sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $cfg['db']['host'], $cfg['db']['name']),
    (string) $cfg['db']['user'],
    (string) $cfg['db']['password'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
);

final class Client
{
    public array $cookies = [];

    public function __construct(private string $base)
    {
    }

    public function request(string $method, string $path, array $opt = []): array
    {
        $headers = $opt['headers'] ?? [];
        if ($this->cookies !== []) {
            $pairs = [];
            foreach ($this->cookies as $k => $v) {
                $pairs[] = "$k=$v";
            }
            $headers[] = 'Cookie: ' . implode('; ', $pairs);
        }
        $content = '';
        if (isset($opt['form'])) {
            $content = http_build_query($opt['form']);
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        } elseif (isset($opt['raw'])) {
            $content = $opt['raw'];
        }
        $ctx = stream_context_create(['http' => [
            'method' => $method,
            'header' => implode("\r\n", $headers),
            'content' => $content,
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => 15,
        ]]);
        $body = @file_get_contents($this->base . $path, false, $ctx);
        $raw = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
        preg_match('#^HTTP/\S+\s+(\d{3})#', $raw[0] ?? '', $m);
        $out = ['status' => (int) ($m[1] ?? 0), 'headers' => [], 'body' => $body === false ? '' : $body];
        foreach (array_slice($raw, 1) as $line) {
            [$k, $v] = array_map('trim', explode(':', $line, 2) + [1 => '']);
            $out['headers'][strtolower($k)][] = $v;
            if (strtolower($k) === 'set-cookie') {
                [$ck, $cv] = explode('=', explode(';', $v, 2)[0], 2) + [1 => ''];
                if ($cv === '' || $cv === 'deleted' || preg_match('/max-age=0/i', $v)) {
                    unset($this->cookies[$ck]);
                } else {
                    $this->cookies[$ck] = $cv;
                }
            }
        }
        return $out;
    }

    public function csrf(): string
    {
        $r = $this->request('GET', '/');
        return preg_match('/<meta name="csrf-token" content="([a-f0-9]{64})">/', $r['body'], $m) ? $m[1] : '';
    }

    public function login(string $email, string $password): array
    {
        $token = $this->csrf();
        return $this->request('POST', '/', ['form' => ['csrf_token' => $token, 'action' => 'login', 'email' => $email, 'password' => $password]]);
    }

    public function sid(): ?string
    {
        return $this->cookies['campus_notes_sid'] ?? null;
    }
}

$results = [];
function check(string $id, string $name, bool $ok, string $detail = ''): void
{
    global $results;
    $results[] = $ok;
    printf("%s  %s  %s%s\n", $ok ? 'PASS' : 'FAIL', $id, $name, $detail !== '' ? "  [$detail]" : '');
}
function noteRow(PDO $pdo, int $id): ?array
{
    $s = $pdo->prepare('SELECT id, user_id, title, body FROM notes WHERE id = ?');
    $s->execute([$id]);
    return $s->fetch() ?: null;
}
function looksLikeLeak(string $body): bool
{
    return (bool) preg_match('/PDOException|SQLSTATE|Stack trace|Fatal error|Warning:|Notice:|\.php on line|LAB_DB_PASSWORD/i', $body);
}

// Fixture: one note for each user, created directly in the DB so ids are known.
$pdo->prepare('INSERT INTO notes (user_id, title, body) VALUES (2, ?, ?)')->execute(['Sam private fixture', 'Sam only']);
$samNote = (int) $pdo->lastInsertId();
$pdo->prepare('INSERT INTO notes (user_id, title, body) VALUES (1, ?, ?)')->execute(['Alex fixture', 'Alex only']);
$alexNote = (int) $pdo->lastInsertId();

echo "Campus Notes security checks against $base\n\n";

// ---------- Login and session ----------
$alex = new Client($base);
$alex->csrf();
$sidBefore = $alex->sid();
$r = $alex->login($alexEmail, $alexPassword);
$home = $alex->request('GET', '/');
check('T01', 'Valid login succeeds and shows own notes', $r['status'] === 303 && str_contains($home['body'], 'Alex fixture'), "status {$r['status']}");
check('T02', 'Session id changes at login (fixation defence)', $sidBefore !== null && $alex->sid() !== null && $sidBefore !== $alex->sid());
$setCookie = implode(' | ', $r['headers']['set-cookie'] ?? []);
check('T03', 'Session cookie is HttpOnly and SameSite=Lax', stripos($setCookie, 'httponly') !== false && stripos($setCookie, 'samesite=lax') !== false);

$bad = new Client($base);
$r = $bad->login($alexEmail, 'wrong-password-123');
$page = $bad->request('GET', '/');
check('T04', 'Invalid password rejected with generic message', str_contains($page['body'], 'Invalid email or password.') && !str_contains($page['body'], 'Your notes'));

$inj = new Client($base);
$inj->login("alex@example.test' -- ", 'anything');
$page = $inj->request('GET', '/');
check('T05', 'SQL-injection login payload is rejected', !str_contains($page['body'], 'Your notes') && !looksLikeLeak($page['body']));

$fix = new Client($base);
$fix->cookies['campus_notes_sid'] = 'attackerchosenid1234567890abcdef';
$fix->request('GET', '/');
check('T06', 'Server-chosen session id replaces an attacker-supplied one (strict mode)', $fix->sid() !== 'attackerchosenid1234567890abcdef');

// ---------- Authorization (web) ----------
$sam = new Client($base);
$sam->login($samEmail, $samPassword);
$alexHome = $alex->request('GET', '/');
check('T07', "Alex's list does not include Sam's notes", !str_contains($alexHome['body'], 'Sam private fixture') && !str_contains($alexHome['body'], 'Sam: study plan'));
$r = $alex->request('GET', '/?edit=' . $samNote);
check('T08', "Alex cannot open Sam's note for editing", $r['status'] === 404 && !str_contains($r['body'], 'Sam only'), "status {$r['status']}");
$token = $alex->csrf();
$r = $alex->request('POST', '/', ['form' => ['csrf_token' => $token, 'action' => 'update', 'id' => $samNote, 'title' => 'hacked', 'body' => 'hacked']]);
check('T09', "Alex cannot update Sam's note (web)", $r['status'] === 404 && noteRow($pdo, $samNote)['title'] === 'Sam private fixture', "status {$r['status']}");
$r = $alex->request('POST', '/', ['form' => ['csrf_token' => $token, 'action' => 'delete', 'id' => $samNote]]);
check('T10', "Alex cannot delete Sam's note (web)", $r['status'] === 404 && noteRow($pdo, $samNote) !== null, "status {$r['status']}");

// ---------- Client-controlled owner / role ----------
$title = 'owner-tamper-' . bin2hex(random_bytes(4));
$alex->request('POST', '/', ['form' => ['csrf_token' => $token, 'action' => 'save', 'user_id' => 2, 'title' => $title, 'body' => 'x']]);
$s = $pdo->prepare('SELECT user_id FROM notes WHERE title = ?');
$s->execute([$title]);
check('T11', 'Posted user_id is ignored; note is owned by the session user', (int) $s->fetchColumn() === 1);

$reg = new Client($base);
$email = 'reg-' . bin2hex(random_bytes(4)) . '@example.test';
$t = $reg->csrf();
$reg->request('POST', '/', ['form' => ['csrf_token' => $t, 'action' => 'register', 'email' => $email, 'password' => 'Synthetic-Test-Pass-1', 'role' => 'admin']]);
$s = $pdo->prepare('SELECT role, password_hash FROM users WHERE email = ?');
$s->execute([$email]);
$row = $s->fetch();
check('T12', 'Registration ignores posted role=admin', $row !== false && $row['role'] === 'student');
check('T13', 'New password stored with password_hash (bcrypt/argon), not MD5', $row !== false && preg_match('/^\$(2y|argon2id?)\$/', $row['password_hash']) === 1);
$t = $reg->csrf();
$reg->request('POST', '/', ['form' => ['csrf_token' => $t, 'action' => 'register', 'email' => 'short-' . bin2hex(random_bytes(3)) . '@example.test', 'password' => 'short']]);
$page = $reg->request('GET', '/');
check('T14', 'Weak (short) password is refused at registration', str_contains($page['body'], 'at least 12 characters'));

// ---------- XSS ----------
$payload = '<script>alert(1)</script>"><img src=x onerror=alert(2)>';
$alex->request('POST', '/', ['form' => ['csrf_token' => $token, 'action' => 'save', 'title' => $payload, 'body' => $payload]]);
$page = $alex->request('GET', '/');
check('T15', 'HTML-like note text renders as text (escaped)', str_contains($page['body'], '&lt;script&gt;alert(1)&lt;/script&gt;') && !str_contains($page['body'], '<script>alert(1)') && !str_contains($page['body'], '<img src=x'));
$r = $alex->request('GET', '/?message=' . rawurlencode('<script>alert(3)</script>'));
check('T16', '?message= is no longer reflected', !str_contains($r['body'], 'alert(3)'));
$csp = implode(' ', $page['headers']['content-security-policy'] ?? []);
check('T17', 'Content-Security-Policy header present (script-src none)', str_contains($csp, "script-src 'none'"));

// ---------- CSRF and unsafe methods (web) ----------
$before = (int) $pdo->query('SELECT COUNT(*) FROM notes')->fetchColumn();
$r = $alex->request('POST', '/', ['form' => ['action' => 'save', 'title' => 'csrf-missing', 'body' => 'x']]);
$after = (int) $pdo->query('SELECT COUNT(*) FROM notes')->fetchColumn();
check('T18', 'POST without CSRF token is rejected (403) and changes nothing', $r['status'] === 403 && $before === $after, "status {$r['status']}");
$r = $alex->request('POST', '/', ['form' => ['csrf_token' => str_repeat('0', 64), 'action' => 'delete', 'id' => $alexNote]]);
check('T19', 'POST with wrong CSRF token is rejected', $r['status'] === 403 && noteRow($pdo, $alexNote) !== null, "status {$r['status']}");
$r = $alex->request('GET', '/?delete=' . $alexNote);
check('T20', 'GET ?delete= no longer deletes (405)', $r['status'] === 405 && noteRow($pdo, $alexNote) !== null, "status {$r['status']}");
$r = $alex->request('GET', '/?logout=1');
$still = $alex->request('GET', '/');
check('T21', 'GET ?logout= is refused (405) and does not end the session', $r['status'] === 405 && str_contains($still['body'], 'Your notes'), "status {$r['status']}");
$r = $alex->request('POST', '/', ['form' => ['csrf_token' => $token, 'action' => 'update', 'id' => $alexNote, 'title' => 'Alex fixture', 'body' => 'Alex edited']]);
check('T22', 'Owner can still update own note (CRUD preserved)', $r['status'] === 303 && noteRow($pdo, $alexNote)['body'] === 'Alex edited', "status {$r['status']}");

// ---------- API ----------
$anon = new Client($base);
$r = $anon->request('GET', '/api.php?user_id=1');
check('T23', 'API GET without session -> 401, no notes', $r['status'] === 401 && !str_contains($r['body'], 'Alex'), "status {$r['status']}");
$r = $anon->request('POST', '/api.php', ['headers' => ['Content-Type: application/json'], 'raw' => json_encode(['id' => $alexNote, 'title' => 'x', 'body' => 'x'])]);
check('T24', 'API POST without session -> 401, no change', $r['status'] === 401 && noteRow($pdo, $alexNote)['body'] === 'Alex edited', "status {$r['status']}");

$r = $alex->request('GET', '/api.php');
$list = json_decode($r['body'], true);
$owners = is_array($list) ? array_unique(array_column($list, 'user_id')) : [];
check('T25', 'API GET returns only the caller\'s notes', $r['status'] === 200 && $owners === [1], "status {$r['status']}");
$r = $alex->request('GET', '/api.php?user_id=2');
check('T26', "API GET ?user_id=<other user> -> 403, no data", $r['status'] === 403 && !str_contains($r['body'], 'Sam'), "status {$r['status']}");

$apiToken = $alex->csrf();
$json = ['Content-Type: application/json', 'X-CSRF-Token: ' . $apiToken, 'Origin: ' . $origin];
$r = $alex->request('POST', '/api.php', ['headers' => $json, 'raw' => json_encode(['id' => $samNote, 'title' => 'hacked', 'body' => 'hacked'])]);
check('T27', "API POST to another user's note -> 404, unchanged", $r['status'] === 404 && noteRow($pdo, $samNote)['title'] === 'Sam private fixture', "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => $json, 'raw' => json_encode(['id' => $alexNote, 'title' => 'Alex fixture', 'body' => 'API edit'])]);
check('T28', 'API POST to own note succeeds', $r['status'] === 200 && noteRow($pdo, $alexNote)['body'] === 'API edit', "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => $json, 'raw' => '{"id": 1, "title": "x", "body": ']);
check('T29', 'API malformed JSON -> 400 generic error, no stack trace', $r['status'] === 400 && !looksLikeLeak($r['body']), "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => $json, 'raw' => '["not","an","object"]']);
check('T30', 'API JSON array instead of object -> 400', $r['status'] === 400, "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => $json, 'raw' => json_encode(['id' => '1 OR 1=1', 'title' => ['x'], 'body' => ''])]);
check('T31', 'API wrong field types -> 422 with no DB change', $r['status'] === 422 && !looksLikeLeak($r['body']), "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => $json, 'raw' => json_encode(['id' => $alexNote, 'title' => 't', 'body' => 'b', 'user_id' => 2])]);
check('T32', 'API extra field (user_id) -> 400', $r['status'] === 400, "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => ['Content-Type: text/plain', 'X-CSRF-Token: ' . $apiToken], 'raw' => json_encode(['id' => $alexNote, 'title' => 't', 'body' => 'b'])]);
check('T33', 'API non-JSON Content-Type -> 415', $r['status'] === 415, "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => ['Content-Type: application/json'], 'raw' => json_encode(['id' => $alexNote, 'title' => 'csrf', 'body' => 'csrf'])]);
check('T34', 'API POST without X-CSRF-Token -> 403, unchanged', $r['status'] === 403 && noteRow($pdo, $alexNote)['body'] === 'API edit', "status {$r['status']}");

$evil = ['Origin: http://evil.example'];
$r = $alex->request('GET', '/api.php', ['headers' => $evil]);
check('T35', 'API GET from untrusted Origin -> 403, no ACAO header', $r['status'] === 403 && !isset($r['headers']['access-control-allow-origin']) && !str_contains($r['body'], 'Alex'), "status {$r['status']}");
$r = $alex->request('POST', '/api.php', ['headers' => array_merge($evil, ['Content-Type: application/json', 'X-CSRF-Token: ' . $apiToken]), 'raw' => json_encode(['id' => $alexNote, 'title' => 'evil', 'body' => 'evil'])]);
check('T36', 'API POST from untrusted Origin -> 403, unchanged', $r['status'] === 403 && noteRow($pdo, $alexNote)['body'] === 'API edit', "status {$r['status']}");
$r = $alex->request('OPTIONS', '/api.php', ['headers' => array_merge($evil, ['Access-Control-Request-Method: POST'])]);
check('T37', 'CORS preflight from untrusted Origin gets no allow headers', !isset($r['headers']['access-control-allow-origin']) && !isset($r['headers']['access-control-allow-credentials']), "status {$r['status']}");

// ---------- Logout ----------
$oldSid = $alex->sid();
$t = $alex->csrf();
$alex->request('POST', '/', ['form' => ['csrf_token' => $t, 'action' => 'logout']]);
$page = $alex->request('GET', '/');
check('T38', 'Logout ends access in the same browser', !str_contains($page['body'], 'Your notes'));
$replay = new Client($base);
$replay->cookies['campus_notes_sid'] = (string) $oldSid;
$page = $replay->request('GET', '/');
$api = $replay->request('GET', '/api.php');
check('T39', 'Old session cookie replayed after logout gives no access (web + API)', !str_contains($page['body'], 'Your notes') && $api['status'] === 401, "api status {$api['status']}");

// Clean-up of fixtures created by this run.
$pdo->prepare('DELETE FROM notes WHERE id IN (?, ?)')->execute([$samNote, $alexNote]);

$passed = count(array_filter($results));
printf("\n%d/%d checks passed.\n", $passed, count($results));
exit($passed === count($results) ? 0 : 1);
