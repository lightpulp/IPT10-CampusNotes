<?php
declare(strict_types=1);

/*
 * Campus Notes web front controller.
 * Shared security code lives in ../src, HTML lives in ../templates.
 */
require dirname(__DIR__) . '/src/bootstrap.php';

register_error_handlers(json: false);
send_security_headers(html: true);
start_secure_session($config['session_idle_seconds']);

$db = Database::connect($config['db']);
$users = new UserRepository($db);
$notes = new NoteRepository($db);

// bcrypt hash of a random throwaway string: failed logins for unknown emails still run
// password_verify(), so response time does not reveal which emails exist.
const DUMMY_PASSWORD_HASH = '$2y$10$WLvYj2iqt19Y1STuTAZVk.cGs9cAcbEOthG2yYLk3Eo.zBQnPU3Sm';
const PASSWORD_MIN_CHARS = 12;
const PASSWORD_MAX_BYTES = 72;   // bcrypt ignores anything past 72 bytes

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$userId = current_user_id();

// The starter changed state with GET links (?delete=, ?logout=). Those are refused now.
if ($method === 'GET' && (isset($_GET['delete']) || isset($_GET['logout']))) {
    header('Allow: POST');
    render('error', ['message' => 'This action needs the form button (POST with a CSRF token).'], 405);
    exit;
}

if ($method === 'POST') {
    // Every state-changing request, including register and login, must carry the session's CSRF token.
    if (!csrf_is_valid($_POST['csrf_token'] ?? null)) {
        render('error', ['message' => 'Request rejected: missing or invalid CSRF token. Reload the page and try again.'], 403);
        exit;
    }

    $action = post_string('action');

    if ($action === 'register') {
        $email = trim(post_string('email'));
        $password = post_string('password');

        if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            flash('error', 'Enter a valid email address.');
            redirect('/');
        }
        $passwordChars = utf8_length($password);
        if ($passwordChars === null || $passwordChars < PASSWORD_MIN_CHARS || strlen($password) > PASSWORD_MAX_BYTES) {
            flash('error', 'Password must be at least ' . PASSWORD_MIN_CHARS . ' characters (and at most ' . PASSWORD_MAX_BYTES . ' bytes).');
            redirect('/');
        }
        try {
            // Role is never read from the request: UserRepository::create() always assigns "student".
            $users->create($email, password_hash($password, PASSWORD_DEFAULT));
        } catch (PDOException $ex) {
            if ($ex->getCode() !== '23000') {   // only handle duplicate email; rethrow anything else
                throw $ex;
            }
            flash('error', 'That account could not be created. Try signing in instead.');
            redirect('/');
        }
        flash('success', 'Account created. You can now sign in.');
        redirect('/');
    }

    if ($action === 'login') {
        $email = trim(post_string('email'));
        $password = post_string('password');

        $user = ($email !== '' && strlen($email) <= 254) ? $users->findByEmail($email) : null;
        $passwordOk = password_verify($password, $user['password_hash'] ?? DUMMY_PASSWORD_HASH);

        if ($user === null || !$passwordOk) {
            flash('error', 'Invalid email or password.');   // same message for both cases; input is not echoed
            redirect('/');
        }
        if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
            $users->updatePasswordHash((int) $user['id'], password_hash($password, PASSWORD_DEFAULT));
        }
        login_user($user);   // regenerates the session id
        redirect('/');
    }

    if ($action === 'logout') {
        logout_user();
        redirect('/');
    }

    // Everything below needs a signed-in user.
    if ($userId === null) {
        render('error', ['message' => 'Please sign in first.'], 401);
        exit;
    }

    if ($action === 'save') {
        $title = post_string('title');
        $body = post_string('body');
        $errors = validate_note($title, $body);
        if ($errors !== []) {
            flash('error', implode(' ', $errors));
            redirect('/');
        }
        // Owner comes from the session. Any posted user_id is ignored.
        $notes->create($userId, $title, $body);
        flash('success', 'Note saved.');
        redirect('/');
    }

    if ($action === 'update') {
        $id = positive_int(post_string('id'));
        $title = post_string('title');
        $body = post_string('body');
        if ($id === null) {
            render('error', ['message' => 'Note not found.'], 404);
            exit;
        }
        $errors = validate_note($title, $body);
        if ($errors !== []) {
            flash('error', implode(' ', $errors));
            redirect('/?edit=' . $id);
        }
        if (!$notes->update($id, $userId, $title, $body)) {
            render('error', ['message' => 'Note not found.'], 404);
            exit;
        }
        flash('success', 'Note updated.');
        redirect('/');
    }

    if ($action === 'delete') {
        $id = positive_int(post_string('id'));
        if ($id === null || !$notes->delete($id, $userId)) {
            render('error', ['message' => 'Note not found.'], 404);
            exit;
        }
        flash('success', 'Note deleted.');
        redirect('/');
    }

    render('error', ['message' => 'Unknown action.'], 400);
    exit;
}

// GET: show the page.
$editing = null;
if ($userId !== null && isset($_GET['edit'])) {
    $editId = positive_int($_GET['edit']);
    $editing = $editId === null ? null : $notes->findForOwner($editId, $userId);
    if ($editing === null) {
        render('error', ['message' => 'Note not found.'], 404);
        exit;
    }
}

render('home', [
    'flash'   => take_flash(),
    'user'    => $userId === null ? null : ['email' => $_SESSION['email'] ?? '', 'role' => $_SESSION['role'] ?? ''],
    'notes'   => $userId === null ? [] : $notes->listForOwner($userId),
    'editing' => $editing,
]);
