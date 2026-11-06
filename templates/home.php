<?php if ($flash !== null): ?>
<p class="flash flash-<?= $flash['type'] === 'success' ? 'success' : 'error' ?>" role="status"><?= e($flash['text']) ?></p>
<?php endif; ?>

<?php if ($user === null): ?>
<h2>Register or sign in</h2>
<form method="post" action="<?= e(url('/')) ?>">
  <?= csrf_field() ?>
  <label>Email <input name="email" type="email" maxlength="254" autocomplete="username" required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <p class="hint">New passwords need at least 12 characters.</p>
  <button name="action" value="register">Register</button>
  <button name="action" value="login">Sign in</button>
</form>
<?php else: ?>
<form method="post" action="<?= e(url('/')) ?>" class="bar">
  <span>Signed in as <?= e($user['email']) ?> (<?= e($user['role']) ?>)</span>
  <?= csrf_field() ?>
  <button name="action" value="logout">Log out</button>
</form>

<?php if ($editing !== null): ?>
<h2>Edit note</h2>
<form method="post" action="<?= e(url('/')) ?>">
  <?= csrf_field() ?>
  <input type="hidden" name="id" value="<?= e($editing['id']) ?>">
  <label>Title <input name="title" value="<?= e($editing['title']) ?>" maxlength="120" required></label>
  <label>Body <textarea name="body" maxlength="10000" required><?= e($editing['body']) ?></textarea></label>
  <button name="action" value="update">Update</button>
  <a href="<?= e(url('/')) ?>">Cancel</a>
</form>
<?php endif; ?>

<h2>Create a note</h2>
<form method="post" action="<?= e(url('/')) ?>">
  <?= csrf_field() ?>
  <label>Title <input name="title" maxlength="120" required></label>
  <label>Body <textarea name="body" maxlength="10000" required></textarea></label>
  <button name="action" value="save">Save</button>
</form>

<h2>Your notes</h2>
<?php if ($notes === []): ?>
<p>No notes yet.</p>
<?php endif; ?>
<?php foreach ($notes as $note): ?>
<article>
  <h3><?= e($note['title']) ?></h3>
  <p class="body"><?= e($note['body']) ?></p>
  <a href="<?= e(url('/?edit=' . $note['id'])) ?>">Edit</a>
  <form method="post" action="<?= e(url('/')) ?>" class="inline">
    <?= csrf_field() ?>
    <input type="hidden" name="id" value="<?= e($note['id']) ?>">
    <button name="action" value="delete">Delete</button>
  </form>
</article>
<?php endforeach; ?>
<?php endif; ?>
