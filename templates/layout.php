<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="<?= e(csrf_token()) ?>">
<title>Campus Notes</title>
<link rel="stylesheet" href="<?= e(url('/assets/style.css')) ?>">
</head>
<body>
<h1>Campus Notes</h1>
<?php require $contentTemplate; ?>
</body>
</html>
