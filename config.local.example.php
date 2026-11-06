<?php
/*
 *
 * Hi sir
 * If you're reading this, I made this because I ran the project in xampp
 * this file is the same as the .env only without current phponly server temporary variables
 * so I can look and change the environment variables whenever I want to, but all of the web application stays the same
 * 
 * config.local.php is git-ignored and blocked from the web by .htaccess. Never commit it.
 * Environment variables (LAB_DB_USER, LAB_DB_PASSWORD, ...) override these values when set.
 */
return [
    'db' => [
        'host'     => 'localhost',
        'name'     => 'notes_lab',
        'user'     => 'notes_app',
        'password' => 'change-me-local-only',
    ],
    // Comma-separated origins allowed to call api.php (scheme://host[:port], no path).
    // 'allowed_origins' => 'http://localhost',
];
