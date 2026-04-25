<?php
/** Destroy the session and bounce back to the login page. */
require_once __DIR__ . '/config/db.php';

if (is_logged_in()) {
    log_activity($pdo, (int)$_SESSION['user_id'], 'logout', '');
}

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params['path'], $params['domain'],
        $params['secure'], $params['httponly']);
}
session_destroy();

header('Location: login.php');
exit;
