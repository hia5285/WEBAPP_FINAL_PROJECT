<?php
/** Entry point: send the user to the dashboard if logged in, else to login. */
require_once __DIR__ . '/config/db.php';

if (vuln_is_logged_in()) {
    header('Location: dashboard.php');
} else {
    header('Location: login.php');
}
exit;
