<?php
/**
 * CSecFiles -- Vulnerable database connection.
 *
 * Uses mysqli on purpose (so the SQL injection lesson can show plain string
 * concatenation against $conn->query). The hardened version uses PDO with
 * prepared statements instead.
 *
 * XAMPP defaults: user=root, no password, MySQL on 127.0.0.1:3306.
 * Adjust below if your local install differs.
 */

$DB_HOST = '127.0.0.1';
$DB_USER = 'root';
$DB_PASS = 'hassan';
$DB_NAME = 'csecfiles';

$conn = @new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);

if ($conn->connect_errno) {
    http_response_code(500);
    echo '<h2>Database connection failed</h2>';
    echo '<p>Make sure XAMPP MySQL is running and that you imported '
       . '<code>database/csecfiles.sql</code> via phpMyAdmin.</p>';
    echo '<pre>' . htmlspecialchars($conn->connect_error) . '</pre>';
    exit;
}

$conn->set_charset('utf8mb4');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/** Convenience: is the user logged in at all? (Note: this app does NOT check
 *  per-document authorization -- that omission is the IDOR vulnerability.) */
function vuln_is_logged_in() {
    return isset($_SESSION['user_id']);
}

/** Fetch the current logged-in user row, or null. */
function vuln_current_user($conn) {
    if (!vuln_is_logged_in()) return null;
    $id = (int)$_SESSION['user_id'];
    $res = $conn->query("SELECT * FROM users WHERE id = $id LIMIT 1");
    return $res ? $res->fetch_assoc() : null;
}

/** Force-redirect to login if not authenticated. */
function vuln_require_login() {
    if (!vuln_is_logged_in()) {
        header('Location: login.php');
        exit;
    }
}
