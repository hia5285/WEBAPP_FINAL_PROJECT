<?php
/**
 * CSecFiles -- Hardened database connection.
 *
 * Uses PDO with prepared-statement enforcement and exception-mode errors
 * (no automatic emulation, so bound parameters are sent as real parameters
 * to MariaDB). The vulnerable build uses raw mysqli string concatenation;
 * this module is the foundation of the SQL injection mitigation.
 */

$DB_HOST = '127.0.0.1';
$DB_USER = 'root';
$DB_PASS = 'hassan';
$DB_NAME = 'csecfiles';

try {
    // MITIGATION: PDO with ATTR_EMULATE_PREPARES=false sends real prepared
    //             statements to MariaDB so user input can never be reparsed
    //             as SQL.
    $pdo = new PDO(
        "mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4",
        $DB_USER,
        $DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
} catch (Throwable $e) {
    http_response_code(500);
    echo '<h2>Database connection failed</h2>';
    echo '<p>Make sure XAMPP MySQL is running and that you imported '
       . '<code>database/csecfiles.sql</code> via phpMyAdmin.</p>';
    // MITIGATION: do not leak the underlying exception message in production.
    echo '<pre>Database is unavailable.</pre>';
    exit;
}

require_once __DIR__ . '/security.php';

if (session_status() === PHP_SESSION_NONE) {
    // MITIGATION: stricter session cookie settings.
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}
