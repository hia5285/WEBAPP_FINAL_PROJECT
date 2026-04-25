<?php
/**
 * VULNERABLE document download.
 *
 * Same IDOR weakness as view_document.php: the only check is "is the user
 * logged in?". Anyone authenticated can download any file by changing ?id=N.
 *
 * Mitigated in: hardened/download.php (can_access_document()).
 */

require_once __DIR__ . '/config/db.php';
vuln_require_login();

$id = (int)($_GET['id'] ?? 0);

// INTENTIONAL VULNERABILITY: IDOR -- no ownership/department/role check.
// Mitigated in: hardened/download.php
$res = $conn->query("SELECT * FROM documents WHERE id = $id LIMIT 1");
$doc = $res ? $res->fetch_assoc() : null;

if (!$doc) {
    http_response_code(404);
    echo 'Document not found.';
    exit;
}

$abs_path = __DIR__ . '/' . $doc['file_path'];
if (!is_file($abs_path)) {
    http_response_code(404);
    echo 'File missing on disk: ' . htmlspecialchars($doc['file_path']);
    exit;
}

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($doc['file_name']) . '"');
header('Content-Length: ' . filesize($abs_path));
readfile($abs_path);
exit;
