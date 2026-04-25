<?php
/**
 * HARDENED document download.
 *
 * Mitigation vs vulnerable/download.php:
 *   - IDOR fix: same can_access_document() gate as view_document.php is
 *     applied before the file bytes leave the server. Without this,
 *     IDOR could be exploited via download.php even if the view page
 *     was fixed.
 */

require_once __DIR__ . '/config/db.php';
require_login();

$current_user = current_user($pdo);
$id = (int)($_GET['id'] ?? 0);

$stmt = $pdo->prepare("SELECT * FROM documents WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $id]);
$doc = $stmt->fetch();

if (!$doc) {
    forbid('You are not authorized to access this resource.');
}

// MITIGATION: IDOR fix.
if (!can_access_document($current_user, $doc)) {
    log_activity($pdo, (int)$current_user['id'],
        'idor_blocked', 'download doc=' . $doc['id']);
    forbid('You are not authorized to access this resource.');
}

// MITIGATION: ensure the resolved path is still inside the uploads/ folder
//             so a poisoned database row cannot be turned into a path
//             traversal at download time.
$base    = realpath(__DIR__ . '/uploads');
$resolved= realpath(__DIR__ . '/' . $doc['file_path']);
if (!$resolved || !$base || strncmp($resolved, $base, strlen($base)) !== 0) {
    forbid('You are not authorized to access this resource.');
}

if (!is_file($resolved)) {
    http_response_code(404);
    echo 'File missing on disk.';
    exit;
}

log_activity($pdo, (int)$current_user['id'],
    'download', 'doc=' . $doc['id']);

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($doc['file_name']) . '"');
header('Content-Length: ' . filesize($resolved));
readfile($resolved);
exit;
