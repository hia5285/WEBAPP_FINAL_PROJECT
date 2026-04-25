<?php
/**
 * VULNERABLE comment handler.
 *
 * Receives POST {document_id, comment} and writes the comment row directly
 * with raw string concatenation. This is the INPUT side of the Stored XSS
 * pair (the OUTPUT side lives in view_document.php which echoes the comment
 * unencoded).
 *
 * Mitigated in: hardened/comments.php
 *   - PDO prepared statement
 *   - Length cap
 *   - Authentication still required
 *   - Output escaping in hardened/view_document.php
 */

require_once __DIR__ . '/config/db.php';
vuln_require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: dashboard.php');
    exit;
}

$document_id = (int)($_POST['document_id'] ?? 0);
$comment     = $_POST['comment'] ?? '';
$user_id     = (int)$_SESSION['user_id'];

if ($document_id <= 0 || $comment === '') {
    header('Location: view_document.php?id=' . $document_id);
    exit;
}

// INTENTIONAL VULNERABILITY: Stored XSS (input side) + SQL injection.
// Comment is inserted unfiltered. When rendered by view_document.php it is
// echoed raw, executing any HTML/JS payload.
// Mitigated in: hardened/comments.php
$sql = "INSERT INTO comments (document_id, user_id, comment)
        VALUES ($document_id, $user_id, '$comment')";
$conn->query($sql);

header('Location: view_document.php?id=' . $document_id);
exit;
