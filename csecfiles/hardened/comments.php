<?php
/**
 * HARDENED comment handler.
 *
 * Mitigations vs vulnerable/comments.php:
 *   1. SQL injection -- prepared statement with bound parameters.
 *   2. Stored XSS (input side) -- length cap (1000 chars). The OUTPUT side
 *      is also fixed in hardened/view_document.php (htmlspecialchars).
 *   3. IDOR -- the user can only comment on a document they are allowed to
 *      view; can_access_document() is checked here too.
 */

require_once __DIR__ . '/config/db.php';
require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: dashboard.php');
    exit;
}

$current_user = current_user($pdo);
$document_id = (int)($_POST['document_id'] ?? 0);
$comment     = trim((string)($_POST['comment'] ?? ''));

if ($document_id <= 0 || $comment === '') {
    header('Location: view_document.php?id=' . $document_id);
    exit;
}

// MITIGATION: cap comment length so an attacker cannot stuff massive
//             payloads into the database.
if (mb_strlen($comment) > 1000) {
    $comment = mb_substr($comment, 0, 1000);
}

// MITIGATION: confirm the user is allowed to see this document before
//             accepting their comment on it (IDOR + abuse prevention).
$dstmt = $pdo->prepare("SELECT * FROM documents WHERE id = :id LIMIT 1");
$dstmt->execute([':id' => $document_id]);
$doc = $dstmt->fetch();

if (!$doc || !can_access_document($current_user, $doc)) {
    forbid('You are not authorized to comment on this document.');
}

// MITIGATION: prepared INSERT, no string concatenation.
$ins = $pdo->prepare(
    "INSERT INTO comments (document_id, user_id, comment)
     VALUES (:d, :u, :c)"
);
$ins->execute([
    ':d' => $document_id,
    ':u' => (int)$current_user['id'],
    ':c' => $comment,
]);

log_activity($pdo, (int)$current_user['id'],
    'comment_add', 'doc=' . $document_id);

header('Location: view_document.php?id=' . $document_id);
exit;
