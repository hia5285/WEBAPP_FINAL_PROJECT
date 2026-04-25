<?php
/**
 * HARDENED document view.
 *
 * Mitigations vs vulnerable/view_document.php:
 *
 *   1. IDOR -- can_access_document() is called BEFORE rendering anything
 *      about the document. If the current user does not own the doc, is not
 *      in the doc's department (for "department" visibility), is not
 *      admin/manager, and the doc is not "public", a 403 page is returned
 *      via forbid().
 *
 *   2. Stored XSS (output side) -- every value coming from the database
 *      is run through e() before being echoed, so any <script> stored by
 *      a malicious commenter is rendered as text.
 */

require_once __DIR__ . '/config/db.php';
require_login();

$current_user = current_user($pdo);
$id = (int)($_GET['id'] ?? 0);

$stmt = $pdo->prepare(
    "SELECT d.*, u.username AS owner_name
     FROM documents d
     JOIN users u ON u.id = d.owner_id
     WHERE d.id = :id LIMIT 1"
);
$stmt->execute([':id' => $id]);
$doc = $stmt->fetch();

if (!$doc) {
    // MITIGATION: same generic 403 whether the document is missing OR the
    //             user is not allowed to see it. This prevents a "fishing"
    //             attacker from learning which IDs exist.
    forbid('You are not authorized to access this resource.');
}

// MITIGATION: IDOR fix -- check authorisation before disclosing anything.
if (!can_access_document($current_user, $doc)) {
    log_activity($pdo, (int)$current_user['id'],
        'idor_blocked', 'view doc=' . $doc['id']);
    forbid('You are not authorized to access this resource.');
}

$cstmt = $pdo->prepare(
    "SELECT c.*, u.username
     FROM comments c
     JOIN users u ON u.id = c.user_id
     WHERE c.document_id = :id
     ORDER BY c.created_at ASC"
);
$cstmt->execute([':id' => (int)$doc['id']]);
$comments = $cstmt->fetchAll();

$APP_VARIANT = 'hardened';
$PAGE_TITLE  = 'Document: ' . $doc['title'];
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <div class="card">
        <div class="card__title">
            <h1 style="margin:0;"><?php echo e($doc['title']); ?></h1>
            <span class="badge badge--<?php echo e($doc['visibility']); ?>">
                <?php echo e($doc['visibility']); ?>
            </span>
        </div>
        <p class="muted">
            Owner: <strong><?php echo e($doc['owner_name']); ?></strong>
            &middot; Department: <?php echo e($doc['department']); ?>
            &middot; Uploaded: <?php echo e($doc['created_at']); ?>
        </p>
        <p><?php echo e($doc['description']); ?></p>
        <div class="row-actions">
            <a class="btn" href="download.php?id=<?php echo (int)$doc['id']; ?>">Download file</a>
            <a class="btn btn--ghost" href="dashboard.php">Back</a>
        </div>
    </div>

    <div class="card">
        <h2>Comments</h2>
        <?php if (!$comments): ?>
            <p class="muted">No comments yet. Be the first to add one.</p>
        <?php else: ?>
            <ul class="comment-list">
                <?php foreach ($comments as $c): ?>
                    <li class="comment">
                        <div class="comment__meta">
                            <strong><?php echo e($c['username']); ?></strong>
                            &middot; <?php echo e($c['created_at']); ?>
                        </div>
                        <div class="comment__body">
                            <?php
                            // MITIGATION: Stored XSS output fix.
                            // Every comment is HTML-escaped via e() so any
                            // <script> or markup that ever made it into the
                            // database is rendered as plain text.
                            echo nl2br(e($c['comment']));
                            ?>
                        </div>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <form method="post" action="comments.php" class="form form--wide" style="margin-top:16px;">
            <input type="hidden" name="document_id" value="<?php echo (int)$doc['id']; ?>">
            <div class="form__row">
                <label class="form__label" for="comment">Add a comment</label>
                <textarea class="textarea" id="comment" name="comment"
                          placeholder="Share your feedback..."
                          required maxlength="1000"></textarea>
                <div class="form__hint">Up to 1000 characters. HTML is not allowed.</div>
            </div>
            <button class="btn" type="submit">Post comment</button>
        </form>
    </div>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
