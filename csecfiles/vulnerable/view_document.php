<?php
/**
 * VULNERABLE document view.
 *
 * Hosts TWO of the lab's deliberate weaknesses:
 *
 *   1. IDOR (Insecure Direct Object Reference)
 *      The page only checks "is the user logged in?". It does NOT check
 *      whether the requested document belongs to the user, or whether the
 *      user's department/role grants access. Anybody who is logged in can
 *      view any document by changing ?id=N in the URL.
 *      Mitigated in: hardened/view_document.php (can_access_document()).
 *
 *   2. Stored XSS (output side)
 *      Comments are rendered with raw echo, so a payload like
 *      <script>alert(1)</script> stored via comments.php executes here.
 *      Mitigated in: hardened/view_document.php (htmlspecialchars on output).
 */

require_once __DIR__ . '/config/db.php';
vuln_require_login();

$current_user = vuln_current_user($conn);
$id = (int)($_GET['id'] ?? 0);

// INTENTIONAL VULNERABILITY: IDOR -- no ownership/department/role check.
// Mitigated in: hardened/view_document.php
$res = $conn->query("SELECT d.*, u.username AS owner_name
                     FROM documents d
                     JOIN users u ON u.id = d.owner_id
                     WHERE d.id = $id LIMIT 1");
$doc = $res ? $res->fetch_assoc() : null;

$comments = [];
if ($doc) {
    $cres = $conn->query("SELECT c.*, u.username
                          FROM comments c
                          JOIN users u ON u.id = c.user_id
                          WHERE c.document_id = " . (int)$doc['id'] . "
                          ORDER BY c.created_at ASC");
    while ($row = $cres->fetch_assoc()) {
        $comments[] = $row;
    }
}

$APP_VARIANT = 'vulnerable';
$PAGE_TITLE  = $doc ? ('Document: ' . $doc['title']) : 'Document not found';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <?php if (!$doc): ?>
        <div class="alert alert--error">Document not found.</div>
        <a class="btn btn--ghost" href="dashboard.php">Back to dashboard</a>
    <?php else: ?>
        <div class="card">
            <div class="card__title">
                <h1 style="margin:0;"><?php echo htmlspecialchars($doc['title']); ?></h1>
                <span class="badge badge--<?php echo htmlspecialchars($doc['visibility']); ?>">
                    <?php echo htmlspecialchars($doc['visibility']); ?>
                </span>
            </div>
            <p class="muted">
                Owner: <strong><?php echo htmlspecialchars($doc['owner_name']); ?></strong>
                &middot; Department: <?php echo htmlspecialchars($doc['department']); ?>
                &middot; Uploaded: <?php echo htmlspecialchars($doc['created_at']); ?>
            </p>
            <p><?php echo htmlspecialchars($doc['description']); ?></p>
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
                                <strong><?php echo htmlspecialchars($c['username']); ?></strong>
                                &middot; <?php echo htmlspecialchars($c['created_at']); ?>
                            </div>
                            <div class="comment__body">
                                <?php
                                // INTENTIONAL VULNERABILITY: Stored XSS sink.
                                // The comment body is echoed RAW, so any HTML
                                // or <script> stored through comments.php
                                // will execute in every viewer's browser.
                                // Mitigated in: hardened/view_document.php
                                echo $c['comment'];
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
                    <textarea class="textarea" id="comment" name="comment" placeholder="Share your feedback..." required></textarea>
                </div>
                <button class="btn" type="submit">Post comment</button>
            </form>
        </div>
    <?php endif; ?>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
