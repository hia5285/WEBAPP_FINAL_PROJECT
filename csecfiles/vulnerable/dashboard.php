<?php
/**
 * VULNERABLE dashboard.
 * Renders stats and a recent-documents table. The table links to view/download
 * pages that contain the IDOR vulnerability.
 */

require_once __DIR__ . '/config/db.php';
vuln_require_login();

$current_user = vuln_current_user($conn);

$total_docs    = (int)$conn->query("SELECT COUNT(*) c FROM documents")->fetch_assoc()['c'];
$my_docs       = (int)$conn->query("SELECT COUNT(*) c FROM documents WHERE owner_id = " . (int)$current_user['id'])->fetch_assoc()['c'];
$total_comments= (int)$conn->query("SELECT COUNT(*) c FROM comments")->fetch_assoc()['c'];
$total_users   = (int)$conn->query("SELECT COUNT(*) c FROM users")->fetch_assoc()['c'];

$recent = $conn->query(
    "SELECT d.*, u.username AS owner_name
     FROM documents d
     JOIN users u ON u.id = d.owner_id
     ORDER BY d.created_at DESC
     LIMIT 10"
);

$APP_VARIANT = 'vulnerable';
$PAGE_TITLE  = 'Dashboard';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <h1>Welcome, <?php echo htmlspecialchars($current_user['full_name']); ?></h1>
    <p class="muted">Here is a quick snapshot of your CSecFiles workspace.</p>

    <div class="stat-grid">
        <div class="stat">
            <div class="stat__label">Total documents</div>
            <div class="stat__value"><?php echo $total_docs; ?></div>
            <div class="stat__hint">Across all departments</div>
        </div>
        <div class="stat">
            <div class="stat__label">My documents</div>
            <div class="stat__value"><?php echo $my_docs; ?></div>
            <div class="stat__hint">Owned by you</div>
        </div>
        <div class="stat">
            <div class="stat__label">Comments</div>
            <div class="stat__value"><?php echo $total_comments; ?></div>
            <div class="stat__hint">All time</div>
        </div>
        <div class="stat">
            <div class="stat__label">Team members</div>
            <div class="stat__value"><?php echo $total_users; ?></div>
            <div class="stat__hint">Registered users</div>
        </div>
    </div>

    <div class="card">
        <div class="card__title">
            <h2>Recent documents</h2>
            <a class="btn btn--ghost" href="upload.php">Upload new</a>
        </div>

        <table class="table">
            <thead>
                <tr>
                    <th>Title</th>
                    <th>Owner</th>
                    <th>Department</th>
                    <th>Visibility</th>
                    <th>Uploaded</th>
                    <th class="right">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($doc = $recent->fetch_assoc()): ?>
                    <?php
                        $is_private = (($doc['visibility'] ?? '') === 'private');
                        $is_owner   = ((int)$doc['owner_id'] === (int)$current_user['id']);
                        $blocked_in_dashboard = ($is_private && !$is_owner);
                    ?>
                    <tr>
                        <td><strong><?php echo htmlspecialchars($doc['title']); ?></strong></td>
                        <td><?php echo htmlspecialchars($doc['owner_name']); ?></td>
                        <td><?php echo htmlspecialchars($doc['department']); ?></td>
                        <td>
                            <span class="badge badge--<?php echo htmlspecialchars($doc['visibility']); ?>">
                                <?php echo htmlspecialchars($doc['visibility']); ?>
                            </span>
                        </td>
                        <td class="muted"><?php echo htmlspecialchars($doc['created_at']); ?></td>
                        <td class="right">
                            <div class="row-actions" style="justify-content:flex-end;">
                                <?php if ($blocked_in_dashboard): ?>
                                    <a
                                        class="btn btn--ghost js-private-doc-block"
                                        href="#"
                                        data-action="view"
                                        data-doc-title="<?php echo htmlspecialchars($doc['title']); ?>"
                                        data-doc-owner="<?php echo htmlspecialchars($doc['owner_name']); ?>"
                                    >View</a>
                                    <a
                                        class="btn btn--ghost js-private-doc-block"
                                        href="#"
                                        data-action="download"
                                        data-doc-title="<?php echo htmlspecialchars($doc['title']); ?>"
                                        data-doc-owner="<?php echo htmlspecialchars($doc['owner_name']); ?>"
                                    >Download</a>
                                <?php else: ?>
                                    <a class="btn btn--ghost" href="view_document.php?id=<?php echo (int)$doc['id']; ?>">View</a>
                                    <a class="btn btn--ghost" href="download.php?id=<?php echo (int)$doc['id']; ?>">Download</a>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
