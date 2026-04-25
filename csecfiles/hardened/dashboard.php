<?php
/**
 * HARDENED dashboard.
 *
 * Same look as the vulnerable dashboard, but every value coming out of the
 * database is run through e() before being echoed.
 */

require_once __DIR__ . '/config/db.php';
require_login();

$current_user = current_user($pdo);

$total_docs    = (int)$pdo->query("SELECT COUNT(*) c FROM documents")->fetchColumn();
$stmt = $pdo->prepare("SELECT COUNT(*) FROM documents WHERE owner_id = :id");
$stmt->execute([':id' => (int)$current_user['id']]);
$my_docs       = (int)$stmt->fetchColumn();
$total_comments= (int)$pdo->query("SELECT COUNT(*) c FROM comments")->fetchColumn();
$total_users   = (int)$pdo->query("SELECT COUNT(*) c FROM users")->fetchColumn();

$recent = $pdo->query(
    "SELECT d.*, u.username AS owner_name
     FROM documents d
     JOIN users u ON u.id = d.owner_id
     ORDER BY d.created_at DESC
     LIMIT 10"
)->fetchAll();

$APP_VARIANT = 'hardened';
$PAGE_TITLE  = 'Dashboard';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <h1>Welcome, <?php echo e($current_user['full_name']); ?></h1>
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
                <?php foreach ($recent as $doc): ?>
                    <tr>
                        <td><strong><?php echo e($doc['title']); ?></strong></td>
                        <td><?php echo e($doc['owner_name']); ?></td>
                        <td><?php echo e($doc['department']); ?></td>
                        <td>
                            <span class="badge badge--<?php echo e($doc['visibility']); ?>">
                                <?php echo e($doc['visibility']); ?>
                            </span>
                        </td>
                        <td class="muted"><?php echo e($doc['created_at']); ?></td>
                        <td class="right">
                            <div class="row-actions" style="justify-content:flex-end;">
                                <a class="btn btn--ghost" href="view_document.php?id=<?php echo (int)$doc['id']; ?>">View</a>
                                <a class="btn btn--ghost" href="download.php?id=<?php echo (int)$doc['id']; ?>">Download</a>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
