<?php
/**
 * HARDENED document search.
 *
 * Mitigation vs vulnerable/search.php:
 *
 *   - PDO prepared statement with a single :q bound parameter.
 *   - The LIKE wildcards are added in PHP, NOT injected into the SQL,
 *     so the user cannot escape the literal.
 *   - Internal SQL errors are caught and presented as a generic message
 *     -- no schema details leak to the attacker.
 *   - Results are filtered through can_access_document() so even if a
 *     row matches, only documents the user is allowed to see are listed.
 *     This means search itself does not become an IDOR oracle.
 */

require_once __DIR__ . '/config/db.php';
require_login();

$current_user = current_user($pdo);
$q       = trim((string)($_GET['q'] ?? ''));
$results = [];
$error   = '';

if ($q !== '') {
    if (mb_strlen($q) > 100) {
        $q = mb_substr($q, 0, 100);
    }

    try {
        // MITIGATION: prepared statement with bound :q.
        //             Wildcards are added here in PHP, not by the user.
        $like = '%' . $q . '%';
        $stmt = $pdo->prepare(
            "SELECT d.*, u.username AS owner_name
             FROM documents d
             JOIN users u ON u.id = d.owner_id
             WHERE d.title LIKE :q OR d.description LIKE :q
             ORDER BY d.created_at DESC
             LIMIT 100"
        );
        $stmt->execute([':q' => $like]);
        $rows = $stmt->fetchAll();

        // MITIGATION: filter by per-document authorisation so search cannot
        //             be used to enumerate private documents.
        foreach ($rows as $row) {
            if (can_access_document($current_user, $row)) {
                $results[] = $row;
            }
        }
    } catch (Throwable $e) {
        // MITIGATION: do not echo $e->getMessage() to the user.
        $error = 'Search is temporarily unavailable.';
    }
}

$APP_VARIANT = 'hardened';
$PAGE_TITLE  = 'Search documents';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <h1>Search documents</h1>
    <p class="muted">Find documents you are authorised to see, by title or description.</p>

    <form method="get" action="search.php" class="search-bar">
        <input class="input" type="text" name="q" placeholder="Search..."
               value="<?php echo e($q); ?>" maxlength="100">
        <button class="btn" type="submit">Search</button>
    </form>

    <?php if ($q !== ''): ?>
        <?php if ($error): ?>
            <div class="alert alert--error"><?php echo e($error); ?></div>
        <?php elseif (count($results) > 0): ?>
            <div class="card">
                <h2>Results (<?php echo count($results); ?>)</h2>
                <table class="table">
                    <thead>
                        <tr><th>Title</th><th>Owner</th><th>Department</th><th>Visibility</th><th class="right">Actions</th></tr>
                    </thead>
                    <tbody>
                        <?php foreach ($results as $d): ?>
                            <tr>
                                <td><strong><?php echo e($d['title']); ?></strong>
                                    <div class="muted" style="font-size:0.82rem;">
                                        <?php echo e(mb_strimwidth((string)$d['description'], 0, 90, '...')); ?>
                                    </div>
                                </td>
                                <td><?php echo e($d['owner_name']); ?></td>
                                <td><?php echo e($d['department']); ?></td>
                                <td>
                                    <span class="badge badge--<?php echo e($d['visibility']); ?>">
                                        <?php echo e($d['visibility']); ?>
                                    </span>
                                </td>
                                <td class="right">
                                    <a class="btn btn--ghost" href="view_document.php?id=<?php echo (int)$d['id']; ?>">View</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="alert alert--info">No documents matched your query.</div>
        <?php endif; ?>
    <?php endif; ?>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
