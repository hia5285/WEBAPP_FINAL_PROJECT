<?php
/**
 * VULNERABLE document search.
 *
 * The PRIMARY SQL injection sink for the lab. The user-supplied query string
 * is concatenated directly into a SELECT, so a payload like
 *
 *     ?q=%' UNION SELECT id, username, password, email, role, department, NULL, 0, NOW() FROM users -- -
 *
 * dumps the users table into the result set.
 *
 * Mitigated in: hardened/search.php (PDO prepared statement with bound LIKE).
 */

require_once __DIR__ . '/config/db.php';
vuln_require_login();

$current_user = vuln_current_user($conn);
$q       = $_GET['q'] ?? '';
$results = null;
$sql     = '';
$error   = '';

if ($q !== '') {
    // INTENTIONAL VULNERABILITY: SQL injection via raw string concatenation.
    // Why it is vulnerable: $q is spliced directly into the SQL with no
    //   quoting, parameterisation or allowlist. A single quote terminates
    //   the literal and lets the attacker append arbitrary SQL.
    // Mitigated in: hardened/search.php
    $sql = "SELECT d.*, u.username AS owner_name
            FROM documents d
            JOIN users u ON u.id = d.owner_id
            WHERE d.title LIKE '%$q%' OR d.description LIKE '%$q%'
            ORDER BY d.created_at DESC";
    $results = $conn->query($sql);

    if (!$results) {
        // Verbose SQL errors leak schema info to an attacker -- helpful
        // for SQLi exploitation (and exactly the kind of thing the
        // hardened version suppresses).
        $error = 'SQL error: ' . $conn->error;
    }
}

$APP_VARIANT = 'vulnerable';
$PAGE_TITLE  = 'Search documents';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <h1>Search documents</h1>
    <p class="muted">Find documents across all departments by title or description.</p>

    <form method="get" action="search.php" class="search-bar">
        <input class="input" type="text" name="q" placeholder="Search..." value="<?php echo htmlspecialchars($q); ?>">
        <button class="btn" type="submit">Search</button>
    </form>

    <?php if ($q !== ''): ?>
        <?php if ($error): ?>
            <div class="alert alert--error"><?php echo htmlspecialchars($error); ?></div>
            <details class="muted" style="margin-bottom:14px;">
                <summary>Executed SQL (debug)</summary>
                <pre><?php echo htmlspecialchars($sql); ?></pre>
            </details>
        <?php elseif ($results && $results->num_rows > 0): ?>
            <div class="card">
                <h2>Results (<?php echo (int)$results->num_rows; ?>)</h2>
                <table class="table">
                    <thead>
                        <tr><th>Title</th><th>Owner</th><th>Department</th><th>Visibility</th><th class="right">Actions</th></tr>
                    </thead>
                    <tbody>
                        <?php while ($d = $results->fetch_assoc()): ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($d['title']); ?></strong>
                                    <div class="muted" style="font-size:0.82rem;">
                                        <?php echo htmlspecialchars(mb_strimwidth((string)$d['description'], 0, 90, '...')); ?>
                                    </div>
                                </td>
                                <td><?php echo htmlspecialchars($d['owner_name'] ?? ''); ?></td>
                                <td><?php echo htmlspecialchars($d['department'] ?? ''); ?></td>
                                <td>
                                    <?php if (!empty($d['visibility'])): ?>
                                        <span class="badge badge--<?php echo htmlspecialchars($d['visibility']); ?>">
                                            <?php echo htmlspecialchars($d['visibility']); ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td class="right">
                                    <a class="btn btn--ghost" href="view_document.php?id=<?php echo (int)$d['id']; ?>">View</a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="alert alert--info">No documents matched your query.</div>
        <?php endif; ?>
    <?php endif; ?>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
