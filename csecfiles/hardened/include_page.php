<?php
/**
 * HARDENED static-page loader.
 *
 * Mitigation vs vulnerable/include_page.php:
 *
 *   - The user-supplied page name is mapped through safe_include_page(),
 *     which is a fixed allowlist of three known pages (about, help, policy)
 *     each pointing at an absolute path inside hardened/pages/.
 *   - Anything not in the allowlist is rejected with a generic message.
 *   - There is no way for ../, slashes, .php suffixes or absolute paths
 *     to influence the include() target.
 */

require_once __DIR__ . '/config/db.php';
require_login();

$current_user = current_user($pdo);
$page_param = (string)($_GET['page'] ?? 'about');

// MITIGATION: allowlist enforcement.
$abs_path = safe_include_page($page_param);

$APP_VARIANT = 'hardened';
$PAGE_TITLE  = 'Information';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <div class="card">
        <?php if ($abs_path === null): ?>
            <div class="alert alert--error">
                Page "<?php echo e($page_param); ?>" is not available.
                Allowed pages: about, help, policy.
            </div>
        <?php else: ?>
            <?php
            // MITIGATION: $abs_path is one of three known absolute paths,
            //             returned by safe_include_page(). It can never be
            //             attacker-controlled.
            include $abs_path;
            ?>
        <?php endif; ?>
    </div>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
