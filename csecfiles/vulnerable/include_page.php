<?php
/**
 * VULNERABLE static-page loader.
 *
 * Intended legitimate usage:
 *     include_page.php?page=about
 *     include_page.php?page=help
 *     include_page.php?page=policy
 *
 * Hosts the Local File Inclusion (LFI) weakness:
 * the user-supplied $_GET['page'] is passed straight into include() with no
 * allowlist, no extension fixing, and no path validation. An attacker can
 * therefore include arbitrary local files such as
 *     ?page=config/db.php          -> leaks DB credentials
 *     ?page=../../../../etc/hosts  -> reads files outside the app on Linux
 *     ?page=C:/xampp/htdocs/...    -> reads files outside the app on Windows
 *
 * Mitigated in: hardened/include_page.php (allowlist via safe_include_page()).
 */

require_once __DIR__ . '/config/db.php';
vuln_require_login();

$current_user = vuln_current_user($conn);
$page = $_GET['page'] ?? 'about';

$APP_VARIANT = 'vulnerable';
$PAGE_TITLE  = 'Information';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <div class="card">
        <?php
        // Allow legitimate use without forcing the user to type the suffix.
        // If the value already ends in .php, leave it -- this is part of the
        // very mistake that creates the vulnerability.
        $target = $page;
        if (!preg_match('/\.php$/i', $target) && !preg_match('/\\\\|\//', $target)) {
            $target = 'pages/' . $target . '.php';
        }

        // INTENTIONAL VULNERABILITY: Local File Inclusion.
        // Why it is vulnerable: $target is built from raw user input with
        //   NO allowlist and NO base-directory check, then passed directly
        //   to include().
        // Mitigated in: hardened/include_page.php
        if (@file_exists($target) || @file_exists(__DIR__ . '/' . $target)) {
            include $target;
        } else {
            echo '<div class="alert alert--error">Page not found: '
                . htmlspecialchars($page) . '</div>';
        }
        ?>
    </div>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
