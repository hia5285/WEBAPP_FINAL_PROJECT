<?php
/**
 * CSecFiles -- Centralised security helpers for the hardened build.
 *
 * Every mitigation that is reused across pages lives here so the lessons
 * map cleanly to single, named functions.
 */

/* ---------- Output escaping (XSS mitigation) ---------- */

/**
 * Escape a string for safe HTML output.
 * MITIGATION: htmlspecialchars with ENT_QUOTES turns <, >, ", ' and & into
 *             entities, so attacker-controlled markup or <script> never
 *             executes in the browser.
 */
function e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

/* ---------- Session / authentication ---------- */

function is_logged_in() {
    return isset($_SESSION['user_id']);
}

function require_login() {
    if (!is_logged_in()) {
        header('Location: login.php');
        exit;
    }
}

function current_user(PDO $pdo) {
    if (!is_logged_in()) return null;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => (int)$_SESSION['user_id']]);
    $row = $stmt->fetch();
    return $row ?: null;
}

/* ---------- IDOR mitigation ---------- */

/**
 * Decide whether $user is allowed to see $document.
 * MITIGATION: every fetched document is run through this gate. The
 *             vulnerable version skipped this check entirely.
 *
 * Rules:
 *   - admin or manager  -> can read everything
 *   - public            -> any logged-in user
 *   - department        -> only users in the same department (or admin/manager)
 *   - private           -> only the owner (or admin/manager)
 */
function can_access_document(array $user, array $document) {
    if (in_array($user['role'], ['admin', 'manager'], true)) {
        return true;
    }
    if ($document['visibility'] === 'public') {
        return true;
    }
    if ($document['visibility'] === 'department'
        && strcasecmp($user['department'], $document['department']) === 0) {
        return true;
    }
    if ($document['visibility'] === 'private'
        && (int)$user['id'] === (int)$document['owner_id']) {
        return true;
    }
    return false;
}

/**
 * Render a 403 page and stop. Intentionally generic so the response does not
 * leak whether the document exists.
 */
function forbid(string $message = 'You are not authorized to access this resource.') {
    http_response_code(403);
    echo '<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="assets/css/style.css">';
    echo '<main class="auth"><div class="auth__card">';
    echo '<div class="auth__brand"><span class="dot"></span> CSecFiles</div>';
    echo '<h2>403 -- Forbidden</h2>';
    echo '<div class="alert alert--error">' . e($message) . '</div>';
    echo '<a class="btn btn--ghost" href="dashboard.php">Back to dashboard</a>';
    echo '</div></main>';
    exit;
}

/* ---------- Brute-force mitigation ---------- */

const MAX_LOGIN_ATTEMPTS  = 5;
const LOCKOUT_MINUTES     = 15;

/**
 * MITIGATION: Returns true if the account is currently inside a lockout
 *             window. Called BEFORE checking the password so an attacker
 *             cannot bypass the lockout by spamming requests.
 */
function is_account_locked(?array $user) : bool {
    if (!$user) return false;
    if (empty($user['locked_until'])) return false;
    return strtotime($user['locked_until']) > time();
}

function register_failed_login(PDO $pdo, ?array $user) : void {
    if (!$user) return;
    $attempts = (int)$user['failed_login_attempts'] + 1;
    $lock_sql = '';
    $params   = [':a' => $attempts, ':id' => (int)$user['id']];

    if ($attempts >= MAX_LOGIN_ATTEMPTS) {
        // MITIGATION: exponential is overkill for a lab; a flat 15 min
        // lockout is enough to defeat brute-forcing in the demo.
        $lock_sql = ', locked_until = DATE_ADD(NOW(), INTERVAL ' . LOCKOUT_MINUTES . ' MINUTE)';
    }

    $sql = "UPDATE users
            SET failed_login_attempts = :a,
                last_failed_login     = NOW()
                $lock_sql
            WHERE id = :id";
    $pdo->prepare($sql)->execute($params);
}

function reset_failed_login(PDO $pdo, array $user) : void {
    $stmt = $pdo->prepare(
        "UPDATE users
            SET failed_login_attempts = 0,
                last_failed_login     = NULL,
                locked_until          = NULL
          WHERE id = :id"
    );
    $stmt->execute([':id' => (int)$user['id']]);
}

/* ---------- LFI mitigation ---------- */

/**
 * MITIGATION: Allowlist for the legacy include_page.php?page= feature.
 *             Returns the absolute path of an APPROVED static page, or null
 *             if the requested name is not in the allowlist. The hardened
 *             include_page.php passes its query string through this and
 *             refuses anything that returns null.
 */
function safe_include_page(string $name) : ?string {
    $allow = [
        'about'  => __DIR__ . '/../pages/about.php',
        'help'   => __DIR__ . '/../pages/help.php',
        'policy' => __DIR__ . '/../pages/policy.php',
    ];
    $name = strtolower(trim($name));
    return $allow[$name] ?? null;
}

/* ---------- Misc ---------- */

/** Append a record to activity_logs. Best-effort; failures are swallowed
 *  to keep the page rendering even if the logs table is missing. */
function log_activity(PDO $pdo, ?int $user_id, string $action, string $details = '') : void {
    try {
        $stmt = $pdo->prepare(
            "INSERT INTO activity_logs (user_id, action, details)
             VALUES (:u, :a, :d)"
        );
        $stmt->execute([
            ':u' => $user_id,
            ':a' => substr($action, 0, 80),
            ':d' => substr($details, 0, 500),
        ]);
    } catch (Throwable $e) {
        // Swallow.
    }
}
