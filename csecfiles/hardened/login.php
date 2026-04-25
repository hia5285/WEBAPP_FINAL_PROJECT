<?php
/**
 * HARDENED login page.
 *
 * Mitigations applied here (matched against vulnerable/login.php):
 *
 *   1. SQL injection
 *      MITIGATION: PDO prepared statement with a bound :username parameter.
 *
 *   2. Brute-force
 *      MITIGATION: account is locked for LOCKOUT_MINUTES after
 *                  MAX_LOGIN_ATTEMPTS consecutive failures. Lockout is
 *                  checked BEFORE password verification so an attacker
 *                  cannot bypass it by spraying requests.
 *
 *   3. Password storage
 *      MITIGATION: password_verify() against a bcrypt hash. Seeded users
 *                  whose row still contains the original plaintext are
 *                  silently re-hashed on first successful login so the
 *                  database converges to bcrypt-only over time.
 *
 *   4. Generic error messages
 *      MITIGATION: a single "Invalid credentials" message regardless of
 *                  whether the username or the password was wrong.
 */

require_once __DIR__ . '/config/db.php';

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';

// Reset-lab CSRF token (used only by reset.php).
if (empty($_SESSION['reset_token'])) {
    $_SESSION['reset_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    // MITIGATION: prepared statement -- $username is sent as a parameter,
    //             never spliced into the SQL text.
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :u LIMIT 1");
    $stmt->execute([':u' => $username]);
    $user = $stmt->fetch();

    if (is_account_locked($user)) {
        // MITIGATION: short-circuit on lockout BEFORE checking the password.
        $error = 'Invalid credentials.';
        log_activity($pdo, $user ? (int)$user['id'] : null,
            'login_blocked', 'Account locked');
    } else {
        $authenticated = false;

        if ($user) {
            $stored = (string)$user['password'];
            $is_bcrypt = (strlen($stored) >= 60 &&
                (str_starts_with($stored, '$2y$') || str_starts_with($stored, '$2a$')));

            if ($is_bcrypt) {
                $authenticated = password_verify($password, $stored);
            } else {
                // Legacy seeded plaintext row. Verify in plaintext, then
                // upgrade silently to a real bcrypt hash so this branch
                // disappears for the user on subsequent logins.
                if (hash_equals($stored, $password)) {
                    $authenticated = true;
                    $new_hash = password_hash($password, PASSWORD_DEFAULT);
                    $upd = $pdo->prepare("UPDATE users SET password = :p WHERE id = :id");
                    $upd->execute([':p' => $new_hash, ':id' => (int)$user['id']]);
                }
            }
        }

        if ($authenticated) {
            // MITIGATION: regenerate the session id to prevent fixation.
            session_regenerate_id(true);

            $_SESSION['user_id']    = (int)$user['id'];
            $_SESSION['username']   = $user['username'];
            $_SESSION['role']       = $user['role'];
            $_SESSION['department'] = $user['department'];

            reset_failed_login($pdo, $user);
            log_activity($pdo, (int)$user['id'], 'login_success', '');

            header('Location: dashboard.php');
            exit;
        } else {
            register_failed_login($pdo, $user);
            // MITIGATION: identical message for unknown user vs wrong password.
            $error = 'Invalid credentials.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in &middot; CSecFiles (Hardened)</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="auth">
    <div class="auth__card">
        <div class="auth__brand"><span class="dot"></span> CSecFiles</div>
        <p class="auth__subtitle">Sign in to your internal workspace.</p>

        <span class="header__badge header__badge--hardened" style="margin-bottom:12px;display:inline-block;">Hardened</span>

        <?php if (($_GET['reset'] ?? '') === '1'): ?>
            <div class="alert" style="margin-bottom:12px;">Lab environment reset. You can sign in with the default accounts.</div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert--error"><?php echo e($error); ?></div>
        <?php endif; ?>

        <form method="post" action="login.php" class="form" autocomplete="off">
            <div class="form__row">
                <label class="form__label" for="username">Username</label>
                <input class="input" id="username" name="username" type="text" required maxlength="60">
            </div>
            <div class="form__row">
                <label class="form__label" for="password">Password</label>
                <input class="input" id="password" name="password" type="password" required maxlength="200">
            </div>
            <button class="btn" type="submit">Sign in</button>
        </form>

        <div class="auth__footer">
            New here? <a href="register.php">Create an account</a>
        </div>

        <hr style="margin:18px 0;opacity:.25;">

        <form method="post" action="reset.php" onsubmit="return confirm('Are you sure you want to reset the lab environment? This deletes all user-generated data.');">
            <input type="hidden" name="reset_token" value="<?php echo e($_SESSION['reset_token']); ?>">
            <button class="btn btn--ghost" type="submit">Reset Lab Environment</button>
        </form>
    </div>
</main>
</body>
</html>
