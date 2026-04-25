<?php
/**
 * VULNERABLE login page.
 *
 * Hosts TWO of the lab's deliberate weaknesses:
 *
 *   1. Brute-force vulnerability
 *      - No failed-attempt counter, no lockout, no CAPTCHA, no delay.
 *        An attacker can fire unlimited password guesses.
 *      - Mitigated in: hardened/login.php
 *
 *   2. SQL injection (bonus -- the primary SQLi demo lives in search.php,
 *      but the same mistake is repeated here so login can also be bypassed
 *      with a payload like:  username = admin' --   password = anything)
 *      - Mitigated in: hardened/login.php (PDO prepared statement +
 *        password_verify).
 */

require_once __DIR__ . '/config/db.php';

if (vuln_is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';

// Reset-lab CSRF token (used only by reset.php). This does not change any of
// the intentional vulnerabilities on the login flow itself.
if (empty($_SESSION['reset_token'])) {
    $_SESSION['reset_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // INTENTIONAL VULNERABILITY: SQL Injection via raw concatenation.
    // INTENTIONAL VULNERABILITY: Brute-force allowed -- no rate limiting.
    // Why it is vulnerable: user-supplied strings are spliced directly into
    //   the SQL statement, and there is no failed-attempt tracking at all.
    // Mitigated in: hardened/login.php
    $sql = "SELECT * FROM users
            WHERE username = '$username' AND password = '$password'
            LIMIT 1";

    $result = $conn->query($sql);

    if ($result && $result->num_rows === 1) {
        $user = $result->fetch_assoc();
        $_SESSION['user_id']    = (int)$user['id'];
        $_SESSION['username']   = $user['username'];
        $_SESSION['role']       = $user['role'];
        $_SESSION['department'] = $user['department'];

        // Detailed error messages also leak which field was wrong --
        // again, fixed in hardened/login.php.
        header('Location: dashboard.php');
        exit;
    } else {
        // Verbose error reveals SQL state if the query is malformed; helpful
        // for an attacker probing for SQLi.
        if ($conn->error) {
            $error = 'SQL error: ' . $conn->error;
        } else {
            $error = 'Login failed. Username or password is incorrect.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in &middot; CSecFiles (Vulnerable)</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="auth">
    <div class="auth__card">
        <div class="auth__brand"><span class="dot"></span> CSecFiles</div>
        <p class="auth__subtitle">Sign in to your internal workspace.</p>

        <span class="header__badge header__badge--vuln" style="margin-bottom:12px;display:inline-block;">Vulnerable Lab</span>

        <?php if (($_GET['reset'] ?? '') === '1'): ?>
            <div class="alert" style="margin-bottom:12px;">Lab environment reset. You can sign in with the default accounts.</div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert--error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form method="post" action="login.php" class="form" autocomplete="off">
            <div class="form__row">
                <label class="form__label" for="username">Username</label>
                <input class="input" id="username" name="username" type="text" required>
            </div>
            <div class="form__row">
                <label class="form__label" for="password">Password</label>
                <input class="input" id="password" name="password" type="password" required>
            </div>
            <button class="btn" type="submit">Sign in</button>
        </form>

        <div class="auth__footer">
            New here? <a href="register.php">Create an account</a>
        </div>

        <hr style="margin:18px 0;opacity:.25;">

        <form method="post" action="reset.php" onsubmit="return confirm('Are you sure you want to reset the lab environment? This deletes all user-generated data.');">
            <input type="hidden" name="reset_token" value="<?php echo htmlspecialchars($_SESSION['reset_token']); ?>">
            <button class="btn btn--ghost" type="submit">Reset Lab Environment</button>
        </form>
    </div>
</main>
</body>
</html>
