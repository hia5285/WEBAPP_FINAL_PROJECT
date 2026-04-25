<?php
/**
 * VULNERABLE registration page.
 *
 * Stores the chosen password as plaintext (lab-only) and uses raw string
 * concatenation in the INSERT (a third secondary SQLi sink).
 *
 * Mitigated in: hardened/register.php (PDO prepared statements + password_hash
 * + length / email validation).
 */

require_once __DIR__ . '/config/db.php';

if (vuln_is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$error   = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name  = $_POST['full_name']  ?? '';
    $email      = $_POST['email']      ?? '';
    $username   = $_POST['username']   ?? '';
    $password   = $_POST['password']   ?? '';
    $department = $_POST['department'] ?? 'General';

    if ($full_name === '' || $email === '' || $username === '' || $password === '') {
        $error = 'All fields are required.';
    } else {
        // INTENTIONAL VULNERABILITY: SQL injection via raw concatenation.
        // INTENTIONAL VULNERABILITY: Password stored in plaintext.
        // Mitigated in: hardened/register.php
        $sql = "INSERT INTO users (full_name, email, username, password, role, department)
                VALUES ('$full_name', '$email', '$username', '$password', 'employee', '$department')";

        if ($conn->query($sql)) {
            $success = 'Account created. You can now sign in.';
        } else {
            $error = 'Could not create account: ' . $conn->error;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Register &middot; CSecFiles (Vulnerable)</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="auth">
    <div class="auth__card">
        <div class="auth__brand"><span class="dot"></span> CSecFiles</div>
        <p class="auth__subtitle">Create your CSecFiles account.</p>

        <span class="header__badge header__badge--vuln" style="margin-bottom:12px;display:inline-block;">Vulnerable Lab</span>

        <?php if ($error): ?>
            <div class="alert alert--error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert--success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <form method="post" action="register.php" class="form" autocomplete="off">
            <div class="form__row">
                <label class="form__label" for="full_name">Full name</label>
                <input class="input" id="full_name" name="full_name" type="text" required>
            </div>
            <div class="form__row">
                <label class="form__label" for="email">Work email</label>
                <input class="input" id="email" name="email" type="email" required>
            </div>
            <div class="form__row">
                <label class="form__label" for="username">Username</label>
                <input class="input" id="username" name="username" type="text" required>
            </div>
            <div class="form__row">
                <label class="form__label" for="password">Password</label>
                <input class="input" id="password" name="password" type="password" required>
            </div>
            <div class="form__row">
                <label class="form__label" for="department">Department</label>
                <select class="select" id="department" name="department">
                    <option>Engineering</option>
                    <option>Marketing</option>
                    <option>IT</option>
                    <option>Sales</option>
                    <option>HR</option>
                    <option>General</option>
                </select>
            </div>
            <button class="btn" type="submit">Create account</button>
        </form>

        <div class="auth__footer">
            Already have an account? <a href="login.php">Sign in</a>
        </div>
    </div>
</main>
</body>
</html>
