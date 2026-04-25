<?php
/**
 * HARDENED registration page.
 *
 * Mitigations applied (matched against vulnerable/register.php):
 *   1. SQL injection      MITIGATION: PDO prepared statement.
 *   2. Plaintext passwords MITIGATION: password_hash(PASSWORD_DEFAULT).
 *   3. Field validation   MITIGATION: length / email / username pattern checks.
 *   4. Account collision  MITIGATION: pre-check via prepared SELECT, then
 *                                     surface a single neutral error.
 */

require_once __DIR__ . '/config/db.php';

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$error   = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name  = trim((string)($_POST['full_name']  ?? ''));
    $email      = trim((string)($_POST['email']      ?? ''));
    $username   = trim((string)($_POST['username']   ?? ''));
    $password   = (string)($_POST['password']        ?? '');
    $department = trim((string)($_POST['department'] ?? 'General'));

    $allowed_departments = ['Engineering','Marketing','IT','Sales','HR','General'];

    if ($full_name === '' || $email === '' || $username === '' || $password === '') {
        $error = 'All fields are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please provide a valid email address.';
    } elseif (!preg_match('/^[A-Za-z0-9_.-]{3,60}$/', $username)) {
        $error = 'Username must be 3-60 characters: letters, digits, dot, dash or underscore.';
    } elseif (strlen($password) < 8 || strlen($password) > 200) {
        $error = 'Password must be 8 to 200 characters.';
    } elseif (!in_array($department, $allowed_departments, true)) {
        $error = 'Invalid department selection.';
    } else {
        $check = $pdo->prepare(
            "SELECT id FROM users WHERE username = :u OR email = :e LIMIT 1"
        );
        $check->execute([':u' => $username, ':e' => $email]);

        if ($check->fetch()) {
            $error = 'Username or email already taken.';
        } else {
            // MITIGATION: bcrypt via password_hash, prepared INSERT.
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $ins = $pdo->prepare(
                "INSERT INTO users (full_name, email, username, password, role, department)
                 VALUES (:f, :e, :u, :p, 'employee', :d)"
            );
            $ins->execute([
                ':f' => $full_name,
                ':e' => $email,
                ':u' => $username,
                ':p' => $hash,
                ':d' => $department,
            ]);
            log_activity($pdo, (int)$pdo->lastInsertId(),
                'register', 'New employee registration');
            $success = 'Account created. You can now sign in.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Register &middot; CSecFiles (Hardened)</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="auth">
    <div class="auth__card">
        <div class="auth__brand"><span class="dot"></span> CSecFiles</div>
        <p class="auth__subtitle">Create your CSecFiles account.</p>

        <span class="header__badge header__badge--hardened" style="margin-bottom:12px;display:inline-block;">Hardened</span>

        <?php if ($error): ?>
            <div class="alert alert--error"><?php echo e($error); ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert--success"><?php echo e($success); ?></div>
        <?php endif; ?>

        <form method="post" action="register.php" class="form" autocomplete="off">
            <div class="form__row">
                <label class="form__label" for="full_name">Full name</label>
                <input class="input" id="full_name" name="full_name" type="text" required maxlength="150">
            </div>
            <div class="form__row">
                <label class="form__label" for="email">Work email</label>
                <input class="input" id="email" name="email" type="email" required maxlength="190">
            </div>
            <div class="form__row">
                <label class="form__label" for="username">Username</label>
                <input class="input" id="username" name="username" type="text" required maxlength="60"
                       pattern="[A-Za-z0-9_.\-]{3,60}">
            </div>
            <div class="form__row">
                <label class="form__label" for="password">Password</label>
                <input class="input" id="password" name="password" type="password" required minlength="8" maxlength="200">
                <div class="form__hint">At least 8 characters.</div>
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
