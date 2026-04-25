<?php
/**
 * Shared page header.
 *
 * Each page should set, BEFORE including this file:
 *   $APP_VARIANT   -- 'vulnerable' or 'hardened'
 *   $PAGE_TITLE    -- short title shown in <title> and the top bar
 *   (optional) $current_user array with at least 'username' and 'role'
 */

if (!isset($APP_VARIANT)) { $APP_VARIANT = 'vulnerable'; }
if (!isset($PAGE_TITLE))  { $PAGE_TITLE  = 'CSecFiles'; }

$badge_class = $APP_VARIANT === 'hardened' ? 'header__badge--hardened' : 'header__badge--vuln';
$badge_text  = $APP_VARIANT === 'hardened' ? 'Hardened' : 'Vulnerable Lab';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo htmlspecialchars($PAGE_TITLE, ENT_QUOTES, 'UTF-8'); ?> &middot; CSecFiles</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<div class="app">
    <header class="app__header">
        <div class="header">
            <div class="header__title"><?php echo htmlspecialchars($PAGE_TITLE, ENT_QUOTES, 'UTF-8'); ?></div>
            <div class="header__right">
                <span class="header__badge <?php echo $badge_class; ?>"><?php echo $badge_text; ?></span>
                <?php if (!empty($current_user)): ?>
                    <span class="header__user">
                        Signed in as <strong><?php echo htmlspecialchars($current_user['username'], ENT_QUOTES, 'UTF-8'); ?></strong>
                        (<?php echo htmlspecialchars($current_user['role'], ENT_QUOTES, 'UTF-8'); ?>)
                    </span>
                    <a class="btn btn--ghost" href="logout.php">Log out</a>
                <?php endif; ?>
            </div>
        </div>
    </header>
