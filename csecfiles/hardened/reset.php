<?php
/**
 * CSecFiles (Hardened build) -- Lab reset endpoint.
 *
 * EDUCATIONAL LAB FEATURE ONLY:
 * This script exists so students/instructors can quickly restore the lab back
 * to its original seeded state during local testing. It must never be deployed
 * to a real environment.
 *
 * Security notes:
 * - POST-only + session token check so it is only reachable from the login page UI.
 * - Safe file deletion: only deletes regular files inside ./uploads/ and never
 *   follows user-controlled paths.
 */
require_once __DIR__ . '/config/db.php';

if (is_logged_in()) {
    forbid('You must be logged out to reset the lab environment.');
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo 'Method Not Allowed';
    exit;
}

$token = (string)($_POST['reset_token'] ?? '');
if (empty($_SESSION['reset_token']) || !hash_equals((string)$_SESSION['reset_token'], $token)) {
    http_response_code(403);
    echo 'Forbidden';
    exit;
}

// Rotate token so a captured form cannot be replayed.
$_SESSION['reset_token'] = bin2hex(random_bytes(32));

$sql_file = realpath(__DIR__ . '/../database/csecfiles.sql');
if ($sql_file === false) {
    http_response_code(500);
    echo 'Seed file not found.';
    exit;
}

// Keep the default seeded documents that exist in the repo + (optionally) .gitkeep.
$seed_upload_files = [
    '.gitkeep',
    'company_policy_2026.txt',
    'q1_engineering_roadmap.txt',
    'john_review.txt',
    'marketing_brief.txt',
    'sara_salary_notes.txt',
    'manager_memo.txt',
];

function clean_uploads(string $uploads_dir, array $keep) : void {
    $uploads_real = realpath($uploads_dir);
    if ($uploads_real === false) return;

    $keep_map = [];
    foreach ($keep as $k) $keep_map[$k] = true;

    $it = new DirectoryIterator($uploads_real);
    foreach ($it as $f) {
        if ($f->isDot()) continue;
        if (!$f->isFile()) continue;

        $name = $f->getFilename();
        if (isset($keep_map[$name])) continue;

        $path = $f->getRealPath();
        if ($path === false) continue;

        // Ensure the resolved path is inside uploads (defense-in-depth).
        if (strpos($path, $uploads_real . DIRECTORY_SEPARATOR) !== 0) continue;

        @unlink($path);
    }
}

clean_uploads(__DIR__ . '/uploads', $seed_upload_files);

// Re-import the seed SQL (drops tables + recreates default users/documents/comments).
$sql = file_get_contents($sql_file);
if ($sql === false) {
    http_response_code(500);
    echo 'Failed to read seed file.';
    exit;
}

try {
    // Use mysqli for the reset import (no user input is used).
    $m = @new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    if ($m->connect_errno) {
        throw new RuntimeException('Database connection failed.');
    }
    $m->set_charset('utf8mb4');

    if (!$m->multi_query($sql)) {
        throw new RuntimeException('Reset failed.');
    }
    do {
        if ($res = $m->store_result()) {
            $res->free();
        }
    } while ($m->more_results() && $m->next_result());

    if ($m->errno) {
        throw new RuntimeException('Reset failed.');
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Reset failed.';
    exit;
}

header('Location: login.php?reset=1');
exit;

