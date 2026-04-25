<?php
/**
 * HARDENED upload page.
 *
 * Mitigations vs vulnerable/upload.php:
 *   - PDO prepared INSERT (no SQLi).
 *   - Server-side extension allowlist.
 *   - Random server-side filename, original name remembered separately.
 *   - Department / visibility constrained to known enum values.
 */

require_once __DIR__ . '/config/db.php';
require_login();

$current_user = current_user($pdo);
$error   = '';
$success = '';

const MAX_UPLOAD_BYTES   = 10 * 1024 * 1024; // 10 MB
const ALLOWED_EXTENSIONS = ['pdf','txt','png','jpg','jpeg','docx','xlsx','csv','md'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title       = trim((string)($_POST['title']        ?? ''));
    $description = trim((string)($_POST['description']  ?? ''));
    $department  = trim((string)($_POST['department']   ?? $current_user['department']));
    $visibility  = trim((string)($_POST['visibility']   ?? 'private'));

    $allowed_departments = ['Engineering','Marketing','IT','Sales','HR','General'];
    $allowed_visibility  = ['private','department','public'];

    if ($title === '') {
        $error = 'Title is required.';
    } elseif (mb_strlen($title) > 200 || mb_strlen($description) > 5000) {
        $error = 'Title or description is too long.';
    } elseif (!in_array($department, $allowed_departments, true)) {
        $error = 'Invalid department.';
    } elseif (!in_array($visibility, $allowed_visibility, true)) {
        $error = 'Invalid visibility.';
    } elseif (empty($_FILES['document']['name'])) {
        $error = 'Please select a file to upload.';
    } elseif ($_FILES['document']['error'] !== UPLOAD_ERR_OK) {
        $error = 'Upload failed.';
    } elseif ($_FILES['document']['size'] > MAX_UPLOAD_BYTES) {
        $error = 'File exceeds the 10 MB limit.';
    } else {
        $original = basename($_FILES['document']['name']);
        $ext = strtolower(pathinfo($original, PATHINFO_EXTENSION));

        if (!in_array($ext, ALLOWED_EXTENSIONS, true)) {
            $error = 'File type ".' . e($ext) . '" is not allowed.';
        } else {
            // MITIGATION: random server-side name avoids overwrite, path
            //             traversal via crafted filenames, and keeps the
            //             original extension constrained by the allowlist.
            $safe_name = bin2hex(random_bytes(12)) . '.' . $ext;
            $rel_path  = 'uploads/' . $safe_name;
            $abs_path  = __DIR__ . '/' . $rel_path;

            if (!move_uploaded_file($_FILES['document']['tmp_name'], $abs_path)) {
                $error = 'Could not save the uploaded file.';
            } else {
                // MITIGATION: prepared statement.
                $stmt = $pdo->prepare(
                    "INSERT INTO documents
                        (title, description, file_name, file_path,
                         owner_id, department, visibility)
                     VALUES (:t, :d, :fn, :fp, :o, :dep, :v)"
                );
                $stmt->execute([
                    ':t'   => $title,
                    ':d'   => $description,
                    ':fn'  => $original,
                    ':fp'  => $rel_path,
                    ':o'   => (int)$current_user['id'],
                    ':dep' => $department,
                    ':v'   => $visibility,
                ]);
                log_activity($pdo, (int)$current_user['id'],
                    'upload', 'doc=' . $pdo->lastInsertId());
                $success = 'Document uploaded.';
            }
        }
    }
}

$APP_VARIANT = 'hardened';
$PAGE_TITLE  = 'Upload document';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <h1>Upload document</h1>
    <p class="muted">Add a new document to your CSecFiles workspace.</p>

    <?php if ($error): ?>
        <div class="alert alert--error"><?php echo e($error); ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert--success"><?php echo e($success); ?></div>
    <?php endif; ?>

    <div class="card">
        <form class="form form--wide" method="post" action="upload.php" enctype="multipart/form-data">
            <div class="form__row">
                <label class="form__label" for="title">Title</label>
                <input class="input" id="title" name="title" type="text" required maxlength="200">
            </div>
            <div class="form__row">
                <label class="form__label" for="description">Description</label>
                <textarea class="textarea" id="description" name="description" maxlength="5000"></textarea>
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
            <div class="form__row">
                <label class="form__label" for="visibility">Visibility</label>
                <select class="select" id="visibility" name="visibility">
                    <option value="private">Private (only me)</option>
                    <option value="department">Department</option>
                    <option value="public">Public (everyone)</option>
                </select>
            </div>
            <div class="form__row">
                <label class="form__label" for="document">File</label>
                <input class="input" id="document" name="document" type="file" required>
                <div class="form__hint">Allowed: <?php echo e(implode(', ', ALLOWED_EXTENSIONS)); ?>. Max 10 MB.</div>
            </div>
            <button class="btn" type="submit">Upload</button>
        </form>
    </div>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
