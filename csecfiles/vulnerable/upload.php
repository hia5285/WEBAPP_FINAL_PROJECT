<?php
/**
 * VULNERABLE upload page.
 *
 * Accepts a file and creates a document row. Kept simple: this page is not
 * the focus of any of the five lab vulnerabilities, but it carries the same
 * sloppy practices (raw concatenation, no MIME / extension allowlist) so the
 * contrast with hardened/upload.php is informative.
 */

require_once __DIR__ . '/config/db.php';
vuln_require_login();

$current_user = vuln_current_user($conn);
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title       = $_POST['title']        ?? '';
    $description = $_POST['description']  ?? '';
    $department  = $_POST['department']   ?? $current_user['department'];
    $visibility  = $_POST['visibility']   ?? 'private';

    if ($title === '' || empty($_FILES['document']['name'])) {
        $error = 'Title and file are required.';
    } elseif ($_FILES['document']['error'] !== UPLOAD_ERR_OK) {
        $error = 'Upload failed (PHP error code ' . (int)$_FILES['document']['error'] . ').';
    } else {
        // INTENTIONAL VULNERABILITY (secondary): no extension/MIME allowlist
        // and the original filename is preserved as-is. Mitigated in
        // hardened/upload.php (random server filename + extension allowlist).
        $original = basename($_FILES['document']['name']);
        $dest     = __DIR__ . '/uploads/' . $original;

        if (!move_uploaded_file($_FILES['document']['tmp_name'], $dest)) {
            $error = 'Could not save the uploaded file.';
        } else {
            $owner_id = (int)$current_user['id'];
            $rel_path = 'uploads/' . $original;

            // INTENTIONAL VULNERABILITY: SQL injection via raw concatenation.
            $sql = "INSERT INTO documents (title, description, file_name, file_path, owner_id, department, visibility)
                    VALUES ('$title', '$description', '$original', '$rel_path', $owner_id, '$department', '$visibility')";

            if ($conn->query($sql)) {
                $success = 'Document uploaded.';
            } else {
                $error = 'DB error: ' . $conn->error;
            }
        }
    }
}

$APP_VARIANT = 'vulnerable';
$PAGE_TITLE  = 'Upload document';
require __DIR__ . '/includes/header.php';
require __DIR__ . '/includes/sidebar.php';
?>

<main class="app__main">
    <h1>Upload document</h1>
    <p class="muted">Add a new document to your CSecFiles workspace.</p>

    <?php if ($error): ?>
        <div class="alert alert--error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert--success"><?php echo htmlspecialchars($success); ?></div>
    <?php endif; ?>

    <div class="card">
        <form class="form form--wide" method="post" action="upload.php" enctype="multipart/form-data">
            <div class="form__row">
                <label class="form__label" for="title">Title</label>
                <input class="input" id="title" name="title" type="text" required>
            </div>
            <div class="form__row">
                <label class="form__label" for="description">Description</label>
                <textarea class="textarea" id="description" name="description"></textarea>
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
                <div class="form__hint">Any file type accepted in this lab build.</div>
            </div>
            <button class="btn" type="submit">Upload</button>
        </form>
    </div>
</main>

<?php require __DIR__ . '/includes/footer.php'; ?>
