<?php
/**
 * Shared left sidebar navigation.
 * Active link highlighting happens client-side in app.js.
 */
?>
<aside class="app__sidebar">
    <div class="sidebar__brand">
        <span class="dot"></span>
        <span>CSecFiles</span>
    </div>
    <nav class="sidebar__nav">
        <div class="sidebar__nav-section">Workspace</div>
        <a href="dashboard.php">Dashboard</a>
        <a href="upload.php">Upload document</a>
        <a href="search.php">Search documents</a>

        <div class="sidebar__nav-section">Help</div>
        <a href="include_page.php?page=about">About</a>
        <a href="include_page.php?page=help">Help</a>
        <a href="include_page.php?page=policy">Policy</a>

        <div class="sidebar__nav-section">Account</div>
        <a href="logout.php">Log out</a>
    </nav>
</aside>
