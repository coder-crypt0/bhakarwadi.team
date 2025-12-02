<?php
// api/index.php - adapter to use your root index.php as a function
// Keep this file very small: it simply hands control to your existing index.php.

chdir(__DIR__ . '/..'); // change working dir to repo root so relative includes still work

// If you rely on DOCUMENT_ROOT or SCRIPT_NAME, you may need to set them.
// Example (only set if you see path issues):
if (!isset($_SERVER['DOCUMENT_ROOT'])) {
    $_SERVER['DOCUMENT_ROOT'] = __DIR__ . '/..';
}

// Include your existing index.php (adjust path if your root file name differs)
require_once __DIR__ . '/../index.php';
