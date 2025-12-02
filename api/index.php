<?php
// api/index.php - adapter
// Behavior:
// 1. If the request targets an existing PHP file under the api/ folder, execute that file.
// 2. Otherwise, serve your root index.php (the website).

// Make repo root the working directory so relative includes in root/index.php work
chdir(__DIR__ . '/..');

if (!isset($_SERVER['DOCUMENT_ROOT'])) {
    $_SERVER['DOCUMENT_ROOT'] = getcwd();
}

// Fetch request path (no query string)
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Normalize multiple slashes
$uri = preg_replace('#/+#', '/', $uri);

// Helper: given a requested path, return absolute php file under api/ if exists
function find_api_php(string $requestPath): ?string {
    // Accept paths that start with /api/ or /API/
    if (preg_match('#^/api/(.*)$#i', $requestPath, $m)) {
        $rel = $m[1]; // e.g. Group18/v1/auth.php or Group18/v1
        // If trailing slash, remove it
        $rel = rtrim($rel, '/');

        // If no extension, try index.php in that folder
        $candidates = [];
        if ($rel === '') {
            $candidates[] = 'index.php';
        } else {
            $candidates[] = $rel;
            $candidates[] = $rel . '/index.php';
        }

        foreach ($candidates as $cand) {
            $full = __DIR__ . '/' . $cand; // __DIR__ == <repo>/api
            // Resolve realpath only if file exists to avoid resolving non-existent paths
            if (file_exists($full) && is_file($full)) {
                $real = realpath($full);
                // Security: ensure file is inside the api/ directory
                if ($real !== false && strpos($real, realpath(__DIR__)) === 0) {
                    // Only allow .php files
                    if (strtolower(pathinfo($real, PATHINFO_EXTENSION)) === 'php') {
                        return $real;
                    }
                }
            }
        }
    }
    return null;
}

// Try to locate an API php file
$apiFile = find_api_php($uri);

if ($apiFile !== null) {
    // Execute the API file
    // Ensure superglobals and server vars are preserved
    // Optionally set SCRIPT_FILENAME and SCRIPT_NAME for compatibility
    $_SERVER['SCRIPT_FILENAME'] = $apiFile;
    // Set SCRIPT_NAME to the path starting from /api/...
    $_SERVER['SCRIPT_NAME'] = preg_replace('#^' . preg_quote(getcwd(), '#') . '#', '', $apiFile);
    require $apiFile;
    exit;
}

// If we get here, no API file matched. Serve your site's root index.php
$rootIndex = __DIR__ . '/../index.php';
if (file_exists($rootIndex)) {
    require $rootIndex;
    exit;
}

// As a fallback, return 404
http_response_code(404);
echo '404: Not Found';
