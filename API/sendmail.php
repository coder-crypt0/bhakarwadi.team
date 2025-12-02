<?php
// sendmail.php
// PHP REST API to send mail using PHPMailer (GET or POST).
// Follows the API spec in the uploaded documentation. :contentReference[oaicite:1]{index=1}

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
// Allow CORS (adjust origin in production)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ---- Configuration (use environment variables in production) ----
$EXPECTED_API_KEY = 'dGhlZ3JvdXAxMQ=='; // from your docs (Base64 'thegroup11') :contentReference[oaicite:2]{index=2}

// SMTP credentials: prefer environment variables, fallback to the values you provided.
// IMPORTANT: don't hardcode production passwords in source control.
$smtpHost = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
$smtpPort = getenv('SMTP_PORT') ?: '587';
$smtpUsername = getenv('SMTP_USER') ?: 'no.reply.01.coding@gmail.com';
$smtpPassword = getenv('SMTP_PASS') ?: 'xmel tbor nybn fznj'; // Replace with env var in production
$smtpSecure = getenv('SMTP_SECURE') ?: 'tls'; // 'tls' for STARTTLS

// ---- Input retrieval & validation ----
// Accept both GET and POST (URL query or form/json body)
$method = $_SERVER['REQUEST_METHOD'];
$input = [];

// If JSON body, decode it
$raw = file_get_contents('php://input');
if ($raw !== '' && stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
    $json = json_decode($raw, true);
    if (is_array($json)) {
        $input = $json;
    }
}

// Merge GET/POST parameters and decoded json (json overrides query params)
$params = array_merge($_GET ?? [], $_POST ?? [], $input);

// Required params
$api_key = $params['api_key'] ?? null;
$to      = $params['to']      ?? $params['to_address'] ?? null;
$subject = $params['subject'] ?? $params['subj'] ?? $params['subj ect'] ?? $params['subj ect'] ?? $params['subj ect'] ?? $params['subj ect'] ?? null; // tries to tolerate weird keys
$message = $params['message'] ?? $params['msg'] ?? null;

// Basic checks
if (!$api_key || $api_key !== $EXPECTED_API_KEY) {
    http_response_code(403);
    echo json_encode(['error' => 'Invalid API Key']);
    exit;
}

if (!$to || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid or missing "to" email address']);
    exit;
}

if (!$subject) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing "subject" parameter']);
    exit;
}

if (!$message) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing "message" parameter']);
    exit;
}

// Optional: sanitize content (basic)
$subject = trim(substr($subject, 0, 255));
$message = trim($message);

// ---- PHPMailer send ----
require __DIR__ . '/vendor/autoload.php'; // composer autoload

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$mail = new PHPMailer(true);

try {
    // Server settings
    $mail->isSMTP();
    $mail->Host       = $smtpHost;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtpUsername;
    $mail->Password   = $smtpPassword;
    // Use STARTTLS if port 587
    if (strtolower($smtpSecure) === 'tls' || $smtpPort == 587) {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    } elseif (strtolower($smtpSecure) === 'ssl' || $smtpPort == 465) {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    } else {
        // Fallback: no encryption (not recommended)
        $mail->SMTPSecure = false;
    }
    $mail->Port       = (int)$smtpPort;

    // Recipients
    $mail->setFrom($smtpUsername, 'No Reply');
    $mail->addAddress($to);

    // Content
    $mail->isHTML(false); // plaintext; switch to true if sending HTML
    $mail->Subject = $subject;
    $mail->Body    = $message;

    if (!$mail->send()) {
        // $mail->send() throws on error when exceptions enabled, but handle just in case
        http_response_code(500);
        echo json_encode(['error' => 'Email could not be sent. Error: ' . $mail->ErrorInfo]);
        exit;
    }

    // Success
    http_response_code(200);
    echo json_encode(['success' => 'Email sent successfully']);
    exit;
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Mailer Error: ' . $e->getMessage()]);
    exit;
}
