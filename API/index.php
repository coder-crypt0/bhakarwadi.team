<?php
require_once 'config.php';

header('Content-Type: application/json');
header("Access-Control-Allow-Origin: {$_ENV['CORS_ORIGIN']}");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// API Documentation
$api_info = [
    'name' => 'Tornado Messenger API',
    'version' => '1.0.0',
    'description' => 'REST API for Tornado Messenger - Secure End-to-End Encrypted Messaging',
    'status' => 'active',
    'server_time' => date('c'),
    'endpoints' => [
        'authentication' => [
            'url' => '/auth.php',
            'methods' => ['POST'],
            'description' => 'User authentication and session management',
            'actions' => [
                'register' => [
                    'method' => 'POST',
                    'description' => 'Register a new user account',
                    'required_fields' => ['username', 'password', 'display_name'],
                    'optional_fields' => ['email']
                ],
                'login' => [
                    'method' => 'POST',
                    'description' => 'Login user and create session',
                    'required_fields' => ['username', 'password']
                ],
                'logout' => [
                    'method' => 'POST',
                    'description' => 'Logout user and destroy session',
                    'required_headers' => ['Authorization: Bearer {session_token}']
                ],
                'verify' => [
                    'method' => 'POST',
                    'description' => 'Verify session and get user info',
                    'required_headers' => ['Authorization: Bearer {session_token}']
                ]
            ]
        ],
        'users' => [
            'url' => '/users.php',
            'methods' => ['GET', 'POST', 'PUT', 'DELETE'],
            'description' => 'User profile and account management',
            'authentication' => 'required',
            'actions' => [
                'profile' => [
                    'method' => 'GET',
                    'description' => 'Get user profile information',
                    'parameters' => ['user_id (optional, defaults to current user)']
                ],
                'search' => [
                    'method' => 'GET',
                    'description' => 'Search for users',
                    'required_parameters' => ['q'],
                    'optional_parameters' => ['limit', 'offset']
                ],
                'sessions' => [
                    'method' => 'GET',
                    'description' => 'Get user active sessions'
                ],
                'update_profile' => [
                    'method' => 'POST/PUT',
                    'action' => 'profile',
                    'description' => 'Update user profile',
                    'optional_fields' => ['display_name', 'email', 'status']
                ],
                'change_password' => [
                    'method' => 'POST/PUT',
                    'action' => 'password',
                    'description' => 'Change user password',
                    'required_fields' => ['current_password', 'new_password']
                ],
                'delete_session' => [
                    'method' => 'DELETE',
                    'action' => 'session',
                    'description' => 'Delete user session',
                    'required_parameters' => ['session_id']
                ],
                'delete_account' => [
                    'method' => 'DELETE',
                    'action' => 'account',
                    'description' => 'Delete user account',
                    'required_fields' => ['password']
                ]
            ]
        ],
        'messages' => [
            'url' => '/messages.php',
            'methods' => ['GET', 'POST', 'DELETE'],
            'description' => 'Messaging and conversation management',
            'authentication' => 'required',
            'actions' => [
                'send' => [
                    'method' => 'POST',
                    'action' => 'send',
                    'description' => 'Send a message',
                    'required_fields' => ['receiver_id', 'content'],
                    'optional_fields' => ['message_type', 'encryption_key', 'file_id']
                ],
                'conversation' => [
                    'method' => 'GET',
                    'action' => 'conversation',
                    'description' => 'Get messages in conversation with specific user',
                    'required_parameters' => ['user_id'],
                    'optional_parameters' => ['limit', 'offset', 'before']
                ],
                'conversations' => [
                    'method' => 'GET',
                    'action' => 'conversations',
                    'description' => 'Get list of all conversations',
                    'optional_parameters' => ['limit', 'offset']
                ],
                'mark_read' => [
                    'method' => 'POST',
                    'action' => 'read',
                    'description' => 'Mark messages as read',
                    'options' => 'Either message_ids OR other_user_id',
                    'optional_fields' => ['message_ids', 'other_user_id']
                ],
                'delete' => [
                    'method' => 'DELETE',
                    'description' => 'Delete a message',
                    'required_parameters' => ['message_id']
                ],
                'statistics' => [
                    'method' => 'GET',
                    'action' => 'stats',
                    'description' => 'Get message statistics for current user'
                ]
            ]
        ],
        'files' => [
            'url' => '/upload.php',
            'methods' => ['GET', 'POST', 'DELETE'],
            'description' => 'File upload and management',
            'authentication' => 'required',
            'actions' => [
                'upload' => [
                    'method' => 'POST',
                    'action' => 'upload',
                    'description' => 'Upload a file',
                    'content_type' => 'multipart/form-data',
                    'required_fields' => ['file']
                ],
                'download' => [
                    'method' => 'GET',
                    'action' => 'download',
                    'description' => 'Download a file',
                    'required_parameters' => ['file_id']
                ],
                'list' => [
                    'method' => 'GET',
                    'action' => 'list',
                    'description' => 'List user files',
                    'optional_parameters' => ['limit', 'offset']
                ],
                'delete' => [
                    'method' => 'DELETE',
                    'description' => 'Delete a file',
                    'required_parameters' => ['file_id']
                ]
            ]
        ]
    ],
    'authentication' => [
        'type' => 'Bearer Token',
        'header' => 'Authorization: Bearer {session_token}',
        'description' => 'Most endpoints require authentication via session token obtained from login'
    ],
    'rate_limiting' => [
        'auth_endpoints' => '10 requests per 5 minutes',
        'user_endpoints' => '50 requests per 5 minutes',
        'message_endpoints' => '100 requests per 5 minutes',
        'upload_endpoints' => '20 requests per 5 minutes'
    ],
    'response_format' => [
        'success' => [
            'success' => true,
            'data' => '...',
            'message' => 'Optional success message'
        ],
        'error' => [
            'success' => false,
            'error' => 'Error description'
        ]
    ],
    'file_upload_limits' => [
        'max_file_size' => '50MB',
        'allowed_types' => [
            'images' => ['jpeg', 'jpg', 'png', 'gif', 'webp'],
            'documents' => ['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx'],
            'archives' => ['zip'],
            'data' => ['json', 'csv']
        ]
    ],
    'security_features' => [
        'encryption' => 'End-to-end encryption support',
        'tor_integration' => 'Anonymous access via TOR network',
        'rate_limiting' => 'Request rate limiting per IP',
        'session_management' => 'Secure session tokens with expiration',
        'input_validation' => 'Comprehensive input validation and sanitization',
        'file_security' => 'File type validation and malware scanning'
    ],
    'error_codes' => [
        200 => 'Success',
        400 => 'Bad Request - Invalid parameters or data',
        401 => 'Unauthorized - Authentication required or invalid',
        403 => 'Forbidden - Access denied',
        404 => 'Not Found - Resource not found',
        405 => 'Method Not Allowed',
        413 => 'Payload Too Large - File too big',
        429 => 'Too Many Requests - Rate limit exceeded',
        500 => 'Internal Server Error'
    ],
    'examples' => [
        'register_user' => [
            'url' => 'POST /auth.php?action=register',
            'headers' => [
                'Content-Type: application/json',
                'X-API-Key: {your_api_key}'
            ],
            'body' => [
                'username' => 'john_doe',
                'password' => 'SecurePass123!',
                'display_name' => 'John Doe',
                'email' => 'john@example.com'
            ]
        ],
        'login' => [
            'url' => 'POST /auth.php?action=login',
            'headers' => [
                'Content-Type: application/json',
                'X-API-Key: {your_api_key}'
            ],
            'body' => [
                'username' => 'john_doe',
                'password' => 'SecurePass123!'
            ]
        ],
        'send_message' => [
            'url' => 'POST /messages.php?action=send',
            'headers' => [
                'Content-Type: application/json',
                'Authorization: Bearer {session_token}',
                'X-API-Key: {your_api_key}'
            ],
            'body' => [
                'receiver_id' => 'user123456789abcdef',
                'content' => 'Hello, this is a secure message!',
                'message_type' => 'text',
                'encryption_key' => 'optional_encryption_key'
            ]
        ],
        'upload_file' => [
            'url' => 'POST /upload.php?action=upload',
            'headers' => [
                'Authorization: Bearer {session_token}',
                'X-API-Key: {your_api_key}'
            ],
            'body' => 'multipart/form-data with file field'
        ]
    ]
];

// Check if specific endpoint documentation is requested
$endpoint = $_GET['endpoint'] ?? null;

if ($endpoint && isset($api_info['endpoints'][$endpoint])) {
    $response = [
        'success' => true,
        'endpoint' => $endpoint,
        'documentation' => $api_info['endpoints'][$endpoint]
    ];
} else {
    $response = [
        'success' => true,
        'api' => $api_info
    ];
}

echo json_encode($response, JSON_PRETTY_PRINT);
?>
