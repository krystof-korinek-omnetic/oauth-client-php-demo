<?php
// A minimal, self-contained demo showing: sign-in link, callback handler, refresh token, and user info fetch.
session_start();

const OAUTH_TOKEN_PATH = '/dms/v1/auth/oauth/token';
const OAUTH_CALLBACK_PATH = 'callback';

// Configuration (env overrides with sensible defaults)
$clientId = getenv('OAUTH_CLIENT_ID') ?: '';
$clientSecret = getenv('OAUTH_CLIENT_SECRET') ?: '';
$apiUrl = getenv('OAUTH_AUTH_SERVER') ?: 'https://api.dev.omnetic.dev';
$authorizationEndpointUrl = getenv('OAUTH_AUTHORIZATION_SERVER') ?: 'https://iam.dev.omnetic.dev';
$redirectUri = 'http://' . $_SERVER['HTTP_HOST'] . '/' . OAUTH_CALLBACK_PATH;
// Optional workspace can be provided via env; if set, it takes precedence over callback query param
$envWorkspace = getenv('OAUTH_WORKSPACE') ?: null;

// Keep a CSRF state in session; generate if missing.
if (!isset($_SESSION['state'])) {
    $_SESSION['state'] = bin2hex(random_bytes(10));
}

// Form-encoded POST helper (for OAuth token endpoint)
function form_post(string $url, array $payload, array $extraHeaders = []): array
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $defaultHeaders = [
        'Accept: application/json',
        'Content-Type: application/x-www-form-urlencoded',
    ];
    $headers = array_values(array_unique(array_merge($defaultHeaders, $extraHeaders)));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload));

    $raw = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $body = $raw !== false ? json_decode($raw, true, 512, JSON_THROW_ON_ERROR) : null;
    return [$status, $body];
}

function oauth_token(string $apiUrl, array $payload, array $headers = []): array
{
    // OAuth token endpoint expects application/x-www-form-urlencoded
    return form_post($apiUrl . OAUTH_TOKEN_PATH, $payload, $headers);
}

function print_block(string $title, $data): void
{
    echo sprintf('<p><strong>%s</strong> <pre>%s</pre></p>', htmlspecialchars($title), print_r($data, true));
}

// Simple router based on path
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';

switch ($path) {
    case '/logout':
        // Logging out = drop tokens from session
        unset($_SESSION['access_token'], $_SESSION['refresh_token'], $_SESSION['workspace']);
        echo '<p>You are logged out.</p>';
        break;

    case '/refresh-token':
        if (isset($_SESSION['refresh_token'])) {
            // Resolve workspace: env wins; fallback to one remembered from callback
            $workspace = $envWorkspace ?: ($_SESSION['workspace'] ?? null);
            $headers = [];
            if ($workspace) {
                $headers[] = 'x-workspace: ' . $workspace;
            }

            $payload1 = [
                'client_id' => $clientId,
                'refresh_token' => $_SESSION['refresh_token'],
                'grant_type' => 'refresh_token',
            ];
            if ($clientSecret) {
                $payload1['client_secret'] = $clientSecret;
            }
            [$status, $tokenData] = oauth_token($apiUrl, $payload1, $headers);

            if ($status === 200 && is_array($tokenData)) {
                $_SESSION['access_token'] = $tokenData['access_token'] ?? null;
                $_SESSION['refresh_token'] = $tokenData['refresh_token'] ?? null;
            }
            print_block('Refresh token response:', $tokenData);
        } else {
            echo '<p>No refresh token in session.</p>';
        }
        break;

    case '/' . OAUTH_CALLBACK_PATH:
        // Redirect target: exchange authorization code for tokens
        if (isset($_GET['code'], $_GET['state'])) {
            // Basic CSRF check
            if (!hash_equals($_SESSION['state'] ?? '', (string)$_GET['state'])) {
                die('States do not match!!');
            }

            $workspace = $envWorkspace ?: ($_GET['workspace'] ?? null);
            $headers = [];
            if ($workspace) {
                $headers[] = 'x-workspace: ' . $workspace;
            }

            $payload = [
                'code' => (string)$_GET['code'],
                'client_id' => $clientId,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ];
            if ($clientSecret) {
                $payload['client_secret'] = $clientSecret;
            }
            [$status, $tokenData] = oauth_token($apiUrl, $payload, $headers);

            if ($status === 200 && is_array($tokenData)) {
                $_SESSION['access_token'] = $tokenData['access_token'] ?? null;
                $_SESSION['refresh_token'] = $tokenData['refresh_token'] ?? null;

                if (!$envWorkspace) {
                    $_SESSION['workspace'] = $workspace;
                }
            }
            print_block('Access token response:', $tokenData);
        }
        break;

    default:
        // Home page: if authenticated, show user info
        if (isset($_SESSION['access_token'])) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $apiUrl . '/dms/v1/user/info');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "Authorization: Bearer {$_SESSION['access_token']}",
                'Accept: application/json',
                'Content-type: application/json',
                "x-workspace: $currentWorkspace",
            ]);
            $raw = curl_exec($ch);
            $decoded = $raw !== false ? json_decode($raw, true, 512, JSON_THROW_ON_ERROR) : null;

            if (is_array($decoded)) {
                $summary = [
                    'id' => $decoded['id'] ?? null,
                    'email' => $decoded['email'] ?? null,
                    'firstName' => $decoded['firstName'] ?? null,
                    'lastName' => $decoded['lastName'] ?? null,
                ];
                print_block('User info (summary):', $summary);
            }

            print_block('User info:', $decoded);
        }
}

$currentWorkspace = $envWorkspace ?: ($_SESSION['workspace'] ?? null);

if ($currentWorkspace) {
    echo "<p><em>Workspace:</em> $currentWorkspace</p>";
}

if (!isset($_SESSION['access_token'], $_SESSION['refresh_token'])) {
    $signInUrl = $authorizationEndpointUrl
        . '?response_type=code'
        . '&state=' . urlencode($_SESSION['state'])
        . '&client_id=' . urlencode($clientId)
        . '&redirect_uri=' . urlencode($redirectUri);

    // Workspace can be specified beforehand meaning a user is going to be signed in to that workspace
    if ($envWorkspace) {
        $signInUrl .= '&workspace=' . urlencode($envWorkspace);
    }
    echo "<p><a href='$signInUrl'>Sign In</a></p>";
}

echo '<p><a href="/">Home page</a></p>';

if (isset($_SESSION['refresh_token'])) {
    echo '<p><a href="/refresh-token">Refresh token</a></p>';
}

if (isset($_SESSION['access_token'])) {
    echo '<p><a href="/logout">Log out</a></p>';
}
