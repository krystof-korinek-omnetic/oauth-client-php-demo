# OAuth 2 client for OMNETIC DMS

Minimal PHP demo of OAuth 2.0 with OMNETIC DMS (Authorization Code flow). It shows how your app (the client) can obtain
and use access tokens without handling user passwords.

## OAuth 2

[OAuth 2.0](https://oauth.net/2/) lets a user grant a third‑party application limited access to their resources without
sharing a password. After authentication and consent, the app receives short‑lived access tokens (and optionally refresh
tokens) using a standardized grant such as the Authorization Code flow. Those tokens are sent with API requests (for
example, in the `Authorization: Bearer <token>` header).

## What changed

This repository uses the current OAuth flow for OMNETIC DMS, replacing the legacy OAuth flow used in the previous
versions of this demo.

- Uses the official OAuth 2.0 request/response bodies for authorization code and refresh token flows.
- OAuth login happens in the IAM app. The returned authorization `code` is exchanged in DMS for the same `access_token`/
  `refresh_token` you would receive from the normal login endpoint. Previously, a special OAuth access token was used.
- Workspace handling has changed:
    - You can still pass `workspace` as a query parameter to the authorization URL, but it is now optional.
    - If omitted, the workspace may be determined during the login process and returned to your callback URL as
      `?workspace=...`.
    - For API calls the `x-workspace` HTTP header must be provided. At minimum, it must be sent when refreshing an
      access token. If your access token is still valid and already encodes the workspace, the header can be omitted for
      non‑refresh calls.
- Legacy flows are being discontinued; only the new flow used in this repository is supported going forward.
- The new OAuth process newly
  supports [PKCE flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce)

## Quick start

1) Get a client id and (optionally) a client secret from the service provider.

2) Start the PHP built‑in server with your credentials (adjust values as needed):

```sh
OAUTH_CLIENT_ID='<my-client-id>' \
OAUTH_CLIENT_SECRET='<my-client-secret>' \
php -S 0.0.0.0:8080 -t ./demo
```

3) Open `http://localhost:8080` in your browser.

> [!IMPORTANT]
> Remeber to register your `redirect_uri` in the DMS OAuth client's allowed redirect URIs. Otherwise, the login will
> fail.

## Environment variables

| Environment Variable         | Required | Description                                                                                            | Default                       |
|------------------------------|----------|--------------------------------------------------------------------------------------------------------|-------------------------------|
| `OAUTH_CLIENT_ID`            | Yes      | OAuth client identifier.                                                                               | —                             |
| `OAUTH_CLIENT_SECRET`        | No       | OAuth client secret; required depending on client configuration.                                       | —                             |
| `OAUTH_AUTH_SERVER`          | No       | Base URL of the DMS API.                                                                               | `https://api.dev.omnetic.dev` |
| `OAUTH_AUTHORIZATION_SERVER` | No       | Base URL of the IAM authorization server.                                                              | `https://iam.dev.omnetic.dev` |
| `OAUTH_WORKSPACE`            | No       | Optional preferred workspace. If set, it takes precedence over the workspace returned to the callback. | —                             |

## Workspace rules

- You may preselect a workspace by adding `&workspace=<id>` to the authorization URL. The demo does this automatically
  when `OAUTH_WORKSPACE` is set.
- If no workspace is provided, IAM may determine it during login and append `?workspace=<id>` to the callback.
- For API calls you must include the `x-workspace` header, at least for refresh token requests.

## Endpoints

- **Authorization endpoint (IAM)**
    - Method: `GET`
    - Base: `{OAUTH_AUTHORIZATION_SERVER}` (e.g., `https://iam.dev.omnetic.dev`)
    - Query params: `response_type=code`, `client_id`, `redirect_uri`, `state`, optional `workspace`
    - Purpose: Redirect user to sign in and consent; returns `code` (and optional `workspace`) to your `redirect_uri`.

- **Token endpoint (DMS)**
    - Method: `POST` (form‑encoded)
    - URL: `{OAUTH_AUTH_SERVER}/dms/v1/auth/oauth/token` (e.g., `https://api.dev.omnetic.dev/dms/v1/auth/oauth/token`)
    - Grants:
        - `authorization_code`: fields `code`, `client_id`, `redirect_uri`, optional `client_secret`
        - `refresh_token`: fields `refresh_token`, `client_id`, optional `client_secret`
    - Headers: include `x-workspace: <workspace>` — required for refresh requests; recommended for others unless the
      access token already carries workspace information.

## Using the access token

- Call DMS APIs with `Authorization: Bearer <access_token>` and `x-workspace: <workspace>` (when applicable).
- Example:

```sh
curl -H "Authorization: Bearer <access_token>" \
     -H "x-workspace: <workspace>" \
     "${OAUTH_AUTH_SERVER:-https://api.dev.omnetic.dev}/dms/v1/user/info"
```

## Requirements

- PHP >= 8.0
- cURL extension
