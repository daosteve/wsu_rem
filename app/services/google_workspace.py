"""
Google Workspace operations via the Admin SDK Directory API.

One-time setup
──────────────
1.  In Google Cloud Console, create (or reuse) a project and enable the
    "Admin SDK API".
2.  Create a Service Account. Download its JSON key file.
    Store it at the path set in GW_SERVICE_ACCOUNT_FILE (e.g. /opt/wsu_rem/secrets/gw-sa.json).
    Restrict file permissions: chmod 600.
3.  In the Google Workspace Admin console go to:
      Security → Access and data control → API controls → Domain-wide delegation
    Add the service account's Client ID with the scope:
      https://www.googleapis.com/auth/admin.directory.user
4.  Set GW_DELEGATED_ADMIN to a super-admin email (the account the SA impersonates).
"""

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

_SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.user.security',
]


def _get_service(cfg):
    creds = service_account.Credentials.from_service_account_file(
        cfg['GW_SERVICE_ACCOUNT_FILE'],
        scopes=_SCOPES,
        subject=cfg['GW_DELEGATED_ADMIN'],
    )
    return build('admin', 'directory_v1', credentials=creds, cache_discovery=False)


def _not_configured(cfg) -> bool:
    return not cfg.get('GW_SERVICE_ACCOUNT_FILE') or not cfg.get('GW_DELEGATED_ADMIN')


def _resolve_user_key(cfg: dict, username: str) -> str:
    """Return a fully-qualified email for the user.

    If `username` already contains '@' it is used as-is.
    Otherwise the domain is taken from GW_USER_DOMAIN, falling back to
    the domain portion of GW_DELEGATED_ADMIN.
    """
    if '@' in username:
        return username
    domain = cfg.get('GW_USER_DOMAIN', '').strip()
    if not domain:
        admin = cfg.get('GW_DELEGATED_ADMIN', '')
        domain = admin.split('@')[-1] if '@' in admin else ''
    if not domain:
        return username
    return f'{username}@{domain}'


def suspend_user(cfg: dict, username: str) -> tuple:
    """
    Suspend a Google Workspace user.
    `username` must be the user's primary email address or unique ID.
    If your sAMAccountName matches the email prefix, append the domain here or
    adjust the GW_USER_DOMAIN config variable as needed.
    """
    if _not_configured(cfg):
        return 'error', 'Google Workspace is not configured (see .env.example)'
    try:
        service = _get_service(cfg)
        user_key = _resolve_user_key(cfg, username)
        service.users().update(userKey=user_key, body={'suspended': True}).execute()
        return 'success', f'User {user_key} suspended in Google Workspace'
    except HttpError as exc:
        return 'error', f'Google API error {exc.status_code}: {exc.reason}'
    except Exception as exc:
        return 'error', str(exc)


def unsuspend_user(cfg: dict, username: str) -> tuple:
    """Re-activate a suspended Google Workspace user."""
    if _not_configured(cfg):
        return 'error', 'Google Workspace is not configured (see .env.example)'
    try:
        service = _get_service(cfg)
        user_key = _resolve_user_key(cfg, username)
        service.users().update(userKey=user_key, body={'suspended': False}).execute()
        return 'success', f'User {user_key} re-activated in Google Workspace'
    except HttpError as exc:
        return 'error', f'Google API error {exc.status_code}: {exc.reason}'
    except Exception as exc:
        return 'error', str(exc)


def get_last_login(cfg: dict, username: str) -> str:
    """Return the user's last login time as a formatted string, or '' on failure.

    The Admin SDK returns lastLoginTime in ISO-8601 format (UTC).
    Returns a display string like '2026-05-14 10:30 UTC' or '' if unknown.
    """
    if _not_configured(cfg):
        return ''
    try:
        service = _get_service(cfg)
        user_key = _resolve_user_key(cfg, username)
        user = service.users().get(
            userKey=user_key,
            projection='basic',
            fields='lastLoginTime',
        ).execute()
        raw = user.get('lastLoginTime', '')
        if not raw or raw == '1970-01-01T00:00:00.000Z':
            return ''
        # Format: "2026-05-14T10:30:00.000Z" → "2026-05-14 10:30 UTC"
        return raw[:16].replace('T', ' ') + ' UTC'
    except Exception:
        return ''


def reset_sign_in_cookies(cfg: dict, username: str) -> tuple:
    """Invalidate all active browser sessions (sign-out everywhere) for a GW user."""
    if _not_configured(cfg):
        return 'error', 'Google Workspace is not configured (see .env.example)'
    try:
        service = _get_service(cfg)
        user_key = _resolve_user_key(cfg, username)
        service.users().signOut(userKey=user_key).execute()
        return 'success', f'All Google sign-in sessions terminated for {user_key}'
    except HttpError as exc:
        return 'error', f'Google API error {exc.status_code}: {exc.reason}'
    except Exception as exc:
        return 'error', str(exc)
