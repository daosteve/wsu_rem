"""
Microsoft Entra ID (Azure AD) – revoke all sign-in sessions via Microsoft Graph.

One-time setup
──────────────
1.  Azure Portal → Entra ID → App registrations → New registration.
    Name it "WSU Remediation", single-tenant.
2.  Certificates & secrets → New client secret. Copy the value to ENTRA_CLIENT_SECRET.
3.  API permissions → Add a permission → Microsoft Graph → Application permissions →
    search for "User.RevokeSessions.All" → Add.
4.  Click "Grant admin consent for <tenant>".
5.  Copy the Tenant ID  → ENTRA_TENANT_ID
    Copy the Application (client) ID → ENTRA_CLIENT_ID
"""

import msal
import requests

_GRAPH_ENDPOINT = 'https://graph.microsoft.com/v1.0'
_SCOPES = ['https://graph.microsoft.com/.default']


def _get_token(cfg: dict) -> str:
    authority = f"https://login.microsoftonline.com/{cfg['ENTRA_TENANT_ID']}"
    app = msal.ConfidentialClientApplication(
        cfg['ENTRA_CLIENT_ID'],
        authority=authority,
        client_credential=cfg['ENTRA_CLIENT_SECRET'],
    )
    result = app.acquire_token_for_client(scopes=_SCOPES)
    if 'access_token' not in result:
        raise RuntimeError(result.get('error_description', 'Failed to acquire Entra token'))
    return result['access_token']


def _not_configured(cfg: dict) -> bool:
    return not all(cfg.get(k) for k in ('ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET'))


def revoke_sessions(cfg: dict, username: str) -> tuple:
    """
    Revoke all Entra ID sign-in sessions for a user.
    `username` can be the UPN (user@domain.com) or the Entra Object ID.
    If you pass a sAMAccountName without a domain, append the UPN suffix or
    look up the user's Object ID first.
    """
    if _not_configured(cfg):
        return 'error', 'Entra ID is not configured (see .env.example)'
    try:
        token = _get_token(cfg)
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        url = f'{_GRAPH_ENDPOINT}/users/{username}/revokeSignInSessions'
        resp = requests.post(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return 'success', 'All Entra ID sign-in sessions revoked'
        return 'error', f'Graph API {resp.status_code}: {resp.text[:200]}'
    except Exception as exc:
        return 'error', str(exc)
