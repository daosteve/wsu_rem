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
from datetime import datetime

_GRAPH_ENDPOINT = 'https://graph.microsoft.com/v1.0'
_SCOPES = ['https://graph.microsoft.com/.default']

# Human-readable labels for authentication method odata types
_METHOD_LABELS = {
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod': 'Microsoft Authenticator',
    '#microsoft.graph.phoneAuthenticationMethod': 'Phone',
    '#microsoft.graph.fido2AuthenticationMethod': 'FIDO2 Security Key',
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod': 'Windows Hello for Business',
    '#microsoft.graph.emailAuthenticationMethod': 'Email OTP',
    '#microsoft.graph.softwareOathAuthenticationMethod': 'Software OATH Token',
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod': 'Temporary Access Pass',
    '#microsoft.graph.platformCredentialAuthenticationMethod': 'Platform Credential',
}
_PASSWORD_METHOD = '#microsoft.graph.passwordAuthenticationMethod'


def _fmt_dt(iso_str: str) -> str:
    """Format a Graph API ISO 8601 UTC timestamp to a readable string."""
    try:
        dt = datetime.strptime(iso_str, '%Y-%m-%dT%H:%M:%SZ')
        return dt.strftime('%Y-%m-%d %H:%M UTC')
    except (ValueError, TypeError):
        return iso_str


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


import re as _re
_GUID_RE = _re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    _re.IGNORECASE,
)


def _not_configured(cfg: dict) -> bool:
    return not all(cfg.get(k) for k in ('ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET'))


def _resolve_upn(cfg: dict, username: str) -> str:
    """
    Return a UPN or Object ID suitable for the Graph API /users/{id} path.

    - If *username* already contains '@' (UPN) or is a GUID (Object ID),
      it is returned as-is.
    - Otherwise it is treated as a sAMAccountName and ENTRA_UPN_SUFFIX
      (e.g. 'worcester.edu') is appended to form a UPN.
    """
    if '@' in username or _GUID_RE.match(username):
        return username

    suffix = cfg.get('ENTRA_UPN_SUFFIX', '').strip().lstrip('@')
    if not suffix:
        raise RuntimeError(
            "ENTRA_UPN_SUFFIX is not configured. "
            "Set it to your tenant's UPN suffix (e.g. worcester.edu) so that "
            "sAMAccountNames can be resolved without requiring User.Read.All."
        )
    return f'{username}@{suffix}'


def revoke_sessions(cfg: dict, username: str) -> tuple:
    """
    Revoke all Entra ID sign-in sessions for a user.
    Accepts a UPN (user@domain.com), an Entra Object ID, or a sAMAccountName.
    For sAMAccountNames, ENTRA_UPN_SUFFIX must be set in config.
    """
    if _not_configured(cfg):
        return 'error', 'Entra ID is not configured (see .env.example)'
    try:
        token = _get_token(cfg)
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        upn = _resolve_upn(cfg, username)
        url = f'{_GRAPH_ENDPOINT}/users/{upn}/revokeSignInSessions'
        resp = requests.post(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return 'success', 'All Entra ID sign-in sessions revoked'
        return 'error', f'Graph API {resp.status_code}: {resp.text[:200]}'
    except Exception as exc:
        return 'error', str(exc)


def get_mfa_info(cfg: dict, username: str) -> dict:
    """
    Return MFA registration and last-used details for a user.

    Requires these additional Graph application permissions (admin consent needed):
      • UserAuthenticationMethod.Read.All  – for registered methods
      • AuditLog.Read.All                  – for last MFA sign-in log

    Returns a dict with zero or more of:
      mfa_methods    – list of registered non-password method names
      mfa_last_used  – formatted UTC timestamp of the most recent MFA sign-in
      mfa_last_method – authentication method used in that sign-in

    Returns {} silently on any error or if Entra is not configured.
    """
    if _not_configured(cfg):
        return {}
    try:
        token = _get_token(cfg)
        headers = {'Authorization': f'Bearer {token}'}
        upn = _resolve_upn(cfg, username)
        result = {}

        # --- Registered authentication methods ---
        r = requests.get(
            f'{_GRAPH_ENDPOINT}/users/{upn}/authentication/methods',
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            methods = []
            for m in r.json().get('value', []):
                odata_type = m.get('@odata.type', '')
                if odata_type == _PASSWORD_METHOD:
                    continue
                label = _METHOD_LABELS.get(odata_type, odata_type.rsplit('.', 1)[-1])
                if odata_type == '#microsoft.graph.phoneAuthenticationMethod':
                    phone_type = m.get('phoneType', '')
                    if phone_type and phone_type != 'mobile':
                        label = f'Phone ({phone_type})'
                if label not in methods:
                    methods.append(label)
            if methods:
                result['mfa_methods'] = methods

        # --- Most recent MFA sign-in (requires AuditLog.Read.All) ---
        r2 = requests.get(
            f'{_GRAPH_ENDPOINT}/auditLogs/signIns',
            headers=headers,
            params={
                '$filter': (
                    f"userPrincipalName eq '{upn}'"
                    " and authenticationRequirement eq 'multiFactorAuthentication'"
                ),
                '$top': '1',
                '$select': 'createdDateTime,authenticationDetails',
            },
            timeout=10,
        )
        if r2.status_code == 200:
            entries = r2.json().get('value', [])
            if entries:
                entry = entries[0]
                dt = entry.get('createdDateTime', '')
                if dt:
                    result['mfa_last_used'] = _fmt_dt(dt)
                # Find the secondary (MFA) authentication step
                for detail in entry.get('authenticationDetails', []):
                    if (detail.get('authenticationStepRequirement') == 'secondaryAuthentication'
                            and detail.get('succeeded')):
                        method = detail.get('authenticationMethod', '')
                        if method:
                            result['mfa_last_method'] = method
                        break

        return result
    except Exception:
        return {}
