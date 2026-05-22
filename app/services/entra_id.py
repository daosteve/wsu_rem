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
from datetime import datetime, timedelta

_GRAPH_ENDPOINT = 'https://graph.microsoft.com/v1.0'
_GRAPH_BETA = 'https://graph.microsoft.com/beta'
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
        # Strip sub-second precision and trailing Z before parsing
        s = iso_str.rstrip('Z').split('.')[0]
        dt = datetime.strptime(s, '%Y-%m-%dT%H:%M:%S')
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

    Returns a dict with zero or more of:
      mfa_methods    – list of registered non-password methods, each a dict
                         with 'name' and 'registered' (createdDateTime) when available

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
        # Use the beta endpoint: it exposes createdDateTime for most types and
        # lastUsedDateTime for phone methods (which lack createdDateTime).
        r = requests.get(
            f'{_GRAPH_BETA}/users/{upn}/authentication/methods',
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            methods = []
            seen_names: set[str] = set()
            for m in r.json().get('value', []):
                odata_type = m.get('@odata.type', '')
                if odata_type == _PASSWORD_METHOD:
                    continue
                label = _METHOD_LABELS.get(odata_type, odata_type.rsplit('.', 1)[-1])
                if odata_type == '#microsoft.graph.phoneAuthenticationMethod':
                    phone_type = m.get('phoneType', '')
                    if phone_type and phone_type != 'mobile':
                        label = f'Phone ({phone_type})'
                if label in seen_names:
                    continue
                seen_names.add(label)
                entry: dict = {'name': label}
                if m.get('createdDateTime'):
                    entry['registered'] = _fmt_dt(m['createdDateTime'])
                methods.append(entry)
            if methods:
                result['mfa_methods'] = methods

        return result
    except Exception:
        return {}


def get_audit_activity(cfg: dict, username: str) -> list:
    """
    Return Entra ID audit entries for 'User started security info registration'
    in the last 30 days where the user is the target.

    Requires AuditLog.Read.All application permission (admin consent needed).
    Returns a list of dicts with 'date', 'result', 'initiated_by'.
    Returns [] silently on any error or if Entra is not configured.
    """
    if _not_configured(cfg):
        return []
    try:
        token = _get_token(cfg)
        headers = {'Authorization': f'Bearer {token}'}
        upn = _resolve_upn(cfg, username)
        since = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        r = requests.get(
            f'{_GRAPH_ENDPOINT}/auditLogs/directoryAudits',
            headers=headers,
            params={
                '$filter': (
                    f"targetResources/any(t: t/userPrincipalName eq '{upn}')"
                    " and activityDisplayName eq 'User started security info registration'"
                    f" and activityDateTime ge {since}"
                ),
                '$top': '5',
                '$orderby': 'activityDateTime desc',
                '$select': 'activityDateTime,result,initiatedBy',
            },
            timeout=10,
        )
        if r.status_code != 200:
            return []
        entries = []
        for item in r.json().get('value', []):
            dt = _fmt_dt(item.get('activityDateTime', ''))
            res = item.get('result', '')
            initiated_by = ''
            ib = item.get('initiatedBy', {})
            if ib.get('user'):
                initiated_by = ib['user'].get('displayName') or ib['user'].get('userPrincipalName', '')
            elif ib.get('app'):
                initiated_by = ib['app'].get('displayName', '')
            entries.append({'date': dt, 'result': res, 'initiated_by': initiated_by})
        return entries
    except Exception:
        return []
