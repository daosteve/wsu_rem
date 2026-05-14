"""
Active Directory operations over LDAPS using ldap3.

Requires:
  - LDAPS (port 636) to a Domain Controller
  - Service account with read access + permission to modify userAccountControl and unicodePwd
  - For password resets: the DC must be reached over SSL/TLS (already enforced)
"""

import re
import ssl

from ldap3 import Server, Connection, Tls, ALL, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

# AD userAccountControl flags
_ADS_UF_ACCOUNTDISABLE = 0x0002
_ADS_UF_NORMAL_ACCOUNT  = 0x0200

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-]{1,64}$')


def _build_server(cfg) -> Server:
    if cfg.get('LDAP_CA_CERT_FILE'):
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg['LDAP_CA_CERT_FILE'])
    else:
        # No CA bundle configured – disable validation (internal DC with private CA,
        # matches wsu_sws behaviour on the same internal network).
        tls = Tls(validate=ssl.CERT_NONE)
    return Server(cfg['LDAP_HOST'], port=cfg['LDAP_PORT'], use_ssl=True, tls=tls, get_info=ALL)


def _svc_conn(cfg) -> Connection:
    """Return an auto-bound service-account connection (GC / read)."""
    server = _build_server(cfg)
    return Connection(server, user=cfg['LDAP_BIND_DN'], password=cfg['LDAP_BIND_PASSWORD'], auto_bind=True)


def _subdomain_from_dn(dn: str) -> str:
    """Return the first (child) DC label from a DN in upper case.

    Example: 'CN=Bob,OU=Staff,DC=WSC,DC=worcester,DC=local' → 'WSC'
    """
    for part in dn.split(','):
        part = part.strip()
        if part.upper().startswith('DC='):
            return part.split('=', 1)[1].upper()
    return ''


def _write_conn(cfg: dict, dn: str) -> Connection:
    """Return an auto-bound write-capable connection to the child domain's DC on port 636.

    Reads use the Global Catalog (port 3269) which spans all child domains but
    is read-only.  Writes must target the authoritative DC for the user's domain
    on standard LDAPS port 636.

    LDAP_WRITE_HOSTS maps subdomain labels (e.g. 'WSC') to DC hostnames.
    """
    label = _subdomain_from_dn(dn)
    write_hosts = cfg.get('LDAP_WRITE_HOSTS') or {}
    write_host = write_hosts.get(label)
    if not write_host:
        raise LDAPException(
            f'No write DC configured for subdomain "{label}". '
            'Add it to LDAP_WRITE_HOSTS in .env.'
        )
    if cfg.get('LDAP_CA_CERT_FILE'):
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg['LDAP_CA_CERT_FILE'])
    else:
        tls = Tls(validate=ssl.CERT_NONE)
    server = Server(write_host, port=636, use_ssl=True, tls=tls, get_info=ALL)
    return Connection(server, user=cfg['LDAP_BIND_DN'], password=cfg['LDAP_BIND_PASSWORD'], auto_bind=True)


def _extract_subdomain(dn: str, base_dn: str):
    """
    Return the immediate sub-domain label if the DN lives in a sub-domain of
    base_dn, or None if it is in the top-level domain itself.

    Example (base_dn = "DC=worcester,DC=local"):
      "CN=John,OU=Staff,DC=WSC,DC=worcester,DC=local"  → "WSC"
      "CN=Admin,CN=Users,DC=worcester,DC=local"         → None  (top-level)
    """
    def dc_parts(s):
        return [p.split('=', 1)[1].lower() for p in s.split(',')
                if p.strip().upper().startswith('DC=')]

    dn_dcs   = dc_parts(dn)
    base_dcs = dc_parts(base_dn)

    if len(dn_dcs) <= len(base_dcs):
        return None  # same depth or shallower → top-level domain

    # The leading DC component(s) beyond the base identify the sub-domain.
    return dn_dcs[0].upper()


def _is_organizational_user(dn: str) -> bool:
    """
    Return True only if the DN contains at least one OU= component between the
    user's CN and the domain DC components.  Accounts that live directly inside
    a CN= container (e.g. CN=Users, CN=Builtin) are treated as system/service
    accounts and rejected.
    """
    parts = [p.strip() for p in dn.split(',')]
    return any(p.upper().startswith('OU=') for p in parts)


def _find_user(conn: Connection, cfg: dict, username: str):
    """Return (dn, entry) or (None, None) if not found.

    The LDAP filter restricts results to real user accounts only
    (objectCategory=person excludes computers and other non-person objects).
    """
    safe = escape_filter_chars(username)
    conn.search(
        cfg['LDAP_USER_SEARCH_BASE'],
        f'(&(objectClass=user)(objectCategory=person)(sAMAccountName={safe}))',
        attributes=[
            'distinguishedName', 'displayName', 'userAccountControl', 'mail',
            'memberOf', 'whenCreated', 'whenChanged',
        ],
    )
    if not conn.entries:
        return None, None
    entry = conn.entries[0]
    return str(entry.distinguishedName), entry


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_users(cfg: dict, usernames: list) -> list:
    """Return a list of dicts describing each user's AD status."""
    results = []
    base_dn = cfg.get('LDAP_BASE_DN', '')
    try:
        conn = _svc_conn(cfg)
        for username in usernames:
            if not _USERNAME_RE.match(username):
                results.append({'username': username, 'found': False, 'reason': 'Invalid username format'})
                continue
            dn, entry = _find_user(conn, cfg, username)
            if dn is None:
                results.append({'username': username, 'found': False})
                continue
            subdomain = _extract_subdomain(dn, base_dn)
            if subdomain is None:
                # Top-level domain accounts are excluded per policy.
                results.append({'username': username, 'found': False,
                                'reason': 'Not in a recognised sub-domain'})
                continue
            uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0

            # Extract the OU path: OU= components from the DN, innermost first,
            # stopping before the DC components.
            dn_parts = [p.strip() for p in dn.split(',')]
            ou_parts = [p.split('=', 1)[1] for p in dn_parts
                        if p.upper().startswith('OU=')]
            ou_path = ' > '.join(ou_parts) if ou_parts else ''

            # Group memberships: CN value from each memberOf DN.
            raw_groups = entry.memberOf.values if entry.memberOf else []
            groups = []
            for g in raw_groups:
                for part in str(g).split(','):
                    part = part.strip()
                    if part.upper().startswith('CN='):
                        groups.append(part.split('=', 1)[1])
                        break

            # Dates come back as datetime objects from ldap3.
            def _fmt_dt(attr):
                try:
                    v = attr.value
                    return v.strftime('%Y-%m-%d') if v else ''
                except Exception:
                    return ''

            results.append({
                'username': username,
                'found': True,
                'display_name': str(entry.displayName) if entry.displayName else username,
                'email': str(entry.mail) if entry.mail else '',
                'ad_disabled': bool(uac & _ADS_UF_ACCOUNTDISABLE),
                'domain': subdomain,
                'ou': ou_path,
                'groups': groups,
                'created': _fmt_dt(entry.whenCreated),
                'modified': _fmt_dt(entry.whenChanged),
            })
        conn.unbind()
    except LDAPException as exc:
        results.append({'username': '__LDAP_ERROR__', 'found': False, 'reason': str(exc)})
    return results


def disable_user(cfg: dict, username: str) -> tuple:
    """Disable an AD account by setting the ACCOUNTDISABLE bit."""
    try:
        # Lookup via Global Catalog (read-only, spans all child domains)
        gc_conn = _svc_conn(cfg)
        dn, entry = _find_user(gc_conn, cfg, username)
        gc_conn.unbind()
        if dn is None:
            return 'error', 'User not found in AD'
        uac = int(entry.userAccountControl.value) if entry.userAccountControl else _ADS_UF_NORMAL_ACCOUNT
        new_uac = uac | _ADS_UF_ACCOUNTDISABLE
        # Write via the authoritative domain DC on port 636
        wconn = _write_conn(cfg, dn)
        wconn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
        modify_result = wconn.result
        wconn.unbind()
        if modify_result['result'] == 0:
            return 'success', f'Account disabled (UAC={new_uac})'
        return 'error', modify_result.get('description', 'Modify failed')
    except LDAPException as exc:
        return 'error', str(exc)


def enable_user(cfg: dict, username: str) -> tuple:
    """Re-enable an AD account by clearing the ACCOUNTDISABLE bit."""
    try:
        gc_conn = _svc_conn(cfg)
        dn, entry = _find_user(gc_conn, cfg, username)
        gc_conn.unbind()
        if dn is None:
            return 'error', 'User not found in AD'
        uac = int(entry.userAccountControl.value) if entry.userAccountControl else _ADS_UF_NORMAL_ACCOUNT
        new_uac = uac & ~_ADS_UF_ACCOUNTDISABLE
        wconn = _write_conn(cfg, dn)
        wconn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
        modify_result = wconn.result
        wconn.unbind()
        if modify_result['result'] == 0:
            return 'success', f'Account re-enabled (UAC={new_uac})'
        return 'error', modify_result.get('description', 'Modify failed')
    except LDAPException as exc:
        return 'error', str(exc)


def reset_password(cfg: dict, username: str, new_password: str = None) -> tuple:
    """
    Reset an AD account password.
    Requires LDAPS – the connection already enforces SSL.
    """
    new_password = new_password or cfg['AD_RESET_PASSWORD']
    try:
        # Lookup via Global Catalog (read-only, spans all child domains)
        gc_conn = _svc_conn(cfg)
        dn, entry = _find_user(gc_conn, cfg, username)
        gc_conn.unbind()
        if dn is None:
            return 'error', 'User not found in AD'
        # AD requires the new password surrounded by double quotes, encoded as UTF-16-LE
        encoded = f'"{new_password}"'.encode('utf-16-le')
        # Write via the authoritative domain DC on port 636
        wconn = _write_conn(cfg, dn)
        wconn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [encoded])]})
        modify_result = wconn.result
        wconn.unbind()
        if modify_result['result'] == 0:
            return 'success', 'Password reset successfully'
        return 'error', modify_result.get('description', 'Password reset failed')
    except LDAPException as exc:
        return 'error', str(exc)
