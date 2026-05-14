import re
import ssl
import logging

from flask import render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from ldap3 import Server, Connection, Tls, ALL
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.auth import bp
from app.models import User
from app import limiter

log = logging.getLogger(__name__)

# sAMAccountName allowed characters
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-]{1,64}$')


def _build_tls(cfg) -> Tls:
    """Build a Tls object, optionally pinning to a custom CA bundle."""
    if cfg.get('LDAP_CA_CERT_FILE'):
        return Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=cfg['LDAP_CA_CERT_FILE'],
        )
    # No CA bundle configured – disable validation (internal DC with private CA,
    # matches wsu_sws behaviour on the same internal network).
    return Tls(validate=ssl.CERT_NONE)


def ldap_authenticate(username: str, password: str) -> 'User | None':
    """
    Authenticate operator via LDAP, check group membership.
    Returns a User on success, None on failure or insufficient permissions.
    """
    cfg = current_app.config

    if not _USERNAME_RE.match(username):
        return None

    safe_username = escape_filter_chars(username)

    try:
        # Step 1 – service account looks up the user DN + group membership
        tls = _build_tls(cfg)
        server = Server(cfg['LDAP_HOST'], port=cfg['LDAP_PORT'], use_ssl=True, tls=tls, get_info=ALL)
        svc_conn = Connection(
            server,
            user=cfg['LDAP_BIND_DN'],
            password=cfg['LDAP_BIND_PASSWORD'],
            auto_bind=True,
        )
        svc_conn.search(
            cfg['LDAP_USER_SEARCH_BASE'],
            f'(sAMAccountName={safe_username})',
            attributes=['distinguishedName', 'displayName', 'memberOf'],
        )
        if not svc_conn.entries:
            log.warning('LDAP: user not found: %s', username)
            svc_conn.unbind()
            return None

        entry = svc_conn.entries[0]
        user_dn = str(entry.distinguishedName)
        display_name = str(entry.displayName) if entry.displayName else username
        member_of = [str(g) for g in entry.memberOf] if entry.memberOf else []
        log.info('LDAP: found user %s, memberOf=%s', user_dn, member_of)
        svc_conn.unbind()

        # Step 2 – bind as the user to verify the password
        user_conn = Connection(server, user=user_dn, password=password)
        if not user_conn.bind():
            log.warning('LDAP: password bind failed for %s, result=%s', user_dn, user_conn.result)
            return None
        user_conn.unbind()

        # Step 3 – check group membership (CN-based match)
        def _cn_match(cn_list, member_dns):
            for cn in cn_list:
                for dn in member_dns:
                    if dn.lower().startswith(f'cn={cn.lower()},'):
                        return True
            return False

        allowed_groups = cfg.get('LDAP_ALLOWED_GROUPS', [])
        admin_groups = cfg.get('LDAP_ADMIN_GROUPS', [])

        if allowed_groups and not _cn_match(allowed_groups, member_of):
            log.warning('LDAP: user %s not in allowed groups %s', username, allowed_groups)
            return None  # authenticated but not authorized

        is_admin = bool(admin_groups and _cn_match(admin_groups, member_of))
        log.info('LDAP: auth OK for %s, is_admin=%s', username, is_admin)
        return User(username=username, display_name=display_name, is_admin=is_admin)

    except LDAPException as exc:
        log.error('LDAP exception during auth for %s: %s', username, exc)
        return None


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('quarantine.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = ldap_authenticate(username, password)
        if user:
            login_user(user)
            session['username'] = user.username
            session['display_name'] = user.display_name
            session['is_admin'] = user.is_admin
            session.permanent = True

            # Validate next to prevent open-redirect
            next_page = request.args.get('next', '')
            if not next_page.startswith('/') or '//' in next_page:
                next_page = url_for('quarantine.index')
            return redirect(next_page)

        flash('Invalid credentials or insufficient permissions.', 'danger')

    return render_template('login.html')


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))
