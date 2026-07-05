import csv
import io
import re
import time
from datetime import datetime

from flask import render_template, request, jsonify, current_app
from flask_login import login_required, current_user

from app.quarantine import bp
from app.models import OperationLog, QuarantineRecord
from app import db
from app.services import active_directory, google_workspace, entra_id, email_alerts

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-]{1,64}$')

VALID_ACTIONS = frozenset({
    'ad_disable',
    'ad_enable',
    'ad_reset_password',
    'gw_suspend',
    'gw_unsuspend',
    'gw_reset_cookies',
    'entra_revoke_sessions',
    'entra_require_mfa_reregister',
})

SYSTEM_MAP = {
    'ad_disable': 'AD',
    'ad_enable': 'AD',
    'ad_reset_password': 'AD',
    'gw_suspend': 'GW',
    'gw_unsuspend': 'GW',
    'gw_reset_cookies': 'GW',
    'entra_revoke_sessions':          'Entra',
    'entra_require_mfa_reregister':    'Entra',
}


def _parse_usernames(text: str) -> list:
    """Extract valid usernames from free text (newlines, commas, semicolons, spaces)."""
    raw = re.split(r'[\s,;]+', text.strip())
    return [u for u in raw if _USERNAME_RE.match(u)]


@bp.route('/')
@login_required
def index():
    return render_template('quarantine.html')


@bp.route('/lookup', methods=['POST'])
@login_required
def lookup():
    """Look up users in AD. Accepts JSON body or multipart form with optional CSV file."""
    usernames = []

    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw = data.get('usernames', '')
        if isinstance(raw, list):
            usernames = [u for u in raw if isinstance(u, str) and _USERNAME_RE.match(u)]
        else:
            usernames = _parse_usernames(str(raw))
    else:
        # Multipart form – CSV file takes priority over textarea
        f = request.files.get('csv_file')
        if f and f.filename:
            stream = io.StringIO(f.read().decode('utf-8', errors='replace'))
            reader = csv.reader(stream)
            for row in reader:
                if row:
                    candidate = row[0].strip()
                    if _USERNAME_RE.match(candidate):
                        usernames.append(candidate)
        else:
            text = request.form.get('usernames', '')
            usernames = _parse_usernames(text)

    if not usernames:
        return jsonify({'error': 'No valid usernames provided.'}), 400
    if len(usernames) > 20:
        return jsonify({'error': 'Maximum 20 usernames per request.'}), 400

    results = active_directory.lookup_users(current_app.config, usernames)

    # Mark which found users were disabled by this system
    quarantined = {
        r.username
        for r in QuarantineRecord.query.filter(
            QuarantineRecord.username.in_(usernames)
        ).all()
    }
    for user in results:
        if user.get('found'):
            user['quarantined_by_us'] = user['username'] in quarantined

    # Enrich found users with GW last login (best-effort; never blocks the response)
    gw_configured = not google_workspace._not_configured(current_app.config)
    if gw_configured:
        for user in results:
            if user.get('found'):
                user['gw_last_login'] = google_workspace.get_last_login(
                    current_app.config, user['username']
                )

    # Enrich found users with Entra MFA info and audit activity (best-effort; never blocks the response)
    entra_configured = not entra_id._not_configured(current_app.config)
    if entra_configured:
        for user in results:
            if user.get('found'):
                user.update(entra_id.get_mfa_info(current_app.config, user['username']))
                user['entra_audit'] = entra_id.get_audit_activity(
                    current_app.config, user['username']
                )

    return jsonify({'users': results})


@bp.route('/csv_lookup', methods=['POST'])
@login_required
def csv_lookup():
    """Parse an uploaded CSV, extract unique usernames from the 'Host User Email'
    column, and look them up in AD (no GW/Entra enrichment for speed).
    Returns the same user shape as /lookup without the 20-user cap.
    """
    f = request.files.get('csv_file')
    if not f or not f.filename:
        return jsonify({'error': 'No CSV file provided.'}), 400

    try:
        raw = io.StringIO(f.read().decode('utf-8', errors='replace'))
    except Exception as exc:
        return jsonify({'error': f'Failed to read file: {exc}'}), 400

    EMAIL_COLUMN = 'Host User Email'
    seen: set = set()
    usernames: list = []

    try:
        reader = csv.DictReader(raw)
        for row in reader:
            email = (row.get(EMAIL_COLUMN) or '').strip()
            if not email:
                for v in row.values():
                    if v and '@' in str(v):
                        email = str(v).strip()
                        break
            if not email:
                continue
            if email.lower().startswith('mailto:'):
                email = email[7:]
            username = email.split('@')[0] if '@' in email else email
            if not _USERNAME_RE.match(username):
                continue
            if username not in seen:
                seen.add(username)
                usernames.append(username)
    except Exception as exc:
        return jsonify({'error': f'Failed to parse CSV: {exc}'}), 400

    if not usernames:
        return jsonify({'error': 'No valid usernames found in CSV.'}), 400

    MAX_CSV_USERS = 2000
    if len(usernames) > MAX_CSV_USERS:
        return jsonify({
            'error': f'CSV contains {len(usernames)} unique users; maximum is {MAX_CSV_USERS}.'
        }), 400

    results = active_directory.lookup_users(current_app.config, usernames)
    # Filter out internal LDAP error sentinels
    results = [u for u in results if u.get('username') != '__LDAP_ERROR__']

    quarantined = {
        r.username
        for r in QuarantineRecord.query.filter(
            QuarantineRecord.username.in_(usernames)
        ).all()
    }
    for user in results:
        if user.get('found'):
            user['quarantined_by_us'] = user['username'] in quarantined

    found_count    = sum(1 for u in results if u.get('found'))
    not_found_count = sum(1 for u in results if not u.get('found'))
    return jsonify({
        'users':        results,
        'total_in_csv': len(usernames),
        'found':        found_count,
        'not_found':    not_found_count,
    })


@bp.route('/execute', methods=['POST'])
@login_required
def execute():
    """Execute quarantine / remediation actions and log every operation."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get('actions'), list):
        return jsonify({'error': 'Invalid request body.'}), 400

    actions = data['actions']
    if not actions:
        return jsonify({'error': 'No actions specified.'}), 400

    results = []
    log_entries = []
    qr_to_add = []
    qr_to_delete = []

    for item in actions:
        username = str(item.get('username', '')).strip()
        action   = str(item.get('action',   '')).strip()
        reason   = str(item.get('reason',   '')).strip()[:128]
        comment  = str(item.get('comment',  '')).strip()

        if not _USERNAME_RE.match(username):
            results.append({'username': username, 'action': action, 'result': 'error', 'detail': 'Invalid username.'})
            continue
        if action not in VALID_ACTIONS:
            results.append({'username': username, 'action': action, 'result': 'error', 'detail': 'Invalid action.'})
            continue

        cfg = current_app.config
        result, detail = 'error', 'Unknown error'

        try:
            if action == 'ad_disable':
                if not reason:
                    results.append({'username': username, 'action': action, 'result': 'error', 'detail': 'Quarantine reason is required.'})
                    continue
                res = active_directory.disable_user(cfg, username, reason=reason, comment=comment, operator=current_user.username)
                result, detail = res[0], res[1]
                original_dn = res[2] if len(res) > 2 else None
                if result == 'success' and original_dn:
                    existing = QuarantineRecord.query.filter_by(username=username).first()
                    if existing:
                        existing.original_dn = original_dn
                        existing.quarantined_at = datetime.utcnow()
                    else:
                        qr_to_add.append(QuarantineRecord(username=username, original_dn=original_dn))
            elif action == 'ad_enable':
                rec = QuarantineRecord.query.filter_by(username=username).first()
                if not rec:
                    results.append({'username': username, 'action': action, 'result': 'error', 'detail': 'Account was not disabled by this system.'})
                    continue
                result, detail = active_directory.enable_user(
                    cfg, username,
                    original_dn=rec.original_dn,
                    operator=current_user.username,
                )
                if result in ('success', 'warning'):
                    qr_to_delete.append(rec)
            elif action == 'ad_reset_password':
                result, detail = active_directory.reset_password(cfg, username)
            elif action == 'gw_suspend':
                result, detail = google_workspace.suspend_user(cfg, username)
            elif action == 'gw_unsuspend':
                result, detail = google_workspace.unsuspend_user(cfg, username)
            elif action == 'gw_reset_cookies':
                result, detail = google_workspace.reset_sign_in_cookies(cfg, username)
            elif action == 'entra_revoke_sessions':
                result, detail = entra_id.revoke_sessions(cfg, username)
            elif action == 'entra_require_mfa_reregister':
                result, detail = entra_id.require_mfa_reregistration(cfg, username)
        except Exception as exc:
            result, detail = 'error', str(exc)

        results.append({'username': username, 'action': action, 'result': result, 'detail': detail})
        log_entries.append(OperationLog(
            operator=current_user.username,
            target_username=username,
            action=action,
            system=SYSTEM_MAP[action],
            result=result,
            detail=detail,
            reason=reason or None,
            comment=comment or None,
        ))

    if log_entries or qr_to_add or qr_to_delete:
        db.session.add_all(log_entries)
        db.session.add_all(qr_to_add)
        for rec in qr_to_delete:
            db.session.delete(rec)
        db.session.commit()

    # Best-effort email alert
    try:
        email_alerts.send_operation_alert(current_app.config, current_user.username, results)
    except Exception:
        pass

    return jsonify({'results': results})


@bp.route('/csv_remediate', methods=['POST'])
@login_required
def csv_remediate():
    """Parse an uploaded CSV, extract unique usernames from the 'Host User Email'
    column (stripping mailto: and @domain suffixes), then for every user found in
    AD execute: ad_reset_password · gw_reset_cookies · entra_revoke_sessions.

    De-duplicates rows first so each user's APIs are called exactly once,
    keeping the request count proportional to unique accounts, not CSV rows.
    """
    f = request.files.get('csv_file')
    if not f or not f.filename:
        return jsonify({'error': 'No CSV file provided.'}), 400

    try:
        stream = io.StringIO(f.read().decode('utf-8', errors='replace'))
    except Exception as exc:
        return jsonify({'error': f'Failed to read file: {exc}'}), 400

    EMAIL_COLUMN = 'Host User Email'
    seen: set = set()
    usernames: list = []

    try:
        reader = csv.DictReader(stream)
        for row in reader:
            email = (row.get(EMAIL_COLUMN) or '').strip()
            if not email:
                # Fallback: first cell value that contains '@'
                for v in row.values():
                    if v and '@' in str(v):
                        email = str(v).strip()
                        break
            if not email:
                continue
            if email.lower().startswith('mailto:'):
                email = email[7:]
            username = email.split('@')[0] if '@' in email else email
            if not _USERNAME_RE.match(username):
                continue
            if username not in seen:
                seen.add(username)
                usernames.append(username)
    except Exception as exc:
        return jsonify({'error': f'Failed to parse CSV: {exc}'}), 400

    if not usernames:
        return jsonify({'error': 'No valid usernames found in CSV.'}), 400

    MAX_CSV_USERS = 2000
    if len(usernames) > MAX_CSV_USERS:
        return jsonify({
            'error': (
                f'CSV contains {len(usernames)} unique users; maximum is {MAX_CSV_USERS}. '
                'Split the file into smaller batches.'
            )
        }), 400

    cfg = current_app.config

    # Single LDAP connection for all unique usernames
    ad_results = active_directory.lookup_users(cfg, usernames)
    found_users = [u for u in ad_results if u.get('found')]

    gw_configured    = not google_workspace._not_configured(cfg)
    entra_configured = not entra_id._not_configured(cfg)

    # Throttle: pause between each user's GW and Entra calls to stay well
    # below API rate limits when processing large CSVs.
    _GW_ENTRA_DELAY = 0.3   # seconds between Google → Entra call per user
    _USER_DELAY     = 0.1   # seconds between users

    results: list = []
    log_entries: list = []

    for user in found_users:
        username = user['username']
        row_actions: list = []

        # 1 · AD reset password (pass dn to skip redundant LDAP lookup)
        try:
            r, d = active_directory.reset_password(cfg, username, dn=user.get('dn'))
        except Exception as exc:
            r, d = 'error', str(exc)
        row_actions.append({'action': 'ad_reset_password', 'result': r, 'detail': d})
        log_entries.append(OperationLog(
            operator=current_user.username, target_username=username,
            action='ad_reset_password', system='AD', result=r, detail=d,
        ))

        # 2 · Google reset sign-in cookies
        time.sleep(_GW_ENTRA_DELAY)
        if gw_configured:
            try:
                r, d = google_workspace.reset_sign_in_cookies(cfg, username)
            except Exception as exc:
                r, d = 'error', str(exc)
            log_entries.append(OperationLog(
                operator=current_user.username, target_username=username,
                action='gw_reset_cookies', system='GW', result=r, detail=d,
            ))
        else:
            r, d = 'skipped', 'Google Workspace not configured'
        row_actions.append({'action': 'gw_reset_cookies', 'result': r, 'detail': d})

        # 3 · Entra revoke sign-in sessions
        time.sleep(_GW_ENTRA_DELAY)
        if entra_configured:
            try:
                r, d = entra_id.revoke_sessions(cfg, username)
            except Exception as exc:
                r, d = 'error', str(exc)
            log_entries.append(OperationLog(
                operator=current_user.username, target_username=username,
                action='entra_revoke_sessions', system='Entra', result=r, detail=d,
            ))
        else:
            r, d = 'skipped', 'Entra ID not configured'
        row_actions.append({'action': 'entra_revoke_sessions', 'result': r, 'detail': d})

        results.append({'username': username, 'found': True, 'actions': row_actions})
        time.sleep(_USER_DELAY)

    # Append not-found entries (no API calls made for these)
    for u in ad_results:
        if not u.get('found'):
            results.append({'username': u['username'], 'found': False, 'actions': []})

    if log_entries:
        db.session.add_all(log_entries)
        db.session.commit()

    # Best-effort email alert (flatten to same shape as /execute results)
    flat = [
        {'username': r['username'], 'action': a['action'],
         'result': a['result'], 'detail': a['detail']}
        for r in results for a in r.get('actions', [])
    ]
    try:
        email_alerts.send_operation_alert(cfg, current_user.username, flat)
    except Exception:
        pass

    return jsonify({
        'total_unique': len(usernames),
        'found':        len(found_users),
        'not_found':    len(usernames) - len(found_users),
        'results':      results,
    })
