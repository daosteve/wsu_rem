import csv
import io
import re
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
    'gw_reset_cookies',
    'entra_revoke_sessions',
})

SYSTEM_MAP = {
    'ad_disable': 'AD',
    'ad_enable': 'AD',
    'ad_reset_password': 'AD',
    'gw_suspend': 'GW',
    'gw_reset_cookies': 'GW',
    'entra_revoke_sessions': 'Entra',
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

    # Enrich found users with GW last login (best-effort; never blocks the response)
    gw_configured = not google_workspace._not_configured(current_app.config)
    if gw_configured:
        for user in results:
            if user.get('found'):
                user['gw_last_login'] = google_workspace.get_last_login(
                    current_app.config, user['username']
                )

    return jsonify({'users': results})


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
                res = active_directory.disable_user(cfg, username, reason=reason, comment=comment)
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
                original_dn = rec.original_dn if rec else None
                result, detail = active_directory.enable_user(
                    cfg, username,
                    original_dn=original_dn,
                    operator=current_user.username,
                )
                if result == 'success' and rec:
                    qr_to_delete.append(rec)
            elif action == 'ad_reset_password':
                result, detail = active_directory.reset_password(cfg, username)
            elif action == 'gw_suspend':
                result, detail = google_workspace.suspend_user(cfg, username)
            elif action == 'gw_reset_cookies':
                result, detail = google_workspace.reset_sign_in_cookies(cfg, username)
            elif action == 'entra_revoke_sessions':
                result, detail = entra_id.revoke_sessions(cfg, username)
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
