from datetime import datetime, timedelta
from functools import wraps
import re

from flask import render_template, request, jsonify, abort, current_app
from flask_login import login_required, current_user

from app.logs import bp
from app.models import OperationLog
from app import db
from app.services import active_directory, google_workspace

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-]{1,64}$')

_REMEDIATE_ACTIONS = {
    'ad_enable':         ('AD', active_directory.enable_user),
    'ad_reset_password': ('AD', active_directory.reset_password),
    'gw_unsuspend':      ('GW', google_workspace.unsuspend_user),
}


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


@bp.route('/')
@login_required
@admin_required
def index():
    return render_template('logs.html')


@bp.route('/search')
@login_required
@admin_required
def search():
    q_operator = request.args.get('operator', '').strip()
    q_username = request.args.get('username', '').strip()
    q_system   = request.args.get('system', '').strip()
    q_action   = request.args.get('action', '').strip()
    q_result   = request.args.get('result', '').strip()
    q_from     = request.args.get('from_date', '').strip()
    q_to       = request.args.get('to_date', '').strip()

    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1

    query = OperationLog.query

    if q_operator:
        query = query.filter(OperationLog.operator.ilike(f'%{q_operator}%'))
    if q_username:
        query = query.filter(OperationLog.target_username.ilike(f'%{q_username}%'))
    if q_system in ('AD', 'GW', 'Entra'):
        query = query.filter(OperationLog.system == q_system)
    if q_action:
        query = query.filter(OperationLog.action == q_action)
    if q_result in ('success', 'error'):
        query = query.filter(OperationLog.result == q_result)
    if q_from:
        try:
            query = query.filter(OperationLog.timestamp >= datetime.fromisoformat(q_from))
        except ValueError:
            pass
    if q_to:
        try:
            to_dt = datetime.fromisoformat(q_to) + timedelta(days=1)
            query = query.filter(OperationLog.timestamp < to_dt)
        except ValueError:
            pass

    pagination = query.order_by(OperationLog.timestamp.desc()).paginate(
        page=page, per_page=25, error_out=False
    )

    rows = [
        {
            'id': r.id,
            'timestamp': r.timestamp.isoformat(sep=' ', timespec='seconds'),
            'operator': r.operator,
            'target_username': r.target_username,
            'action': r.action,
            'system': r.system,
            'result': r.result,
            'detail': r.detail or '',
        }
        for r in pagination.items
    ]

    return jsonify({
        'rows': rows,
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page,
    })


@bp.route('/remediate', methods=['POST'])
@login_required
@admin_required
def remediate():
    """Execute a re-enable or password-reset action from the logs page and record it."""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    action = str(data.get('action', '')).strip()

    if not _USERNAME_RE.match(username):
        return jsonify({'error': 'Invalid username.'}), 400
    if action not in _REMEDIATE_ACTIONS:
        return jsonify({'error': 'Invalid action.'}), 400

    system, fn = _REMEDIATE_ACTIONS[action]
    kwargs = {}
    if action == 'ad_reset_password':
        password = str(data.get('password', '')).strip()
        if not password:
            return jsonify({'error': 'Password is required.'}), 400
        if len(password) > 256:
            return jsonify({'error': 'Password too long.'}), 400
        kwargs['new_password'] = password
    try:
        result, detail = fn(current_app.config, username, **kwargs)
    except Exception as exc:
        result, detail = 'error', str(exc)

    entry = OperationLog(
        operator=current_user.username,
        target_username=username,
        action=action,
        system=system,
        result=result,
        detail=detail,
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify({'result': result, 'detail': detail})
