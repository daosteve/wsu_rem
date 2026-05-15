from datetime import datetime
from flask_login import UserMixin
from flask import session
from app import db, login_manager


class User(UserMixin):
    """In-memory user for Flask-Login. Authenticated via LDAP; not stored in DB."""

    def __init__(self, username: str, display_name: str, is_admin: bool = False):
        self.id = username
        self.username = username
        self.display_name = display_name
        self.is_admin = is_admin


@login_manager.user_loader
def load_user(user_id: str):
    # Reconstruct User from session data set during login.
    if session.get('username') == user_id:
        return User(
            username=user_id,
            display_name=session.get('display_name', user_id),
            is_admin=session.get('is_admin', False),
        )
    return None


class OperationLog(db.Model):
    __tablename__ = 'operation_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    operator = db.Column(db.String(128), nullable=False)
    target_username = db.Column(db.String(128), nullable=False, index=True)
    action = db.Column(db.String(64), nullable=False)
    system = db.Column(db.String(32), nullable=False)   # AD | GW | Entra
    result = db.Column(db.String(16), nullable=False)   # success | error
    detail = db.Column(db.Text)
    reason  = db.Column(db.String(128))                  # quarantine reason
    comment = db.Column(db.Text)                         # optional operator comment


class QuarantineRecord(db.Model):
    """Tracks the original AD DN of quarantined accounts so they can be
    moved back to their original OU when re-enabled."""
    __tablename__ = 'quarantine_records'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), nullable=False, unique=True, index=True)
    original_dn = db.Column(db.Text, nullable=False)
    quarantined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
