import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask ─────────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ['SECRET_KEY']

    # ── Database ──────────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Secure session cookies ────────────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # ── LDAP / Active Directory ───────────────────────────────────────────────
    LDAP_HOST = os.environ['LDAP_HOST']
    LDAP_PORT = int(os.environ.get('LDAP_PORT', 636))
    LDAP_USE_SSL = True
    LDAP_CA_CERT_FILE = os.environ.get('LDAP_CA_CERT_FILE', '')  # path to CA bundle if self-signed
    LDAP_BASE_DN = os.environ['LDAP_BASE_DN']
    LDAP_BIND_DN = os.environ['LDAP_BIND_DN']
    LDAP_BIND_PASSWORD = os.environ['LDAP_BIND_PASSWORD']
    LDAP_USER_SEARCH_BASE = os.environ.get('LDAP_USER_SEARCH_BASE') or os.environ['LDAP_BASE_DN']
    # Map of subdomain label → DC hostname for write operations (port 636).
    # Format: "LABEL=hostname,LABEL2=hostname2"  (labels are case-insensitive)
    # Example: "WSC=wsc_domain.worcester.edu,ACL=acl_domain.worcester.edu"
    LDAP_WRITE_HOSTS = {
        k.strip().upper(): v.strip()
        for pair in os.environ.get('LDAP_WRITE_HOSTS', '').split(',')
        if '=' in pair
        for k, v in [pair.split('=', 1)]
    }

    # Comma-separated CN names of AD groups allowed to log in
    LDAP_ALLOWED_GROUPS = [g.strip() for g in os.environ.get('LDAP_ALLOWED_GROUPS', '').split(',') if g.strip()]
    # Comma-separated CN names of AD groups that get admin access (log search)
    LDAP_ADMIN_GROUPS = [g.strip() for g in os.environ.get('LDAP_ADMIN_GROUPS', '').split(',') if g.strip()]

    # ── AD remediation ────────────────────────────────────────────────────────
    AD_RESET_PASSWORD = os.environ['AD_RESET_PASSWORD']

    # ── Google Workspace ──────────────────────────────────────────────────────
    # See docs/google_workspace_setup.md for service-account setup instructions
    GW_SERVICE_ACCOUNT_FILE = os.environ.get('GW_SERVICE_ACCOUNT_FILE', '')
    GW_DELEGATED_ADMIN = os.environ.get('GW_DELEGATED_ADMIN', '')

    # ── Microsoft Entra ID ────────────────────────────────────────────────────
    # See docs/entra_id_setup.md for app-registration setup instructions
    ENTRA_TENANT_ID = os.environ.get('ENTRA_TENANT_ID', '')
    ENTRA_CLIENT_ID = os.environ.get('ENTRA_CLIENT_ID', '')
    ENTRA_CLIENT_SECRET = os.environ.get('ENTRA_CLIENT_SECRET', '')
    # UPN suffix used to build user@domain from a bare sAMAccountName.
    # e.g. 'worcester.edu'  →  hdao10 becomes hdao10@worcester.edu
    ENTRA_UPN_SUFFIX = os.environ.get('ENTRA_UPN_SUFFIX', '')

    # ── Rate limiting ─────────────────────────────────────────────────────────
    # Recommended: set to a Redis URL for persistent rate-limit storage.
    # e.g. redis://localhost:6379/0  (requires redis package)
    # Leave unset to use in-memory storage (fine for a single-process deployment).
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')

    # ── Email alerts ──────────────────────────────────────────────────────────
    SMTP_HOST = os.environ.get('SMTP_HOST', 'localhost')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 25))
    SMTP_FROM = os.environ.get('SMTP_FROM', 'wsu-rem@localhost')
    ALERT_RECIPIENTS = [r.strip() for r in os.environ.get('ALERT_RECIPIENTS', '').split(',') if r.strip()]
