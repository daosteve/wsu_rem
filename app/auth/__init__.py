from flask import Blueprint

bp = Blueprint('auth', __name__, url_prefix='/auth')

from app.auth import routes  # noqa: F401, E402
