from flask import Blueprint

bp = Blueprint('quarantine', __name__, url_prefix='/')

from app.quarantine import routes  # noqa: F401, E402
