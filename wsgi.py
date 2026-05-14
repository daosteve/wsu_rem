import os
from werkzeug.middleware.proxy_fix import ProxyFix
from app import create_app

app = create_app()

# Trust N proxy hops as set by WSU_REM_TRUSTED_PROXY_COUNT (matches wsu_sws pattern)
_proxy_count = int(os.environ.get('WSU_REM_TRUSTED_PROXY_COUNT', '1'))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_count, x_proto=_proxy_count, x_host=_proxy_count)

if __name__ == '__main__':
    app.run()
