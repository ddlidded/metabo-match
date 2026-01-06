import os
import sys

from metabomatch import _compat
sys.modules['flask._compat'] = _compat

import jinja2
import markupsafe
jinja2.Markup = markupsafe.Markup

import werkzeug.urls
import urllib.parse
werkzeug.urls.url_quote = urllib.parse.quote
werkzeug.urls.url_decode = urllib.parse.parse_qs
werkzeug.urls.url_encode = urllib.parse.urlencode

import flask
from werkzeug.local import LocalStack
if not hasattr(flask, '_request_ctx_stack'):
    flask._request_ctx_stack = LocalStack()
if not hasattr(flask, '_app_ctx_stack'):
    flask._app_ctx_stack = LocalStack()

from metabomatch.app import create_app

try:
    from metabomatch.configs.development import DevelopmentConfig as Config
except ImportError:
    from metabomatch.configs.default import DefaultConfig as Config


app = create_app(Config)


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = bool(app.config.get("DEBUG", False))
    use_reloader = os.environ.get("USE_RELOADER", "").lower() in ("1", "true", "yes", "on")
    app.run(host=host, port=port, debug=debug, use_reloader=use_reloader)
