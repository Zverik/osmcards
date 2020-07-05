from . import db
from . import crossing
from flask import Flask
from flask_wtf.csrf import CSRFProtect


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object('www.config_default')

    try:
        app.config.from_object('config')
    except FileNotFoundError:
        raise
        pass
    db.init_app(app)
    app.cli.add_command(db.migrate)
    crossing.oauth.init_app(app)
    csrf = CSRFProtect()
    csrf.init_app(app)

    try:
        from flask_compress import Compress
        Compress(app)
    except ImportError:
        pass

    app.register_blueprint(crossing.cross)
    return app
