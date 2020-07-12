from . import db
from . import crossing
from flask import Flask, request
from flask_compress import Compress
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel


# TODO: make a function to find these
SUPPORTED_LOCALES = ['en', 'ru']


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
    CSRFProtect(app)
    babel = Babel(app)
    Compress(app)

    def get_locale():
        return request.accept_languages.best_match(SUPPORTED_LOCALES)

    if babel.locale_selector_func is None:
        babel.locale_selector_func = get_locale

    app.register_blueprint(crossing.cross)
    return app
