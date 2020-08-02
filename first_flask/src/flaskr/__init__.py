import os

from flask import Flask

def create_app(test_config=None):
    # create and config the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path,'flaskr.sqlite')
    )

    if test_config is None:
        # load the actual config file
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config
        app.config.from_mapping(test_config)

    # ensure that the instance folder exist
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # initialize the db with app instance
    from . import db
    db.init_app(app)

    # register the auth blueprint
    from . import auth
    app.register_blueprint(auth.bp)

    return app