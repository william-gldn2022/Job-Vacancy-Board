from flask import Flask
from models import db, bcrypt
import os
from flask_migrate import Migrate

class Config:
    SECRET_KEY = os.environ['SECRET_KEY']
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASEDIR, "instance/job_vacancy_board.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Setting up the app
def create_app(test_config=None):
    app = Flask(__name__, static_url_path=f"/static")
    if test_config is not None:
        app.config.update(test_config)
    else:
        app.config.from_object(Config)
    with app.app_context():
        from main import main
        app.register_blueprint(main)
        app.config.from_object(Config)
        db.init_app(app)
        bcrypt.init_app(app)
        migrate = Migrate(app, db)
        return app