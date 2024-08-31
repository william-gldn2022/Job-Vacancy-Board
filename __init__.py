from flask import Flask
from models import db, bcrypt
import os
from flask_migrate import Migrate

class Config:
    SECRET_KEY = 'your_secret_key'
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASEDIR, "instance/job_vacancy_board.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Setting up the app
def create_app():
    app = Flask(__name__, static_url_path=f"/static")
    with app.app_context():
        from main import main
        app.register_blueprint(main)
        app.config.from_object(Config)
        db.init_app(app)
        bcrypt.init_app(app)
        migrate = Migrate(app, db)
        return app