from flask import Flask
from models import db, bcrypt
import os

class Config:
    SECRET_KEY = 'your_secret_key'
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASEDIR, "instance/job_vacancy_board.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

def create_app():
    app = Flask(__name__, static_url_path=f"/static")
    with app.app_context():
        from main import main
        app.register_blueprint(main)
        app.config.from_object(Config)
        db.init_app(app)
        bcrypt.init_app(app)
        return app