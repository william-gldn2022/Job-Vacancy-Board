import os

class Config:
    SECRET_KEY = 'your_secret_key'
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASEDIR, "instance/job_vacancy_board.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

