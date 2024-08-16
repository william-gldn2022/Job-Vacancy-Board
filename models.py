# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jobRole = db.Column(db.String(100), nullable=False)
    shortDescription = db.Column(db.String(100), nullable=False)
    longDescription = db.Column(db.String(500), nullable=False)
    salary = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(50), nullable=False)
    grade = db.Column(db.String(20), nullable=False)
    

