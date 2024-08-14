from flask import Flask, render_template, redirect, url_for, request, flash, session, Blueprint
from models import db, bcrypt, User, Job
from decorators import login_required
from waitress import serve
from flask_bootstrap import Bootstrap
import os

app = Blueprint('app', __name__)

app = Flask(__name__)

Bootstrap(app)

class Config:
    SECRET_KEY = 'your_secret_key'
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASEDIR, "instance/job_vacancy_board.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)

ADMIN_PASSWORD = 'makemeadmin'

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('basic_search'))
    
    if request.method == 'POST':
        if 'login' in request.form:
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['role'] = user.role
                return redirect(url_for('basic_search'))
            else:
                flash('Login Failed. Check your username and/or password.')
        elif 'register' in request.form:
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            role = request.form['role']
            admin_password = request.form.get('admin_password', '')

            if password != confirm_password:
                flash('Passwords do not match.')
            elif role == 'Admin' and admin_password != ADMIN_PASSWORD:
                flash('Invalid admin password.')
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(username=username, password=hashed_password, role=role)
                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id
                session['role'] = new_user.role
                return redirect(url_for('basic_search'))
    
    return render_template('index.html')

@app.route('/basic-search', methods=['GET', 'POST'])
@login_required
def basic_search():
    if request.method == 'POST':
        search_term = request.form['search']
        jobs = Job.query.filter(Job.role.contains(search_term)).all()
        return render_template('results.html', jobs=jobs)
    
    return render_template('basic-search.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/results')
@login_required
def results():
    return render_template('results.html')

@app.route('/user-management')
@login_required
def userManagement():
    return render_template('user-management.html')

@app.route('/advert-management')
@login_required
def advertManagement():
    return render_template('advert-management.html')

