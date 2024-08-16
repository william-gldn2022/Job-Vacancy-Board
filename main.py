from flask import Flask, render_template, redirect, url_for, request, flash, session, Blueprint
from models import db, bcrypt, User, Job
from decorators import login_required
from waitress import serve
from flask_bootstrap import Bootstrap
import os
from sqlalchemy import or_

main = Blueprint('main', __name__)

app = Flask(__name__)

Bootstrap(app)

ADMIN_PASSWORD = 'makemeadmin'

@main.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('main.basic_search'))
    
    if request.method == 'POST':
        if 'login' in request.form:
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['role'] = user.role
                return redirect(url_for('main.basic_search'))
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
                return redirect(url_for('main.basic_search'))
    
    return render_template('index.html')

@main.route('/basic-search', methods=['GET', 'POST'])
@login_required
def basic_search():
    if request.method == 'POST':
        # Collecting search inputs
        search_term = request.form.get('search', '')
        min_salary = request.form.get('minSalary', None)
        max_salary = request.form.get('maxSalary', None)
        selected_locations = request.form.getlist('locations')
        selected_grades = request.form.getlist('grades')
        selected_job_roles = request.form.getlist('jobRoles')

        # Get the query object from the search function
        jobs_query = search_jobs(
            search_term=search_term,
            min_salary=min_salary,
            max_salary=max_salary,
            selected_locations=selected_locations,
            selected_grades=selected_grades,
            selected_job_roles=selected_job_roles
        )

        # Create a subquery for further filtering
        jobs_subquery = jobs_query.with_entities(Job.id).subquery()

        # Calculate counts based on the filtered jobs only
        location_counts = db.session.query(Job.location, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.location).all()
        grade_counts = db.session.query(Job.grade, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.grade).all()
        job_role_counts = db.session.query(Job.jobRole, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.jobRole).all()

        # Execute the query to get the actual jobs
        jobs = jobs_query.all()

        # Render the results page with the filtered jobs and counts
        return render_template('results.html', jobs=jobs, 
                               location_counts=location_counts, 
                               grade_counts=grade_counts, 
                               job_role_counts=job_role_counts)
    
    return render_template('basic-search.html')

@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index'))

@main.route('/results')
@login_required
def results():
    jobs = Job.query.all()
    location_counts = db.session.query(Job.location, db.func.count(Job.id)).group_by(Job.location).all()
    grade_counts = db.session.query(Job.grade, db.func.count(Job.id)).group_by(Job.grade).all()
    job_role_counts = db.session.query(Job.jobRole, db.func.count(Job.id)).group_by(Job.jobRole).all()

    return render_template('results.html', jobs=jobs, location_counts=location_counts, grade_counts=grade_counts, job_role_counts=job_role_counts)

@main.route('/user-management')
@login_required
def userManagement():
    return render_template('user-management.html')

@main.route('/advert-management')
@login_required
def advertManagement():
    return render_template('advert-management.html')

@main.route('/health', methods=["GET"])
def health():
    return {"Status":"Live"}, 200

def search_jobs(search_term='', min_salary=None, max_salary=None, selected_locations=None, selected_grades=None, selected_job_roles=None):
    query = Job.query.filter(
        or_(
            Job.jobRole.contains(search_term),
            Job.location.contains(search_term),
            Job.shortDescription.contains(search_term)
        )
    )

    if min_salary:
        query = query.filter(Job.salary >= int(min_salary))
    if max_salary:
        query = query.filter(Job.salary <= int(max_salary))

    if selected_locations:
        query = query.filter(Job.location.in_(selected_locations))

    if selected_grades:
        query = query.filter(Job.grade.in_(selected_grades))

    if selected_job_roles:
        query = query.filter(Job.jobRole.in_(selected_job_roles))

    # Return the query object instead of the result set
    return query

