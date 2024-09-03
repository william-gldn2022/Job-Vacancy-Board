from flask import Flask, render_template, redirect, url_for, request, flash, session, Blueprint
from models import db, bcrypt, User, Job
from decorators import login_required
from flask_bootstrap import Bootstrap
import os
from sqlalchemy import or_
import re

# Configuration and Initialisation
app = Flask(__name__)
Bootstrap(app)

ADMIN_PASSWORD = 'makemeadmin'

# Blueprint Registration
main = Blueprint('main', __name__)

# Utility Functions - Password Checking, Job Searching, Filter Count
def validate_password(password, confirm_password=None):
    # Validates password according to the specified rules
    if confirm_password is not None and password != confirm_password:
        return "Passwords do not match."
    if len(password) < 8:
        return "Password needs to be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password needs to contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password needs to contain at least one lowercase letter."
    if not re.search(r'[\W_]', password):
        return "Password needs to contain at least one special character."
    return None

def search_jobs(search_term='', min_salary=None, max_salary=None, selected_locations=None, selected_grades=None, selected_job_roles=None):
    # Constructs a search query for jobs based on the provided filters.
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

    return query

def get_filter_counts(jobs_subquery):
    #Gets counts of jobs grouped by location, grade, and job role.
    location_counts = db.session.query(Job.location, db.func.count(Job.id)).filter(
        Job.id.in_(jobs_subquery)).group_by(Job.location).all()
    grade_counts = db.session.query(Job.grade, db.func.count(Job.id)).filter(
        Job.id.in_(jobs_subquery)).group_by(Job.grade).all()
    job_role_counts = db.session.query(Job.jobRole, db.func.count(Job.id)).filter(
        Job.id.in_(jobs_subquery)).group_by(Job.jobRole).all()

    return location_counts, grade_counts, job_role_counts

# Routes
@main.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('main.basic_search'))

    if request.method == 'POST':
        # Determine whether it's a login or registration attempt
        if 'login' in request.form:
            return handle_login()
        elif 'register' in request.form:
            return handle_registration()

    return render_template('index.html')

def handle_login():
    # Handles the login process
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['role'] = user.role
        session['username'] = user.username
        return redirect(url_for('main.basic_search'))
    else:
        flash('Login Failed. Check your username and/or password.')
    return redirect(url_for('main.index'))

def handle_registration():
    # Handles the registration process.
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    role = request.form['role']
    admin_password = request.form.get('admin_password', '')

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already taken. Please choose a different one.')
        return redirect(url_for('main.index'))

    password_error = validate_password(password, confirm_password)
    if password_error:
        flash(password_error)
        return redirect(url_for('main.index'))

    if role == 'Admin' and admin_password != ADMIN_PASSWORD:
        flash('Invalid admin password.')
        return redirect(url_for('main.index'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    session['user_id'] = new_user.id
    session['role'] = new_user.role
    session['username'] = new_user.username
    return redirect(url_for('main.basic_search'))

#Carries out searching functionality - also responsible for loading searchbar if no search requested
@main.route('/basic-search', methods=['GET', 'POST'])
@login_required
def basic_search():
    if request.method == "POST":

        search_term = request.form.get('search', request.args.get('search', ''))
        min_salary = request.form.get('minSalary', request.args.get('minSalary', None))
        max_salary = request.form.get('maxSalary', request.args.get('maxSalary', None))
        selected_locations = request.form.getlist('locations')
        selected_grades = request.form.getlist('grades')
        selected_job_roles = request.form.getlist('jobRoles')

        jobs_query = search_jobs(
            search_term=search_term,
            min_salary=min_salary,
            max_salary=max_salary,
            selected_locations=selected_locations,
            selected_grades=selected_grades,
            selected_job_roles=selected_job_roles
        )

        jobs_subquery = jobs_query.with_entities(Job.id).subquery()
        location_counts, grade_counts, job_role_counts = get_filter_counts(jobs_subquery)

        jobs = jobs_query.all() if request.method == 'POST' else []

        return render_template('results.html',
                            jobs=jobs,
                            location_counts=location_counts,
                            grade_counts=grade_counts,
                            job_role_counts=job_role_counts,
                            search_term=search_term,
                            min_salary=min_salary,
                            max_salary=max_salary,
                            selected_locations=selected_locations,
                            selected_grades=selected_grades,
                            selected_job_roles=selected_job_roles)
    
    return render_template('basic-search.html')

# User logout route
@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index'))

#Shows results from searches
@main.route('/results')
@login_required
def results():
    jobs = Job.query.all()
    jobs_subquery = db.session.query(Job.id).subquery()
    location_counts, grade_counts, job_role_counts = get_filter_counts(jobs_subquery)

    return render_template('results.html', jobs=jobs, location_counts=location_counts, grade_counts=grade_counts, job_role_counts=job_role_counts)

#Shows table of adverts for admin use
@main.route('/advert-management')
@login_required
def advert_management():
    if session.get('role') != 'Admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.index'))

    jobs = Job.query.all()
    return render_template('advert-management.html', jobs=jobs)

#Adds new advert to db
@main.route('/advert-management/add', methods=['POST'])
@login_required
def add_job():
    if session['role'] != 'Admin':
        flash('Unauthorised access!', 'danger')
        return redirect(url_for('main.advert_management'))

    job = Job(
        jobRole=request.form['jobRole'],
        shortDescription=request.form['shortDescription'],
        longDescription=request.form['longDescription'],
        grade=request.form['grade'],
        location=request.form['location'],
        salary=request.form['salary']
    )
    db.session.add(job)
    db.session.commit()
    flash('Job added successfully!', 'success')
    return redirect(url_for('main.advert_management'))

#Edits existing ad in db
@main.route('/advert-management/edit/<job_id>', methods=['POST'])
@login_required
def edit_job(job_id):
    if session.get('role') != 'Admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.index'))

    job = Job.query.get_or_404(job_id)
    job.jobRole = request.form['jobRole']
    job.shortDescription = request.form['shortDescription']
    job.longDescription = request.form['longDescription']
    job.grade = request.form['grade']
    job.location = request.form['location']
    job.salary = request.form['salary']
    db.session.commit()
    flash('Job updated successfully!', 'success')
    return redirect(url_for('main.advert_management'))

#Deletes advert from db
@main.route('/advert-management/delete/<job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    if session.get('role') != 'Admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.index'))

    job = Job.query.get_or_404(job_id)
    db.session.delete(job)
    db.session.commit()
    flash('Job deleted successfully!', 'success')
    return redirect(url_for('main.advert_management'))

# Loads user management table for admin
@main.route('/user-management')
@login_required
def user_management():
    if session.get('role') != 'Admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.index'))

    users = User.query.all()
    return render_template('user-management.html', users=users)

#Allows the admin to add a new user.
@main.route('/user-management/add', methods=['POST'])
@login_required
def add_user():
    if session.get('role') != 'Admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.user_management'))

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists!', 'danger')
        return redirect(url_for('main.user_management'))
    
    password_error = validate_password(password)
    if password_error:
        flash(password_error, 'danger')
        return redirect(url_for('main.user_management'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    flash('User added successfully!', 'success')
    return redirect(url_for('main.user_management'))

# Allows the admin to edit an existing user
@main.route('/user-management/edit/<user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if session.get('role') != 'Admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.user_management'))

    user = User.query.get_or_404(user_id)
    user.username = request.form['username']
    new_password = request.form['password']
    if new_password:
        password_error = validate_password(new_password)
        if password_error:
            flash(password_error, 'danger')
            return redirect(url_for('main.user_management'))
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.role = request.form['role']
    db.session.commit()
    flash('User updated successfully!', 'success')
    return redirect(url_for('main.user_management'))

# Allows the admin to delete an existing user.
@main.route('/user-management/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session.get('role') != 'Admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.user_management'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('main.user_management'))

@main.route('/health', methods=["GET"])
def health():
    return {'Status': 'Live'}, 200
