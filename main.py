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
                session['username'] = user.username
                return redirect(url_for('main.basic_search'))
            else:
                flash('Login Failed. Check your username and/or password.')
        elif 'register' in request.form:
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            role = request.form['role']
            admin_password = request.form.get('admin_password', '')

            # Check if username is already taken
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already taken. Please choose a different one.')
            elif password != confirm_password:
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
                session['username'] = new_user.username
                return redirect(url_for('main.basic_search'))
    
    return render_template('index.html')

@main.route('/basic-search', methods=['GET', 'POST'])
@login_required
def basic_search():
    # Retrieve search term and filters from the request
    search_term = request.form.get('search', request.args.get('search', ''))
    min_salary = request.form.get('minSalary', request.args.get('minSalary', None))
    max_salary = request.form.get('maxSalary', request.args.get('maxSalary', None))
    selected_locations = request.form.getlist('locations')
    selected_grades = request.form.getlist('grades')
    selected_job_roles = request.form.getlist('jobRoles')

    if request.method == 'POST':
        # Apply filters based on the form submission
        jobs_query = search_jobs(
            search_term=search_term,
            min_salary=min_salary,
            max_salary=max_salary,
            selected_locations=selected_locations,
            selected_grades=selected_grades,
            selected_job_roles=selected_job_roles
        )

        jobs_subquery = jobs_query.with_entities(Job.id).subquery()

        location_counts = db.session.query(Job.location, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.location).all()
        grade_counts = db.session.query(Job.grade, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.grade).all()
        job_role_counts = db.session.query(Job.jobRole, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.jobRole).all()

        jobs = jobs_query.all()

        return render_template('results.html', jobs=jobs, 
                               location_counts=location_counts, 
                               grade_counts=grade_counts, 
                               job_role_counts=job_role_counts,
                               search_term=search_term,
                               min_salary=min_salary,
                               max_salary=max_salary,
                               selected_locations=selected_locations,
                               selected_grades=selected_grades,
                               selected_job_roles=selected_job_roles)

    # For GET requests, initialize the counts without any filters
    jobs_query = search_jobs(
        search_term=search_term,
        min_salary=min_salary,
        max_salary=max_salary,
        selected_locations=selected_locations,
        selected_grades=selected_grades,
        selected_job_roles=selected_job_roles
    )

    jobs_subquery = jobs_query.with_entities(Job.id).subquery()

    location_counts = db.session.query(Job.location, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.location).all()
    grade_counts = db.session.query(Job.grade, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.grade).all()
    job_role_counts = db.session.query(Job.jobRole, db.func.count(Job.id)).filter(Job.id.in_(jobs_subquery)).group_by(Job.jobRole).all()

    return render_template('basic-search.html',
                           location_counts=location_counts, 
                           grade_counts=grade_counts, 
                           job_role_counts=job_role_counts,
                           search_term=search_term,
                           min_salary=min_salary,
                           max_salary=max_salary,
                           selected_locations=selected_locations,
                           selected_grades=selected_grades,
                           selected_job_roles=selected_job_roles)

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


@main.route('/advert-management')
@login_required
def advert_management():
    if session.get('role') != 'Admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.index'))

    jobs = Job.query.all()
    return render_template('advert-management.html', jobs=jobs)

@main.route('/advert-management/add', methods=['POST'])
@login_required
def add_job():
    if session['role'] != 'Admin':
        flash('Unauthorised access!', 'danger')
        return redirect(url_for('main.advert_management'))

    jobRole = request.form['jobRole']
    shortDescription = request.form['shortDescription']
    longDescription = request.form['longDescription']
    grade = request.form['grade']
    location = request.form['location']
    salary = request.form['salary']
    
    # Create a new job
    new_job = Job(jobRole=jobRole, shortDescription=shortDescription, longDescription=longDescription, grade=grade, location=location, salary=salary)
    db.session.add(new_job)
    db.session.commit()
    flash('Job added successfully!', 'success')
    return redirect(url_for('main.advert_management'))

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


@main.route('/user-management', methods=['GET'])
@login_required
def user_management():
    # Check if the user is an admin
    if session['role'] == 'Admin':
        users = User.query.all()  # Fetch all users for admin
    else:
        users = [User]  # Fetch only the current user for non-admins

    return render_template('user-management.html', users=users)

@main.route('/user-management/add', methods=['POST'])
@login_required
def add_user():
    if session['role'] != 'Admin':
        flash('Unauthorised access!', 'danger')
        return redirect(url_for('main.user_management'))

    username = request.form['username']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    role = request.form['role']
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already taken. Please choose a different one.')
    else:
        # Create a new user
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('main.user_management'))

@main.route('/user-management/edit/<user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if session['role'] == 'Admin':
        new_username = request.form['username']
        new_role = request.form['role']

        # Check if the username is changing and perform the uniqueness check
        if user.username != new_username:
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                flash('Username already taken. Please choose a different one.')
                return redirect(url_for('main.user_management'))
            user.username = new_username
        user.role = new_role

    # Both admin and user can change password
    if request.form['password']:
        if request.form['password'] != request.form['confirm_password']:
            flash('Passwords did not match.')
        else:
            user.password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('main.user_management'))

    return redirect(url_for('main.user_management'))

@main.route('/user-management/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session['role'] != 'Admin':
        flash('Unauthorised access!', 'danger')
        return redirect(url_for('main.user_management'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('main.user_management'))

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

