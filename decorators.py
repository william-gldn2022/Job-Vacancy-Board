from functools import wraps
from flask import redirect, url_for, session, flash

# Controlling the login - decorator used for all webpages except index to ensure user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must log in before accessing this page.', 'warning')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function
