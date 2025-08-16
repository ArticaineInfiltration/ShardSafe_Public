from functools import wraps
from flask import abort,flash,redirect,url_for
from flask_login import login_required,current_user

def adminRequired(f):
    @wraps(f)
    @login_required
    def decoratedFunction(*args, **kwargs):
        if current_user.role not in ['admin', 'superadmin'] :
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decoratedFunction

def adminModeBlock(f):
    @wraps(f)
    @login_required
    def decoratedFunction(*args, **kwargs):
        if current_user.role == 'admin' or current_user.role == 'superadmin':
            flash('This feature is not available to admins','error')
            return(redirect(url_for('admin.adminLandingPage')))
              # Forbidden
        return f(*args, **kwargs)
    return decoratedFunction