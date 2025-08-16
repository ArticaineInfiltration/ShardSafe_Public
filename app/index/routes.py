from flask import Blueprint, redirect,url_for
from flask_login import current_user
  
main = Blueprint('main', __name__)

@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.landingPage'))
    return redirect(url_for('login.loginController'))

