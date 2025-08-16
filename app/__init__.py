from flask import Flask
from flask_login import LoginManager
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
import secrets
from app.extensions import bcrypt
from os import path
import os
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO
import logging

# logging.getLogger('werkzeug').addFilter(
#     lambda record: "write() before start_response" not in record.getMessage()
# )
# socketio = SocketIO()

from dotenv import load_dotenv
load_dotenv()
loginManager = LoginManager()
loginManager.login_view = 'login.loginController' 
DB_NAME = "database.db"
FERNET_KEY = os.getenv("FERNET_KEY")
fernet = Fernet(FERNET_KEY.encode())

db = SQLAlchemy()
socketio = SocketIO()

def create_app(config='development'):

    app = Flask(__name__)
    socketio.init_app(app)

    if config =='testing':
        app.config['WTF_CSRF_ENABLED'] = False
        app.secret_key = os.getenv('SECRET_KEY')
        app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'TEST_UPLOAD_FOLDER')
    # for DB 
        app.config['SQLALCHEMY_DATABASE_URI'] =  'sqlite:///:memory:'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(app)
        app.config['BCRYPT_LOG_ROUNDS'] = 14
    else:
        
        app.secret_key = os.getenv('SECRET_KEY')
        app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'UPLOAD_FOLDER')
        # for DB 
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
        db.init_app(app)

        app.config['BCRYPT_LOG_ROUNDS'] = 14

 
    @app.after_request
    def add_header(response):
        response.headers["Cache-Control"] = "no-store"
        return response
    
    # Import and register blueprints
    from .login.routes import login
    from .dashboard.routes import dashboard
    from .userRegistration.routes import registerUser
    from .index.routes import main
    from .admin.routes import admin
    from .upload.routes import upload
    from .download.routes import download
    from .auth.routes import auth
    from .deleteFile.routes import deleteFile
    from .share.routes import share
    

    app.register_blueprint(login)
    app.register_blueprint(dashboard)
    app.register_blueprint(registerUser)
    app.register_blueprint(main)
    app.register_blueprint(admin)
    app.register_blueprint(upload)
    app.register_blueprint(download)
    app.register_blueprint(auth)
    app.register_blueprint(deleteFile)
    app.register_blueprint(share)
    # Init login manager
    loginManager.init_app(app)
    bcrypt.init_app(app)

    
        
    csrf = CSRFProtect()
    csrf.init_app(app)
    # all this may break if sql db is changed

    from .models import User 
    
    def load_user(user_id):
        return User.query.get(user_id)
    loginManager.user_loader(load_user)

    createDB(app)

    return app

def createDB(app):
        with app.app_context():
            db.create_all()