from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.forms import RegisterForm
import os,base64
from app.models import User
from app import db
from ..extensions import bcrypt




def generateRandSalt(length=16):
    return base64.b64encode(os.urandom(length)).decode()

registerUser = Blueprint('registerUser', __name__)  # name + import name

@registerUser.route('/register', methods=['GET', 'POST'])
def registerUserController():
    form = RegisterForm()
    if request.method =='GET':
        if request.args.get('error') == 'weak_password':
          
            flash("Password must be at least 8 characters long, include an uppercase letter, a number, and a special character.", "danger")
            return redirect(url_for('registerUser.registerUserController'))
        if request.args.get('error') == 'mismatch_password':
            flash("Passwords do not match!", "danger")
            return redirect(url_for('registerUser.registerUserController'))
        
        
    if request.method == 'POST':
        # print("GOT POST")
       
        
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data

            encPublicKey = form.encPublicKey.data
            encPrivateKey = form.encPrivateKey.data
            encIV = form.encIV.data
            encSalt =form.encSalt.data

            loginPublicKey = form.loginPublicKey.data
            loginPrivateKey = form.loginPrivateKey.data
            loginIV = form.loginIV.data
            loginSalt =form.loginSalt.data

            resetPrivateKey_encrypted = form.resetPrivateKey_encrypted.data
            resetIV = form.resetIV.data

            resetEncPrivateKey_encrypted = form.resetEncPrivateKey_encrypted.data
            resetEncIV = form.resetEncIV.data

            
            # print("pvtKeY: \n"+ privateKey)
           
            success = User.registerUser(username,email,
                                        loginPublicKey=loginPublicKey,loginPrivateKey_encrypted=loginPrivateKey,loginIV=loginIV,loginSalt=loginSalt,
                                        encPublicKey=encPublicKey,encPrivateKey_encrypted=encPrivateKey,encIV=encIV, encSalt=encSalt,
                                        resetPrivateKey_encrypted=resetPrivateKey_encrypted,resetIV=resetIV,
                                        resetEncPrivateKey_encrypted=resetEncPrivateKey_encrypted,resetEncIV=resetEncIV )
            if success:
                 return(redirect(url_for('login.loginController')))

         
        for field, errors in form.errors.items():
                for error in errors:
                    print(error)
                    flash(f"ERROR: {error}", category='error')
        return redirect(url_for('registerUser.registerUserController'))


    return render_template('registration/register.html',form=form)