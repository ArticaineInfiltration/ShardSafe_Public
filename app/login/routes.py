from flask import make_response,Blueprint,jsonify, render_template,json, request,session, redirect, url_for, flash
from flask_login import login_user, logout_user,login_required
import requests
from ..models import User 
from app.forms import LoginForm
from app.static.tools.miscTools import verifySignature, generateRandSalt, generateRandIV,generateFakeKey
import base64

login = Blueprint('login', __name__)


@login.route('/logout')
@login_required
def logoutController():
    session.clear()
    User.logout()

    googleCreds = session.get('gdrive_state')
    if googleCreds:
        try:
            creds = json.loads(googleCreds)
            token = creds.get('access_token') or creds.get('refresh_token')
            if token:
                # Google token revocation endpoint
                requests.post(
                    'https://oauth2.googleapis.com/revoke',
                    params={'token': token},
                    headers={'content-type': 'application/x-www-form-urlencoded'}
                )
        except Exception as e:
            print("Token revocation failed:", e)

    oneDriveCreds = ''


    response = make_response(redirect(url_for('login.loginController')))
    
    for cookie in request.cookies:
        response.delete_cookie(cookie)
    
    return response



@login.route('/login', methods=['GET', 'POST'])
def loginController():
    form = LoginForm()
    #print("Session contents:", dict(session))
    if request.method == 'POST':

        data = request.get_json()
        
        step = data.get('step')
        username = data.get('username')
        print(username)

        # prepare to mock if no results:
        fIV = base64.b64encode(generateRandIV()).decode('utf-8')
        fSalt = generateRandSalt()
        # get the user is any: 
        user = User.query.filter_by(username=username).first()
        nulluserPvtKey =generateFakeKey()
        
        # user is the user found, or None
        # hide that user is None
        
        
        if step == 1:
            nonce = base64.b64encode(generateRandIV()).decode('utf-8') # same code used for rand nonce
            if user is not None:
                session['authNonce'] = nonce
                toReturn = {
                    "iv":user.loginIV,
                    "salt":user.loginSalt,
                    "nonce":nonce,
                    "encryptedPrivateKey":user.loginPrivateKey_encrypted,
                    "status":200}
            else:
                toReturn = {
                    "iv":fIV,
                    "salt":fSalt,
                    "nonce":nonce,
                    "encryptedPrivateKey":nulluserPvtKey,
                    "status":200}
            return jsonify(toReturn)
        if step == 2 :
            signature = data.get('signature')
            #print (signature)

            if signature =="" or signature is None:
                return jsonify(
                    {"flashError": {
                    "message": "Incorrect username or password."
                              }
                    }
            ), 400

            # verify the sig here: 
            if user is not None:
                verified = verifySignature(user.loginPublicKey,session['authNonce'],signature)
                if verified:
                    user = User.authenticate(username)
                    # session['loginPrivateKey_encrypted'] = user.loginPrivateKey_encrypted
                    # session['loginIV'] = user.loginIV
                    # session['loginSalt'] = user.loginSalt
                    
                    if user.role == 'admin' or user.role == 'superadmin':
                        path = '/admin'
                    else:
                        path = '/dashboard'
                    
                    response = make_response(
                        jsonify(
                            {'success':True,
                            'redirect':path,
                            'status':200
                            }
                        )
                    )
                    response.set_cookie('encIV',user.encIV,max_age=3600,secure=True)
                    response.set_cookie('encPrivateKey_encrypted',user.encPrivateKey_encrypted,max_age=3600,secure=True)
                    response.set_cookie('encSalt',user.encSalt,max_age=3600,secure=True)
                    response.set_cookie('encPublicKey',user.encPublicKey,max_age=3600,secure=True)
                    
                    return response
                else:
                    return jsonify(
                        {'success':False,
                         "flashError": {
                    "message": "Incorrect username or password.",
                    'status':469           
                        }
                    }
                    )




    return render_template('login/login.html',form=form)
