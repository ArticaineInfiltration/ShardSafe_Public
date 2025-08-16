from flask import Flask,render_template,request,Blueprint,redirect,session,url_for,flash
from app.forms import AWSCredentialsForm
from app.forms import ForgotPasswordForm
from app.forms import ResetPasswordForm
import boto3, requests
from botocore.exceptions import ClientError,EndpointConnectionError
from flask_login import current_user,login_required
from app.admin import adminModeBlock
from app.models import User
from app import db
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseUpload
from app.static.tools.miscTools import creds_to_dict
from msal import ConfidentialClientApplication
from app.extensions import bcrypt

import os 


## manage all the auth and linking stuff here 
GOOGLE_DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
GOOGLE_CLIENT_SECRETS_FILE = "google_client_secret_file.json"
AUTHORITY = f"https://login.microsoftonline.com/common"
ONEDRIVE_SCOPES = ["Files.ReadWrite.All"]



auth = Blueprint('auth',__name__)


@auth.route('/auth/aws',methods =['POST'])                                                                                                                                                                                                                                                                              #Ignore all other content on this page
@adminModeBlock
@login_required
def bindAWSCreds():
    form = AWSCredentialsForm()
    if form.validate_on_submit():
        accessKey = form.accessKey.data
        secretAccessKey = form.secretAccessKey.data
        bucketName = form.bucketName.data
        region = form.region.data
        useARN = form.useARN.data
        # test valid creds
        s3 = boto3.client('s3', aws_access_key_id=accessKey, 
                          aws_secret_access_key=secretAccessKey, 
                          region_name=region)
        
        try:

            if useARN:
                 # use sts to get creds 
                awsSession = boto3.Session(
                aws_access_key_id=accessKey,
                aws_secret_access_key=secretAccessKey
                )
                iam = awsSession.client('sts')  

                identity = iam.get_caller_identity()
                arn = identity['Arn']
                
                # add the arn to db for later sharing use
                current_user.AWSARN = arn
                db.session.add(current_user)
                db.session.commit()

            s3.head_bucket(Bucket=bucketName)

            #if it succeeds, bind the creds
            session['AWS_CREDS'] = {
                 "access_key":accessKey,
                 "secret_access_key":secretAccessKey,
                 "bucket_name": bucketName,
                 "region":region
            }
            
            current_user.updateCloudsInfoBySelf()
            flash(f"AWS S3 Credentials successfully saved - using Bucket {bucketName}",'success')
            return redirect(url_for('dashboard.cloudIntegrationPage'))
        except EndpointConnectionError as e:
            flash(f"ERROR: Could not connect to AWS endpoint. Check your region and network.", "danger")
        except ClientError as e:
            errorCode = e.response['Error']['Code']
            print(errorCode)
            if errorCode == 403:
                flash(f"ERROR: Error connecting to bucket (403).",'error')
            elif errorCode == 404:
                    flash(f"Bucket '{bucketName}' does not exist.",'error')
            elif errorCode == 'InvalidClientTokenId':
                 flash("ERROR: The AWS Credentials are not valid",'error')
            else:
                    flash(f"ERROR: Error checking bucket: {e}",'error')
            return redirect(url_for('dashboard.cloudIntegrationPage'))



    return redirect(url_for('dashboard.cloudIntegrationPage'))

@auth.route('/logout/aws',methods =['GET'])
def releaseAWSCreds():
     session.pop('AWS_CREDS',None)
     current_user.updateCloudsInfoBySelf()
     return redirect(url_for('dashboard.cloudIntegrationPage'))



@auth.route('/login/gdrive')
def login_gdrive():
    flow = Flow.from_client_secrets_file(GOOGLE_CLIENT_SECRETS_FILE, scopes=GOOGLE_DRIVE_SCOPES, redirect_uri=url_for('auth.callback_gdrive', _external=True))
    auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['gdrive_state'] = state
    return redirect(auth_url)


@auth.route('/callback/gdrive')
def callback_gdrive():
    state = session.pop('gdrive_state', None)
    flow = Flow.from_client_secrets_file(GOOGLE_CLIENT_SECRETS_FILE, scopes=GOOGLE_DRIVE_SCOPES, state=state, redirect_uri=url_for('auth.callback_gdrive', _external=True))
    flow.fetch_token(authorization_response=request.url)
    session['GOOGLEDRIVE_CREDS'] = creds_to_dict(flow.credentials)
    current_user.updateCloudsInfoBySelf()
    flash('Google Drive connected', 'success')
    return redirect(url_for('dashboard.cloudIntegrationPage'))

@auth.route('/logout/gdrive')
def logout_gdrive():
    session.pop('GOOGLEDRIVE_CREDS', None)
    current_user.updateCloudsInfoBySelf()
    flash('Logged out from Google Drive.', 'success')
    return redirect(url_for('dashboard.cloudIntegrationPage'))



def build_msal_app():
    CLIENT_ID = os.getenv('CLIENT_ID')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET')
    return ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)


@auth.route('/login/onedrive')
def login_onedrive():
    msal_app = build_msal_app()
    auth_url = msal_app.get_authorization_request_url(ONEDRIVE_SCOPES, redirect_uri=url_for('auth.callback_onedrive', _external=True))
    return redirect(auth_url)



@auth.route('/callback/onedrive')
def callback_onedrive():
    code = request.args.get('code')
    msal_app = build_msal_app()
    result = msal_app.acquire_token_by_authorization_code(code, scopes=ONEDRIVE_SCOPES, redirect_uri=url_for('auth.callback_onedrive', _external=True))
    if 'access_token' in result:
        session['ONEDRIVE_CREDS'] = result['access_token']
        current_user.updateCloudsInfoBySelf()
        flash('OneDrive authentication successful', 'success')
    else:
        flash(f"OneDrive authentication failed: {result.get('error_description')}", 'error')
    return redirect(url_for('dashboard.cloudIntegrationPage'))


@auth.route('/logout/onedrive')
def logout():
    session.pop('ONEDRIVE_CREDS', None)
    current_user.updateCloudsInfoBySelf()
    flash('You have been logged out.', 'success')
    return redirect('https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=' + url_for('dashboard.cloudIntegrationPage', _external=True))


@auth.route('/forgot-password-prefetch', methods=['POST'])
def forgotPasswordFetchController():
    data = request.get_json()
    username = data.get('username')

    user = User.query.filter_by(username=username).first()
    if not user:
        return {"success": False, "message": "Username not found"}, 404

    print('return success ')
    return {
        "success": True,
        "resetPrivateKey": user.resetPrivateKey_encrypted,
        "resetIV": user.resetIV,
        "resetEncPrivateKey": user.resetEncPrivateKey_encrypted,
        "resetEncIV": user.resetEncIV
    }, 200

@auth.route('/forgot-password', methods=['POST'])
def resetPasswordController():
    data = request.get_json()
    username = data.get('username')
    loginPrivateKey = data.get('newPrivateKey')
    loginIV = data.get('newLoginIV')
    encPrivateKey = data.get('newEncPrivateKey')
    encIV = data.get('newEncIV')

    
    
    
    loginSalt = data.get('loginSalt')
    encSalt = data.get('encSalt')

    new_password_hash = data.get('newPasswordHash')

    user = User.query.filter_by(username=username).first()
    if not user:
        return {"success": False, "message": "Username not found"}, 404

    user.loginPrivateKey_encrypted = loginPrivateKey
    user.loginSalt = loginSalt
    user.loginIV = loginIV

    user.encPrivateKey_encrypted = encPrivateKey
    user.encSalt = encSalt
    user.encIV = encIV

    # user.hashedPass = new_password_hash

    try:
        db.session.commit()
        print('success')
        return {"success": True, "message": "Password reset successful"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500

@auth.route('/resetpassword')
def reset_password_page():
    return render_template('login/resetpassword.html')
