#!/usr/bin/env python3
import os
import math
import json
import requests
import boto3
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session
from msal import ConfidentialClientApplication
from zfec.easyfec import Encoder
from botocore.exceptions import ClientError
import google.oauth2.credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseUpload

app = Flask(__name__)
app.secret_key = os.urandom(32)

app.config['MAX_CONTENT_LENGTH'] = 600 * 1024 * 1024  # 600 MiB limit

TOTAL_SHARES = 5
THRESHOLD = 3

aws_key= None
aws_secret= None
aws_bucket= None
aws_region= None


TENANT_ID = 'common'
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
ONEDRIVE_SCOPES = ["Files.ReadWrite.All"]
GOOGLE_DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
GOOGLE_CLIENT_SECRETS_FILE = '/home/user/FYP/google_client_secret.json'

def build_msal_app():
    return ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)

@app.route('/')
def index():
    upload_folder = os.path.join(os.getcwd(), "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    files = os.listdir(upload_folder)
    return render_template('index.html', files=files, logged_in=('token' in session), gdrive_logged_in=('gdrive_token' in session))

@app.route('/login/onedrive')
def login_onedrive():
    msal_app = build_msal_app()
    auth_url = msal_app.get_authorization_request_url(ONEDRIVE_SCOPES, redirect_uri=url_for('callback_onedrive', _external=True))
    return redirect(auth_url)

@app.route('/callback/onedrive')
def callback_onedrive():
    code = request.args.get('code')
    msal_app = build_msal_app()
    result = msal_app.acquire_token_by_authorization_code(code, scopes=ONEDRIVE_SCOPES, redirect_uri=url_for('callback_onedrive', _external=True))
    if 'access_token' in result:
        session['token'] = result['access_token']
        flash('OneDrive authentication successful', 'success')
    else:
        flash(f"OneDrive authentication failed: {result.get('error_description')}", 'error')
    return redirect(url_for('intergrate'))

@app.route('/logout')
def logout():
    session.pop('token', None)
    flash('You have been logged out.', 'success')
    return redirect('https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=' + url_for('intergrate', _external=True))

@app.route('/login/gdrive')
def login_gdrive():
    flow = Flow.from_client_secrets_file(GOOGLE_CLIENT_SECRETS_FILE, scopes=GOOGLE_DRIVE_SCOPES, redirect_uri=url_for('callback_gdrive', _external=True))
    auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['gdrive_state'] = state
    return redirect(auth_url)

@app.route('/callback/gdrive')
def callback_gdrive():
    state = session.pop('gdrive_state', None)
    flow = Flow.from_client_secrets_file(GOOGLE_CLIENT_SECRETS_FILE, scopes=GOOGLE_DRIVE_SCOPES, state=state, redirect_uri=url_for('callback_gdrive', _external=True))
    flow.fetch_token(authorization_response=request.url)
    session['gdrive_token'] = creds_to_dict(flow.credentials)
    flash('Google Drive connected', 'success')
    return redirect(url_for('intergrate'))

@app.route('/logout/gdrive')
def logout_gdrive():
    session.pop('gdrive_token', None)
    flash('Logged out from Google Drive.', 'success')
    return redirect(url_for('intergrate'))

def creds_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

def ensure_onedrive_folder(access_token, folder_name, parent_id=None):
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    url = 'https://graph.microsoft.com/v1.0/me/drive/root/children' if not parent_id else f'https://graph.microsoft.com/v1.0/me/drive/items/{parent_id}/children'
    children = requests.get(url, headers=headers).json()
    for item in children.get('value', []):
        if item['name'] == folder_name and 'folder' in item:
            return item['id']
    new_folder = requests.post(url, headers=headers, json={
        'name': folder_name,
        'folder': {},
        '@microsoft.graph.conflictBehavior': 'rename'
    }).json()
    return new_folder['id']

def upload_to_onedrive(name, data_bytes, access_token, base_filename):
    root_folder = ensure_onedrive_folder(access_token, 'shardsafe')
    subfolder = ensure_onedrive_folder(access_token, base_filename, parent_id=root_folder)
    url = f"https://graph.microsoft.com/v1.0/me/drive/items/{subfolder}:/{name}:/content"
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/octet-stream'}
    resp = requests.put(url, headers=headers, data=data_bytes)
    return resp.status_code in (200, 201), resp.json()

def ensure_gdrive_folder(drive, name, parent_id=None):
    query = f"mimeType='application/vnd.google-apps.folder' and name='{name}'"
    query += f" and '{parent_id}' in parents" if parent_id else " and 'root' in parents"
    results = drive.files().list(q=query, spaces='drive', fields="files(id, name)").execute()
    files = results.get('files', [])
    if files:
        return files[0]['id']
    metadata = {'name': name, 'mimeType': 'application/vnd.google-apps.folder'}
    if parent_id:
        metadata['parents'] = [parent_id]
    folder = drive.files().create(body=metadata, fields='id').execute()
    return folder['id']

def upload_to_gdrive(name, data_bytes, base_filename):
    creds_data = session.get('gdrive_token')
    if not creds_data:
        return False, {'error': 'Not authenticated with Google Drive'}
    creds = Credentials(**creds_data)
    drive = build('drive', 'v3', credentials=creds)
    root_id = ensure_gdrive_folder(drive, 'shardsafe')
    subfolder_id = ensure_gdrive_folder(drive, base_filename, parent_id=root_id)
    media = MediaIoBaseUpload(io.BytesIO(data_bytes), mimetype='application/octet-stream')
    metadata = {'name': name, 'parents': [subfolder_id]}
    file = drive.files().create(body=metadata, media_body=media, fields='id').execute()
    return True, {'webUrl': f"https://drive.google.com/file/d/{file.get('id')}/view"}

def upload_to_s3(name, data, bucket, s3, base_filename):
    key = f"{base_filename}/{name}"
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=data)
        return True, f"https://{bucket}.s3.amazonaws.com/{key}"
    except ClientError as e:
        return False, str(e)
        
@app.route('/intergration', methods=['GET', 'POST'])
def intergrate():
    global aws_key, aws_secret, aws_bucket, aws_region
    
    if request.method == 'POST':
        aws_key = request.form.get('aws_key') or None
        aws_secret = request.form.get('aws_secret')or None
        aws_bucket = request.form.get('aws_bucket')or None
        aws_region = request.form.get('aws_region')or None
    return render_template('cloudintegration.html', logged_in=('token' in session),
    gdrive_logged_in=('gdrive_token' in session),
    aws_key=aws_key,
    aws_secret=aws_secret,
    aws_bucket=aws_bucket,
    aws_region=aws_region)
    
@app.route('/split', methods=['GET', 'POST'])
def split_file():
    if request.method == 'POST':
        f = request.files.get('file')

        if not f or not f.filename:
            flash('No file selected', 'error')
            return redirect(url_for('split_file'))

        access_token = session.get('token')
        if not access_token:
            flash('Please log into OneDrive first', 'error')
            return redirect(url_for('login_onedrive'))

        if not all([aws_key, aws_secret, aws_bucket, aws_region]):
            flash('Please provide all AWS credentials', 'error')
            return redirect(url_for('split_file'))

        try:
            s3 = boto3.client('s3', aws_access_key_id=aws_key, aws_secret_access_key=aws_secret, region_name=aws_region)
        except ClientError as e:
            flash(f"S3 client error: {str(e)}", 'error')
            return redirect(url_for('split_file'))

        data = f.read()
        base = os.path.splitext(f.filename)[0]
        chunk_size = math.ceil(len(data) / THRESHOLD)
        padlen = chunk_size * THRESHOLD - len(data)

        encoder = Encoder(THRESHOLD, TOTAL_SHARES)
        fragments = encoder.encode(data)

        success = 0
        urls = []
        storage_locations = ['onedrive', 's3', 'gdrive']

        for i, frag in enumerate(fragments):
            name = f"{base}_frag_{i}.zfec"
            destination = storage_locations[i % len(storage_locations)]
            if destination == 'onedrive':
                ok, resp = upload_to_onedrive(name, frag, access_token, base)
            elif destination == 'gdrive':
                ok, resp = upload_to_gdrive(name, frag, base)
            else:
                ok, resp = upload_to_s3(name, frag, aws_bucket, s3, base)
            if ok:
                success += 1
                urls.append(resp.get('webUrl', name) if isinstance(resp, dict) else resp)
            else:
                flash(f"Upload failed for {name}: {resp}", 'error')

        if success == TOTAL_SHARES:
            flash(f"All {TOTAL_SHARES} fragments uploaded: {', '.join(urls)}", 'success')
        else:
            flash(f"Only {success}/{TOTAL_SHARES} fragments uploaded", 'warning')

        return redirect(url_for('split_file'))

    return render_template('split.html',aws_key=aws_key,
    aws_secret=aws_secret,
    aws_bucket=aws_bucket,
    aws_region=aws_region)

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=8080, ssl_context='adhoc')

