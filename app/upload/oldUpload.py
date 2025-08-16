from flask import Flask,redirect,url_for, Blueprint,current_app,request,flash,jsonify,session
from app.models import File,User
from app.forms import FileUploadForm
from werkzeug.utils import secure_filename
import os,io
from flask_login import current_user
import uuid 
import boto3
import math, requests
from msal import ConfidentialClientApplication
from zfec.easyfec import Encoder
from botocore.exceptions import ClientError
import google.oauth2.credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseUpload
from app import socketio
from app.static.tools.FileEncryption import encryptFile
from app.static.tools.miscTools import determineMime



THRESHOLD = 3
TOTAL_SHARES = 5


upload = Blueprint('upload',__name__)

################
def emitUpdate():
        socketio.emit("update", {"step": f"test"})


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
    creds_data = session.get('GOOGLEDRIVE_CREDS')
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
        
#################


@upload.route('/upload', methods=['POST', 'FETCH'])
def uploadFileController():
    form = FileUploadForm()

    print(request.form)
    if request.method not in ['POST', 'FETCH']:
        return "Method not allowed", 405

    if request.form:
        file = request.files.get('file')
        fileHash = request.form.get('fileHash')
        userFileType = request.form.get('fileType')
        print("file type from form -> "+ str(userFileType))
        isEnc = False
        key = ""
        if request.form.get('isEnc')=='true':
            isEnc = True
            key = request.form.get('key')
            userFileType = "application/octet-stream"

        print(file)
       


        if not file:
            flash("File upload failed. No files detected",'error')
            return redirect(url_for('dashboard.viewFiles'))

        if not determineMime(file,userFileType):
            flash("Please select the correct file type")
            return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Please enter correct filetype'})

        fileName = secure_filename(file.filename)
        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], fileName)
        socketio.emit("update",{"step":"file sent to ShardSafe Server"} )
        

        try:


            localID = str(uuid.uuid4())
            exists = True 
            while exists:
                exists = File.query.filter_by(localFileIdentifier = localID).first()
                if exists:
                    localID = str(uuid.uuid4())
            
            #file.localFileIdentifier = localID
            file.localFileIdentifier = localID
            fileName = secure_filename(file.filename)
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], localID)
            
            
            socketio.emit("update",{"step":"serverside encryption done, saving.. "} )
            file.save(upload_path)
            # server side encrypt
            socketio.emit("update",{"step":"encrypting on server side "} )
            encryptFile(upload_path)
            #
            # to get size: 
            file.stream.seek(0, os.SEEK_END)  # Move to end of stream
            fileSize = file.stream.tell()         # Get current position (i.e., size in bytes)
            file.stream.seek(0)               # Reset back to beginning for later use
            fileMime = file.mimetype

            print("\n\nMIME")
            print(fileMime)
            print(userFileType)
           
            owner = current_user.username
            
            socketio.emit("update", {"step": "authenticating clouds"})
                
            OneDrivetoken = session.get('ONEDRIVE_CREDS')
            if not OneDrivetoken:
                flash('Please log into OneDrive first', 'error')
                socketio.emit("update", {"step": "ERROR",
                                         "error": "Please Re-authenticate into OneDrive"})
                return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': 'Please Re-login to OneDrive'})
            
            # accessKey = form.accessKey.data
            # secretAccessKey = form.secretAccessKey.data
            # bucketName = form.bucketName.data
            # region = form.region.data
            
            AWSCreds = session.get('AWS_CREDS')
            if not AWSCreds: 
                flash('Please provide all AWS credentials', 'error')
                return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': 'Please login to AWS'})
            
            GoogleDriveCreds = session.get('GOOGLEDRIVE_CREDS')
            if not GoogleDriveCreds:
                flash('Please log into Google Drive first', 'error')
                return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': 'Please login to Google Drive'})
            
            try:
                s3 = boto3.client('s3', aws_access_key_id=AWSCreds['access_key'], aws_secret_access_key=AWSCreds['secret_access_key'], region_name=AWSCreds['region'])
            except ClientError as e:
                flash(f"S3 client error: {str(e)}", 'error')
                return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': 'Please Re-login to AWS'})
            

            socketio.emit("update", {"step": "splitting shares..."})
                
            data = file.read()
            base = file.localFileIdentifier
            chunk_size = math.ceil(len(data) / THRESHOLD)
            padlen = chunk_size * THRESHOLD - len(data)

            encoder = Encoder(THRESHOLD, TOTAL_SHARES)
            fragments = encoder.encode(data)

            success = 0
            urls = []
            storage_locations = ['onedrive', 's3', 'gdrive']
            socketio.emit("update", {"step": "shares have been split"})
                

            for i, frag in enumerate(fragments):
                socketio.emit("update", {"step": f"uploading fragment {i+1}/{TOTAL_SHARES} to cloud"})
                
                name = f"{base}_frag_{i}.zfec"
                destination = storage_locations[i % len(storage_locations)]
                if destination == 'onedrive':
                    print("sending to ONEDRIVE")
                    
                    ok, resp = upload_to_onedrive(name, frag, OneDrivetoken, base)
                elif destination == 'gdrive':
                    
                    print("sending to GOOGLEDRIVE")
                    ok, resp = upload_to_gdrive(name, frag, base)
                else:
                    
                    print("sending to S3")
                    ok, resp = upload_to_s3(name, frag, AWSCreds['bucket_name'], s3, base)
                if ok:
                    success += 1
                    urls.append(resp.get('webUrl', name) if isinstance(resp, dict) else resp)
                else:
                    flash(f"Upload failed for {name}: {resp}", 'error')

            if success == TOTAL_SHARES:
                flash(f"All fragments uploaded: {success}/{TOTAL_SHARES} fragments uploaded successfully", 'success')
            
                File.uploadFile(isE2E = isEnc,key=key, localFileIdentifier=localID,fileName =fileName,fileHash=fileHash, fileSize=fileSize,fileMime=fileMime, owner=owner)
                print(f"[+] Saved to {upload_path}")
                socketio.emit("update", {"step": "DONE"})
                return jsonify({'status': 'ok', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload successful'})
            elif success >= THRESHOLD:
                flash(f"Only {success}/{TOTAL_SHARES} fragments uploaded", 'warning')
                File.uploadFile(isE2E = isEnc,key=key, localFileIdentifier=localID,fileName =fileName,fileHash=fileHash, fileSize=fileSize,fileMime=fileMime, owner=owner)
                print(f"[+] Saved to {upload_path}")
                socketio.emit("update", {"step": "DONE"})
                return jsonify({'status': 'ok', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload partially successful'})
            else:
                flash(f"{success}/{TOTAL_SHARES} fragments uploaded, NOT written to DB", 'warning')

        except Exception as e:
            print(f"Upload failed: {e}")
            return jsonify({'status': 'internalError', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': 'Error, File was NOT uploaded successfully'})

        
        return jsonify({'status': 'ok', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload successful'})
    
    
    return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload failed'})
