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
import json,hashlib,base64

THRESHOLD = 2
TOTAL_SHARES = 3


upload = Blueprint('upload',__name__)

################
def emitUpdate(data):
    socketio.emit("update", data)

def hashSHA256(file):
    sha256 = hashlib.sha256()
    while chunk := file.stream.read(8192):
        sha256.update(chunk)
    
    return sha256.hexdigest()

def base64ToHex(b64String):
    # Decode from base64 to bytes
    byteData = base64.b64decode(b64String)
    # Convert bytes to hex string
    hexString = byteData.hex()
    return hexString

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
        actualFile = request.files['file'] #to test w hash
        fileHash = request.form.get('fileHash')
        encHash = request.form.get('encHash')
        actualFileSize = request.form.get('fileSizeInBytes')
        ownerKey =request.form.get('encryptedKey')
        #print(ownerKey)
        encIV = request.form.get('encIV')
        #print(encIV)
  

        # print(file)
       # test if the received file is the same: 
        serverEncFileHash = hashSHA256(actualFile)
        # print(serverEncFileHash)
        encHash = base64ToHex(encHash)
        # print(encHash)
        # print(hashSHA256(file))
        if  encHash != serverEncFileHash:
            flash("File upload failed. File corrupted on transmission to server",'error')
            return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'encrypted Hashes do not match'})


        if not file:
            flash("File upload failed. No files detected",'error')
            return redirect(url_for('dashboard.viewFiles'))


        fileName = secure_filename(file.filename)
        
        
        # Thread(target=emitUpdate, args=({"step":"file sent to ShardSafe Server"},)).start()
        socketio.start_background_task(emitUpdate, {"step": "file sent to ShardSafe Server"})

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
            # upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], localID)
            # file.save(upload_path)
            
            # to get size: 
            
            fileSize =  actualFileSize      
            fileMime = file.mimetype
            owner = current_user.username
            
            file.stream.seek(0, os.SEEK_END)  # Move to end of stream
            compressedFileSize = file.stream.tell()         # Get current position (i.e., size in bytes)
            file.stream.seek(0)               # Reset back to beginning for later use
   

            # socketio.emit("update", {"step": "authenticating clouds"})
            
            # Thread(target=emitUpdate, args=({"step":"authenticating clouds"},)).start()
            socketio.start_background_task(emitUpdate, {"step":"authenticating clouds"})
            
            canUpload = current_user.checkUploadAbility()
            if not canUpload: # not enough clouds
                flash(f'Please login to {THRESHOLD} or more storages before uploading!', 'error')
                return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': f'be logged in to {THRESHOLD} or more clouds first!'})

            OneDrivetoken = session.get('ONEDRIVE_CREDS')
            AWSCreds = session.get('AWS_CREDS')
            GoogleDriveCreds = session.get('GOOGLEDRIVE_CREDS')
           
            #print(f"SESSION VALS: \n{OneDrivetoken}\n{AWSCreds}\n{GoogleDriveCreds}")
            
            try:
                if AWSCreds:
                    s3 = boto3.client('s3', aws_access_key_id=AWSCreds['access_key'], aws_secret_access_key=AWSCreds['secret_access_key'], region_name=AWSCreds['region'])
                else: 
                    print("AWS not used")
            except ClientError as e:
                flash(f"S3 client error: {str(e)}", 'error')
                return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': 'Please Re-check AWS credentials'})
            

            # socketio.emit("update", {"step": "splitting shares"})
            socketio.start_background_task(emitUpdate,{"step": "splitting shares"})
                
            data = file.read()
            base = file.localFileIdentifier


            encoder = Encoder(THRESHOLD, TOTAL_SHARES)
            fragments = encoder.encode(data)
            
            chunk_size = math.ceil(len(data) / THRESHOLD)
            padlen = chunk_size * THRESHOLD - len(data)

            success = 0
            firstPassDone = False
            uploadedDestinations = []

            fragCounter = 0
            urls = []
            storage_locations = ['onedrive', 's3', 'gdrive']
            # Thread(target=emitUpdate, args=({"step":"Shares have been split"},)).start()
            socketio.start_background_task(emitUpdate, {"step": "Shares have been split"})    

            for i, frag in enumerate(fragments):
                # socketio.emit("update", {"step": f"uploading fragment {i+1}/{TOTAL_SHARES} to cloud"})
                # Thread(target=emitUpdate, args=({"step": f"uploading fragment {i+1}/{TOTAL_SHARES} to cloud"},)).start()
                fragCounter +=1
                ok = False
                resp = None
                name = f"{base}_frag_{i}.zfec"
                destination = storage_locations[i % len(storage_locations)]
                
                if destination == 'onedrive'and OneDrivetoken != None:
                    print("sending to ONEDRIVE")
                    socketio.start_background_task(emitUpdate, {"step": f"Attempting upload of fragment  to OneDrive"})
                    ok, resp = upload_to_onedrive(name, frag, OneDrivetoken, base)

                elif destination == 'gdrive'and GoogleDriveCreds != None:
                    print("sending to GOOGLEDRIVE")
                    socketio.start_background_task(emitUpdate, {"step": f"Attempting upload of fragment  to GoogleDrive"})
                    ok, resp = upload_to_gdrive(name, frag, base)

                
                elif destination == 's3' and AWSCreds != None:
                    print("sending to S3")
                    socketio.start_background_task(emitUpdate, {"step": f"Attempting upload of fragment  to Amazon S3 Bucket"})
                    ok, resp = upload_to_s3(name, frag, AWSCreds['bucket_name'], s3, base)
        

                if ok:
                    success += 1
                    urls.append(resp.get('webUrl', name) if isinstance(resp, dict) else resp)
                    print(f"fragCtr = {fragCounter}, destinations = {uploadedDestinations}")
                    # to handle missing cloud link:
                    if  destination not in uploadedDestinations:
                        uploadedDestinations.append(destination)        
                # else:
                #     flash(f"Upload failed for {name}: {resp}", 'error')
                
                if fragCounter == TOTAL_SHARES and len(uploadedDestinations) < TOTAL_SHARES:
                    print("entered if")
                    # already 'seen' TOTAL_SHARES fragments, but uploaded fewer -> one cloud is down:

                    metadata_dict = {
                    "shard_count":success,
                    "threshold":THRESHOLD,
                    "storage_locations": storage_locations,
                    "shard_filenames":[f"{base}_frag_{i}.zfec" for i in range(TOTAL_SHARES)],
                    "padlen":padlen
                }
                    fileMetaData = json.dumps(metadata_dict)
                
                    File.uploadFile(localFileIdentifier=localID,fileName =fileName,fileHash=fileHash,
                                    actualFileSize=actualFileSize,compressedFileSize=compressedFileSize,fileMime=fileMime,encHash=encHash, ownerKey=ownerKey,encIV=encIV,owner=owner,fileMetaData=fileMetaData)
                    
                    # socketio.emit("update", {"step": "DONE"})
                    # Thread(target=emitUpdate, args=({"step":"DONE"},)).start()
                    socketio.start_background_task(emitUpdate, {"step": "DONE"})
                    flash(f"{success} fragments successfully uploaded", 'warning')
                    return jsonify({'status': 'ok', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload successful'})

            if success >= THRESHOLD:
                flash(f" {success} fragments uploaded: {', '.join(urls)}", 'success')
                
                metadata_dict = {
                    "shard_count":TOTAL_SHARES,
                    "threshold":THRESHOLD,
                    "storage_locations": storage_locations,
                    "shard_filenames":[f"{base}_frag_{i}.zfec" for i in range(TOTAL_SHARES)],
                    "padlen":padlen
                }
                fileMetaData = json.dumps(metadata_dict)
            
                File.uploadFile(localFileIdentifier=localID,fileName =fileName,fileHash=fileHash,
                                 actualFileSize=actualFileSize,compressedFileSize=compressedFileSize,fileMime=fileMime,encHash=encHash, ownerKey=ownerKey,encIV=encIV,owner=owner,fileMetaData=fileMetaData)
               
                # socketio.emit("update", {"step": "DONE"})
                # Thread(target=emitUpdate, args=({"step":"DONE"},)).start()
                socketio.start_background_task(emitUpdate, {"step": "DONE"})
                
                return jsonify({'status': 'ok', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload successful'})
            else:
                flash(f"Only {success}/{TOTAL_SHARES} fragments uploaded", 'warning')

        except Exception as e:
            print(f"Upload failed: {e}")
            return jsonify({'status': 'internalError', 'redirect_url': url_for('dashboard.cloudIntegrationPage'), 'message': 'Error, File was NOT uploaded successfully'})

        
        return jsonify({'status': 'ok', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload successful'})
    
    
    return jsonify({'status': 'fail', 'redirect_url': url_for('dashboard.viewFiles'), 'message': 'Upload failed'})