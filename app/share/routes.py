from flask import Blueprint,send_file, jsonify,request, redirect, url_for, session, flash, current_app
from flask_login import current_user, login_required
import os
import json
import secrets,base64
from datetime import datetime
import traceback
from botocore.exceptions import ClientError
from app import db
from app.models import File
from app.models import SharedFile, User
from app.upload.routes import ensure_onedrive_folder, ensure_gdrive_folder
from app.admin import adminModeBlock
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseDownload
import boto3
import io
from io import BytesIO
from flask_wtf.csrf import validate_csrf, CSRFError
from zfec.easyfec import Decoder

share = Blueprint('share', __name__)

def generateNonce(length=16):
    return base64.b64encode(secrets.token_bytes(length)).decode()

def insert_shared_file(file_id,filename, shared_by, shared_to, shared_path,encFileKey):
    shared_entry = SharedFile(
        file_id=file_id,
        filename=filename,
        shared_by=shared_by,
        shared_to=shared_to,
        shared_path=shared_path,
        sharedKey = encFileKey
    )
    db.session.add(shared_entry)
    db.session.commit()

def download_from_onedrive(name, access_token, base_filename):
    import requests

    # First, get the folder ID for /shardsafe/base_filename/
    root_folder = ensure_onedrive_folder(access_token, 'shardsafe')
    subfolder = ensure_onedrive_folder(access_token, base_filename, parent_id=root_folder)

    # Construct the download URL
    url = f"https://graph.microsoft.com/v1.0/me/drive/items/{subfolder}:/{name}:/content"
    headers = {'Authorization': f'Bearer {access_token}'}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.content
    else:
        print(f"[OneDrive] Failed to download {name}: {response.status_code}")
        return None


def download_from_s3(name, bucket, s3, base_filename):
    try:
        key = f"{base_filename}/{name}"
        obj = s3.get_object(Bucket=bucket, Key=key)
        return obj['Body'].read()
    except ClientError as e:
        print(f"[S3] Error downloading {name}: {e}")
        return None


def download_from_gdrive(name, drive, base_filename):
    # Step 1: Get shardsafe root folder
    root_id = ensure_gdrive_folder(drive, 'shardsafe')
    subfolder_id = ensure_gdrive_folder(drive, base_filename, parent_id=root_id)

    # Step 2: Search for the file by name
    query = f"name='{name}' and '{subfolder_id}' in parents and trashed = false"
    results = drive.files().list(q=query, spaces='drive', fields="files(id)").execute()
    files = results.get('files', [])

    if not files:
        print(f"[GDrive] File {name} not found in {base_filename}")
        return None

    file_id = files[0]['id']

    # Step 3: Download the content
    request = drive.files().get_media(fileId=file_id)
    buffer = io.BytesIO()
    downloader = MediaIoBaseDownload(buffer, request)
    done = False
    while not done:
        status, done = downloader.next_chunk()
    buffer.seek(0)
    return buffer.read()

@share.route('/share/', methods=['POST'])
@adminModeBlock
@login_required
   
def shareFileController():

    token = request.headers.get('X-CSRFToken')
    print("TOKEN->",token)
    validate_csrf(token)
    user = current_user
    step = request.form.get('step')
    

    try:
        if int(step)==1:
            # get required data
            localFileIdentifier = request.form.get('localFileIdentifier')
            file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
            recipientUsername = request.form.get('shareUsername')
            print(recipientUsername)
            recipient = User.query.filter_by(username=recipientUsername).first()
            # try to find duplicates: 
           

            if recipient is None or recipient.allowSharing is False:
                return jsonify({
                    'success': False,
                    'message': "Recipient does not exist or not open to receiving files!",
                    'level': "danger" 
                }), 200
            dupes = SharedFile.query.filter_by(file_id=file.id,shared_to=recipient.username).all()
           
            if len(dupes) > 0:
                return jsonify({
                    'success': False,
                    'message': f"Already shared {file.fileName} with {recipient.username}, sharing cancelled",
                    'level': "danger" 
                }), 200
            elif recipient.id == current_user.id:
                  return jsonify({
                    'success': False,
                    'message': "Cannot share with self!",
                    'level': "danger" 
                }), 200
            elif recipient.role != "user":
                  return jsonify({
                    'success': False,
                    'message': "Recipient does not exist!", # dont expose admin 
                    'level': "danger" 
                }), 200
            else:
                if not file or current_user.username != file.owner:
                    return jsonify({
                    'success': False,
                    'message': "Unauthorized or file not found.",
                    'level': "danger" 
                        }), 200
                else:
                    return jsonify({
                    'success': True,
                    'message': "success",
                    'level': "success",
                    'shareUsername': recipient.username,
                    'ownerKey':file.ownerKey,
                    'localFileIdentifier':file.localFileIdentifier,
                    'recipientPublicKey': recipient.encPublicKey 
                        }), 200
        elif int(step)==2:
                recipientUsername = request.form.get('shareUsername')
                localFileIdentifier = request.form.get('localFileIdentifier')
                recipient = User.query.filter_by(username=recipientUsername).first()
                encFileKeyForRecipient =  request.form.get('encFileKey')
                file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
                
                if recipient is None:
                     return jsonify({
                    'success': False,
                    'message': "Unauthorized or file not found.",
                    'level': "danger" 
                        }), 200
                if not file or current_user.username != file.owner:
                    return jsonify({
                    'success': False,
                    'message': "Unauthorized or file not found.",
                    'level': "danger" 
                        }), 200

                try:
                    metadata = json.loads(file.fileMetaData)
                    fragment_names = metadata['shard_filenames']
                    fragment_locations = metadata['storage_locations']

                    shared_to = recipient.username  # Replace this later with a form or UI selection
                    base_path = os.path.abspath(os.path.join(current_app.root_path, '..', 'sharing'))
                    share_folder = os.path.join(base_path, localFileIdentifier + '_' + shared_to)
                    os.makedirs(share_folder, exist_ok=True)
                    saved_count = 0

                    for name, location in zip(fragment_names, fragment_locations):
                        data = None
                        if location == 'onedrive':
                            token = session.get('ONEDRIVE_CREDS')
                            if token:
                                data = download_from_onedrive(name, token, file.localFileIdentifier)
                        elif location == 's3':
                            creds = session.get('AWS_CREDS')
                            if creds:
                                s3 = boto3.client(
                                    's3',
                                    aws_access_key_id=creds['access_key'],
                                    aws_secret_access_key=creds['secret_access_key'],
                                    region_name=creds['region']
                                )
                                data = download_from_s3(name, creds['bucket_name'], s3, file.localFileIdentifier)
                        elif location == 'gdrive':
                            creds_data = session.get('GOOGLEDRIVE_CREDS')
                            if creds_data:
                                creds = Credentials(**creds_data)
                                drive = build('drive', 'v3', credentials=creds)
                                data = download_from_gdrive(name, drive, file.localFileIdentifier)

                        if data:
                            with open(os.path.join(share_folder, name), 'wb') as f:
                                f.write(data)
                            saved_count += 1

                    if saved_count == 0:
                       
                        return jsonify({
                    'success': False,
                    'message': "No fragments could be found. Please check cloud accounts login",
                    'level': "danger" 
                        }), 200
                    else:
                        insert_shared_file(file.id,file.fileName, current_user.username, shared_to, share_folder,encFileKeyForRecipient)

                except Exception as e:
                    raise e
                print('sharing success')
                return jsonify({
                    'success': True,
                    'message': "success",
                    'level': "success" 
                        }), 200
    except Exception as e:
        print(f"[SHARE ERROR] {e}")
        traceback.print_exc()
        return jsonify({
        'success': False,
        'message': "An error occurred while sharing the file.",
        'level': "danger" 
            }), 200


@share.route('/share/shared-users', methods=['POST'])
@adminModeBlock
@login_required
def getSharedUsers():


    token = request.headers.get('X-CSRFToken')
    validate_csrf(token)
    user = current_user
    localFileIdentifier = request.form.get('localFileIdentifier')
    print("hit fileshares")
    print(localFileIdentifier)
    
    file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
    print('file: ',file.fileName)
    if file:
        if current_user.username != file.owner:
            return jsonify({
                    'success': False,
                    'message': "The file does not exist or you are not authorized to interact with it",
                    'level': "danger" 
                        }), 200

        shares = SharedFile.query.filter_by(file_id=file.id).all()
        print("shares found")
        print(shares)
        if len(shares) >0:
            # shares exist
            recipients = [share.shared_to for share in shares]
            return jsonify({'success':True, 'recipients':recipients})
        else:
            return jsonify({'success':True, 'recipients':[]})
    else:
        return jsonify({
                    'success': False,
                    'message': "The file does not exist or you are not authorized to interact with it",
                    'level': "danger" 
                        }), 200


@share.route('/share/revoke-access', methods=['POST'])
@adminModeBlock
@login_required
def revokeFileAccessController():

    token = request.headers.get('X-CSRFToken')
    validate_csrf(token)
    data = request.get_json()
    targetUsername = data.get('username')
    localFileIdentifier = data.get('fileId')
    
    print(localFileIdentifier)
    
    file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
    print('file: ',file.fileName)
    user = User.query.filter_by(username=targetUsername).first()

    if file:
        if current_user.username != file.owner:
            return jsonify({
                    'success': False,
                    'message': "The file does not exist or you are not authorized to interact with it",
                    'level': "danger" 
                        }), 200

        deleted = SharedFile.deleteByFileIdAndRecipient(file.id,user.username)    
        
        if deleted :
    
            return jsonify({'success':True})
        else:
            return jsonify({'success':False})
    else:
        return jsonify({
                    'success': False,
                    'message': "The file does not exist or you are not authorized to interact with it",
                    'level': "danger" 
                        }), 200
    

def genericError():
    return jsonify({
                    'success': False,
                    'message': "The file does not exist or you are not authorized to interact with it",
                    'level': "danger" 
                        }), 200

@share.route('/getSharedFile/',methods =["POST"])
@adminModeBlock
@login_required
def getSharedFile():
    token = request.headers.get('X-CSRFToken')
    validate_csrf(token)
    data = request.get_json()
    print('DATA')
    print(data)

    step = data.get('step')
    if step == 'getDecryptionParams':
        localFileIdentifier = data.get('localFileIdentifier')
        print("in getShareDec "+localFileIdentifier)
        # get the decryption params for the shared file 
        
        file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
        if (not file):
            return genericError()
        validShare = SharedFile.query.filter_by(file_id=file.id,shared_to = current_user.username).first()
        if (not validShare):
             return genericError()
        
        
        # gen the nonce and store in session: 
        nonce = generateNonce()
        session['shareNonce'] = nonce
        return jsonify({
                    'success': True,
                    'key': validShare.sharedKey,
                    'encIV': file.encIV,
                    'fileHash': file.fileHash,
                    'fileName': file.fileName,
                    'nonce': nonce,
                    'level': "success" 
                        }), 200
    elif step == 'getFile':

        localFileIdentifier = data.get('localFileIdentifier')
        # get the file and combine them
        if data.get('nonce')!= session['shareNonce']:
            return genericError()
        
        # pop the nonce 
        session.pop('shareNonce', None)
        file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
        if not file:
            print('not file')
            return genericError()
        validShare = SharedFile.query.filter_by(file_id = file.id, shared_to = current_user.username).first()
        if not validShare:
            print('not valid share')
            return genericError()

        sharedPath = validShare.shared_path
        if not os.path.exists(sharedPath):
            return jsonify({
                    'success': False,
                    'message':'Error - please get original sender to re-share the file'
                        }), 200
        try:
            # Load metadata from original File record
            print('enter try')
            metadata = json.loads(file.fileMetaData)
            threshold = metadata['threshold']
            fragment_names = metadata['shard_filenames']

            fragments = []
            fragment_indices = []
            for i, name in enumerate(fragment_names):
                print('in for')
                fragment_path = os.path.join(sharedPath, name)
                if os.path.exists(fragment_path):
                    with open(fragment_path, 'rb') as f:
                        fragments.append(f.read())
                        fragment_indices.append(i)

                if len(fragments) == threshold:
                    break

            if len(fragments) < threshold:
                flash("Not enough fragments to reconstruct file.", 'error')
                return redirect(url_for('dashboard.viewFiles'))


                    # Decode using zfec
            decoder = Decoder(threshold, len(fragment_names))
            original = decoder.decode(fragments, fragment_indices, padlen=int(metadata.get('padlen', 0)))

            # Send the reconstructed file
            file_stream = BytesIO(original)
            filename = file.fileName if hasattr(file,'fileName') else f"{file.filename}_reconstructed"
            mimetype = file.fileMime if hasattr(file,'fileMime') else 'application/octet-stream'
            print ('file sent')
            return send_file(
                    file_stream,
                    as_attachment=True,
                    download_name=filename,
                    mimetype=mimetype
                )
        except Exception as e:
                print(f"[Local Download] Error: {e}")
                traceback.print_exc()
                flash("Error reconstructing file from local fragments.", 'error')
                return redirect(url_for('dashboard.viewFiles'))
                
        
        
        print(data)

