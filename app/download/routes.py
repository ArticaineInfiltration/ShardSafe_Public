from flask import make_response,Flask,redirect,url_for, Blueprint,current_app,request,make_response,flash,jsonify,send_from_directory,send_file,session
from app.models import File,User
from app.forms import FileUploadForm
from werkzeug.utils import secure_filename
import os
from flask_login import current_user,login_required
from app.admin import adminModeBlock
from botocore.exceptions import ClientError,EndpointConnectionError
import json
import boto3
from zfec.easyfec import Decoder
print(f"Using Decoder class from: {Decoder.__module__}")
import google.oauth2.credentials
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseDownload
import traceback
from app.upload.routes import ensure_onedrive_folder,ensure_gdrive_folder
import io
from io import BytesIO

download = Blueprint('download',__name__)

FILE_RETREIVE_ERROR = "This file does not exist or you do not have the permissions required to retrieve it"

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

@download.route('/download/preDownload', methods=['POST'])
@adminModeBlock
@login_required
def getCreds():
    #print("entered route ")
    user = current_user
    

    response = make_response(
                        jsonify(
                            {'success':True,
                            'status':200
                            }
                        )
                    )
    response.set_cookie('encIV',user.encIV,max_age=3600,secure=True)
    response.set_cookie('encPrivateKey_encrypted',user.encPrivateKey_encrypted,max_age=3600,secure=True)
    response.set_cookie('encSalt',user.encSalt,max_age=3600,secure=True)
    response.set_cookie('encPublicKey',user.encPublicKey,max_age=3600,secure=True)
                    
    return response

@download.route('/download/<localFileIdentifier>', methods=['GET','POST'])
@adminModeBlock
@login_required
def downloadFileController(localFileIdentifier):
    if request.method == "POST":
        file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
        if file is not None:
            if current_user.username == file.owner:
                try:
                    data = request.get_json()
                    getDecryptionParams = data.get('getDecryptionParams')
                    if getDecryptionParams:
                        return jsonify({"encIV":file.encIV,
                                        "key":file.ownerKey,
                                        "fileHash":file.fileHash,
                                        "fileName":file.fileName})
                    else:
                         return jsonify({"encIV":"",
                                        "key":"",
                                        "fileHash":"",
                                        "fileName":""})
                except Exception as e: 
                    import traceback
                    traceback.print_exc()
                    flash("Error retrieving file.", 'error')
                    return redirect(url_for('dashboard.viewFiles'))

    if request.method == "GET":
        print("got download request!!")
        file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()
    
        if file is not None:
            # If the current user is the owner
            if current_user.username == file.owner:
                try:
                    metadata = json.loads(file.fileMetaData)
                    threshold = metadata['threshold']
                    fragment_names = metadata['shard_filenames']
                    fragment_locations = metadata['storage_locations']

                    fragments = []
                    fragment_indices = []

                    for i, (name, location) in enumerate(zip(fragment_names, fragment_locations)):
                        data = None

                        if location == 'onedrive':
                            token = session.get('ONEDRIVE_CREDS')
                            if not token:
                                continue
                            data = download_from_onedrive(name, token, file.localFileIdentifier)

                        elif location == 's3':
                            creds = session.get('AWS_CREDS')
                            if not creds:
                                continue
                            s3 = boto3.client(
                                's3',
                                aws_access_key_id=creds['access_key'],
                                aws_secret_access_key=creds['secret_access_key'],
                                region_name=creds['region']
                            )
                            data = download_from_s3(name, creds['bucket_name'], s3, file.localFileIdentifier)

                        elif location == 'gdrive':
                            creds_data = session.get('GOOGLEDRIVE_CREDS')
                            if not creds_data:
                                continue
                            creds = Credentials(**creds_data)
                            drive = build('drive', 'v3', credentials=creds)
                            data = download_from_gdrive(name, drive, file.localFileIdentifier)

                        if data:
                            fragments.append(data)
                            fragment_indices.append(i)

                        if len(fragments) == threshold:
                            break

                    if len(fragments) < threshold:
                        flash("Not enough fragments to reconstruct the file", 'error')
                        return redirect(url_for('dashboard.viewFiles'))

                    # zfec expects fragment indices as int list, and fragments as list of bytes
                    fragment_indices = [int(i) for i in fragment_indices]
                    decoder = Decoder(threshold, len(fragment_names))
                    original = decoder.decode(fragments, fragment_indices, padlen=int(metadata.get('padlen', 0)))

                    # Send file as attachment to browser
                    file_stream = BytesIO(original)
                    filename = file.fileName if hasattr(file, 'fileName') else f"{localFileIdentifier}_reconstructed"
                    mimetype = file.fileMime if hasattr(file, 'fileMime') else 'application/octet-stream'

                    return send_file(
                        file_stream,
                        as_attachment=True,
                        download_name=filename,
                        mimetype=mimetype
                    )

                except Exception as e:
                    print(f"Reconstruction error: {e}")
                    import traceback
                    traceback.print_exc()
                    flash("Error retrieving file.", 'error')
                    return redirect(url_for('dashboard.viewFiles'))
            else:
                flash("Unauthorized access.", 'error')
                return redirect(url_for('dashboard.viewFiles'))
        else:
            flash("File not found.", 'error')
            return redirect(url_for('dashboard.viewFiles'))

    return redirect(url_for('dashboard.viewFiles'))