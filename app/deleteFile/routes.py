from flask import Blueprint, request, redirect, url_for, flash, session,jsonify
from flask_login import login_required, current_user
from app.models import File, db,SharedFile
from app import socketio
from app.admin import adminModeBlock
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from app.static.tools.miscTools import emitUpdate
import boto3
import requests
import json
import shutil
import os

from app.upload.routes import ensure_onedrive_folder, ensure_gdrive_folder
THRESHOLD_RECONSTRUCTION = 2

deleteFile = Blueprint('delete', __name__)



@deleteFile.route('/delete/<localFileIdentifier>', methods=['POST'])
@login_required
@adminModeBlock
def deleteFileController(localFileIdentifier):
    file = File.query.filter_by(localFileIdentifier=localFileIdentifier).first()

    if not file:
        flash("File not found.", "error")
        return redirect(url_for("dashboard.viewFiles"))

    if current_user.username != file.owner:
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard.viewFiles"))

    try:
        fileName = file.fileName #needed because we delete it first, later
        socketio.start_background_task(emitUpdate, {"step": "Starting deletion process"})

        metadata = json.loads(file.fileMetaData)
        fragment_names = metadata['shard_filenames']
        fragment_locations = metadata['storage_locations']
        base_filename = file.localFileIdentifier

        fragmentsRemoved = 0
        removedLocations = []

        for name, location in zip(fragment_names, fragment_locations):
            if location == "onedrive":
                token = session.get("ONEDRIVE_CREDS")
                # print(f"OD: token = {token}")
                if token:
                    root_folder = ensure_onedrive_folder(token, "shardsafe")
                    subfolder = ensure_onedrive_folder(token, base_filename, parent_id=root_folder)

                    socketio.start_background_task(emitUpdate, {"step": "Attempting delete from OneDrive"})

                    # Delete entire folder
                    requests.delete(
                        f"https://graph.microsoft.com/v1.0/me/drive/items/{subfolder}",
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    fragmentsRemoved +=1
                    removedLocations.append(location)

            elif location == "s3":
                creds = session.get("AWS_CREDS")
                # print(f"S3: CREDS = {creds}")
                if creds:
                    s3 = boto3.client(
                        "s3",
                        aws_access_key_id=creds["access_key"],
                        aws_secret_access_key=creds["secret_access_key"],
                        region_name=creds["region"]
                    )
                    # Delete all objects in folder
                    bucket = creds["bucket_name"]
                    prefix = f"{base_filename}/"
                    list_response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
                    
                    socketio.start_background_task(emitUpdate, {"step": "Attempting delete from S3"})
                    if "Contents" in list_response:
                        objects = [{'Key': obj['Key']} for obj in list_response['Contents']]
                        s3.delete_objects(Bucket=bucket, Delete={'Objects': objects})
                        fragmentsRemoved +=1
                        removedLocations.append(location)

            elif location == "gdrive":
                creds_data = session.get("GOOGLEDRIVE_CREDS")
                # print(f"gdrive: creds_data = {creds_data}")
                if creds_data:
                    creds = Credentials(**creds_data)
                    drive = build("drive", "v3", credentials=creds)

                    root_id = ensure_gdrive_folder(drive, "shardsafe")
                    subfolder_id = ensure_gdrive_folder(drive, base_filename, parent_id=root_id)
                    
                    socketio.start_background_task(emitUpdate, {"step": "Attempting delete from GoogleDrive"})
                    # Move folder to trash
                    drive.files().update(fileId=subfolder_id, body={"trashed": True}).execute()
                    fragmentsRemoved +=1
                    removedLocations.append(location)

        # Delete from DB
        
        if (fragmentsRemoved >= THRESHOLD_RECONSTRUCTION):
            # enough fragments deleted to ensure reconstruction not possible
             ## deleting any shared instances: 
            print('deleting sharedFile instace(s)')
            SharedFile.deleteByFileName(fileName)
            socketio.start_background_task(emitUpdate, {"step": "final step - removing file metadata"})
            file.handleDelete()
            print('handleDelete success')
            db.session.delete(file)
            db.session.commit()

           
            flash(f"File successfully deleted from {removedLocations}", "success")
        else:

            locationString  = ""
            if len(removedLocations) >0:
                locationString = " -"
                for loc in removedLocations:
                    locationString = locationString+ f" {loc}"

            socketio.start_background_task(emitUpdate, {"step": "NOT ENOUGH CLOUD ACCOUNTS LOGGED IN FOR DELETION"})
            flash(f"File fragments only deleted from {len(removedLocations)} storage locations{locationString}, please sign into more cloud accounts for secure removal of remaining fragments if they were not previously removed", "danger")
            return jsonify({"error": "not enough cloud storages logged in", "redirect": url_for("dashboard.cloudIntegrationPage")}), 401

    except Exception as e:
        print("[Delete Controller Error]", str(e))
        flash("An error occurred during deletion", "error")

    return redirect(url_for("dashboard.viewFiles"))