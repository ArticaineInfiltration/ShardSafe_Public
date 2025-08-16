from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_required, current_user
from app.admin import adminModeBlock
from app.forms import FileUploadForm,AWSCredentialsForm,SharingConfigForm
from app.models import File, SharedFile
from app.forms import EditProfileForm
from flask_login import login_required, current_user
from app import db
from app.extensions import bcrypt
from flask import flash
from app.static.tools.miscTools import getExtensionsFromMime,emptyToNone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import session
import base64, secrets
import re


PER_PAGE = 10

dashboard = Blueprint('dashboard', __name__)

def _verify_key_proof(login_pubkey_spki_b64: str, message: str, sig_b64: str) -> bool:
    try:
        pub = serialization.load_der_public_key(base64.b64decode(login_pubkey_spki_b64))
        pub.verify(
            base64.b64decode(sig_b64),
            message.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

@dashboard.route('/dashboard', methods=['GET', 'POST'])
@adminModeBlock
@login_required
def landingPage():
    current_user.updateInfo() 
    return redirect(url_for('dashboard.viewFiles',tab='myfiles')) # to change once top templates are up

@dashboard.route('/clouds', methods=['GET','POST'])  ## when i tried moving it, it gave an error when running
@login_required
@adminModeBlock
def cloudIntegrationPage():
    form = AWSCredentialsForm()
    configForm = SharingConfigForm()
    configForm.prefill()
    current_user.updateInfo()
    return render_template('user/cloudintegration.html', user=current_user, form=form, configForm=configForm)

@dashboard.route('/files')
@login_required
@adminModeBlock
def viewFiles():
    tab = request.args.get('tab', 'myfiles')  # default is 'myfiles'
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '')

    current_user.updateInfo()

    configForm = SharingConfigForm()
    configForm.prefill()
    if tab == 'myfiles':

        query = File.query.filter_by(owner=current_user.username)
        if search_query:
            query = query.filter(File.fileName.ilike(f"%{search_query}%"))

        filesPaginated = query.paginate(
            page=page, per_page=PER_PAGE, error_out=False
        )

    elif tab == 'shared':
        filesPaginated = SharedFile.query.filter_by(shared_to=current_user.username).paginate(
        	page=page, per_page=PER_PAGE, error_out=False)
        for file in filesPaginated.items:
            print(file.filename)  # safe to print

        uploadForm = FileUploadForm()
        return render_template(
            'user/viewfiles.html',
            uploadForm=uploadForm,
            user=current_user,
            files=filesPaginated.items,
            pagination=filesPaginated,
            active_tab=tab,	
            configForm=configForm  
        )
    
    for file in filesPaginated:
        print(file.fileType)
        file.fileType = getExtensionsFromMime(file.fileType)

    uploadForm = FileUploadForm()
    return render_template(
        'user/viewfiles.html',
        uploadForm=uploadForm,
        user=current_user,
        files=filesPaginated.items,
        pagination=filesPaginated,
        active_tab=tab,    
        configForm=configForm   
    )
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

@dashboard.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def editProfile():
    form = EditProfileForm()
    configForm = SharingConfigForm()
    configForm.prefill()
    current_user.updateInfo()

    if form.validate_on_submit():
        # 1) Always allow profile-only updates (no passwords/crypto required)
        print(form.data)
        current_user.username = form.username.data
        if (current_user.email !=form.email.data):
            # regex for email
            if is_valid_email(form.email.data):
                current_user.email = form.email.data
            else:
                flash("Email Error, please try again", "danger")
                return redirect(url_for('dashboard.editProfile'))

        current_user.email = form.email.data

        
        # 2) If the client performed a password/key rotation, these fields will be present.
        if form.loginPrivateKey.data and form.encPrivateKey.data:
            sig = request.form.get('keyProofSig', '')
            chal = session.get('edit_challenge')
            login_pubkey_spki_b64 = getattr(current_user, 'loginPublicKey', None) \
                                    or getattr(current_user, 'loginPublicKey_spki_b64', None)

            required = all([
                sig, chal, login_pubkey_spki_b64,
                form.loginSalt.data, form.loginIV.data,
                form.encSalt.data,   form.encIV.data,
            ])
            if not required:
                flash("Missing key proof or encrypted key material.", "danger")
                return redirect(url_for('dashboard.editProfile'))

            # 3) Zero-knowledge proof: verify the signature over the challenge
            if not _verify_key_proof(login_pubkey_spki_b64, chal, sig):
                flash("Could not verify ownership of your keys.", "danger")
                return redirect(url_for('dashboard.editProfile'))

            # 4) Accept opaque encrypted blobs (+ salts/IVs). No passwords read by server.
            current_user.loginPrivateKey_encrypted = form.loginPrivateKey.data
            current_user.loginSalt = form.loginSalt.data
            current_user.loginIV = form.loginIV.data

            current_user.encPrivateKey_encrypted = form.encPrivateKey.data
            current_user.encSalt = form.encSalt.data
            current_user.encIV = form.encIV.data

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('dashboard.editProfile'))

    # GET → issue a fresh one-time challenge for the client to sign
    session['edit_challenge'] = secrets.token_urlsafe(24)

    # Pre-fill form fields for the template
    form.username.data = current_user.username
    form.email.data = current_user.email

    # Render the template you actually have
    return render_template('user/editprofile.html',
                           user=current_user,
                           form=form,
                           configForm=configForm,
                           edit_challenge=session['edit_challenge'])

@dashboard.route('/configure-sharing', methods=['GET', 'POST'])
@login_required
def configureSharing():
    configForm = SharingConfigForm()

    if configForm.validate_on_submit():
        
        
        allowSharing = configForm.sharingOptions.data
        
        if allowSharing == 'True':
            allowSharing = True
        elif allowSharing == 'False':
            allowSharing = False

       
        current_user.allowSharing = allowSharing

        db.session.add(current_user)
        db.session.commit()

        flash("Sharing configuration updated successfully.", "success")
        return redirect(url_for('main.index'))
    else:
        print(configForm.errors)
        for error, msg in configForm.errors.items():
            for s in msg:
                flash(f"ERROR: {error} - {s}")
        #
        #

    return redirect(url_for('dashboard.viewFiles'))
