from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField,BooleanField, SubmitField,SelectField,RadioField,HiddenField
from wtforms.validators import InputRequired, Email, Length,equal_to, Regexp,Optional, EqualTo
from flask_login import current_user

passwordMsg = "Password must be at least 8 characters long and include an uppercase letter, a digit, and a special character."

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15,message="Username must be between 4-15 characters")])
    email = StringField('Email', validators=[InputRequired(), Email()])
    encPublicKey = HiddenField(validators=[InputRequired()])
    encPrivateKey = HiddenField(validators=[InputRequired()])
    encIV = HiddenField(validators=[InputRequired()])
    encSalt = HiddenField(validators=[InputRequired()])

    loginPublicKey = HiddenField(validators=[InputRequired()])
    loginPrivateKey = HiddenField(validators=[InputRequired()])
    loginIV = HiddenField(validators=[InputRequired()])
    loginSalt = HiddenField(validators=[InputRequired()])

    resetPrivateKey_encrypted = HiddenField(validators=[InputRequired()])
    resetIV = HiddenField(validators=[InputRequired()])
    resetEncPrivateKey_encrypted = HiddenField(validators=[InputRequired()])
    resetEncIV = HiddenField(validators=[InputRequired()])


    register = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submitBtn = SubmitField('Login')



class FileUploadForm(FlaskForm):
    file = FileField('File', validators=[
    FileRequired(),
    FileAllowed(['jpg', 'png', 'txt', 'mp4', 'pdf', 'docx'], "Only JPG, PNG, TXT, MP4, PDF, and DOCX files allowed!")
])
    fileType = SelectField('file type',choices=[
        ('image/jpeg','.jpg / .jpeg'),
        ('image/png','.png'),
        ('text/plain','.txt'),
        ('video/mp4','.mp4'),
        ('application/pdf','.pdf'),
        ('other','other (.exe, .elf, folders, etc)'),
        ('application/vnd.openxmlformats-officedocument.wordprocessingml.document','.docx')])
    submit = SubmitField('Upload')

class EditProfileForm(FlaskForm):
    email = StringField('Email Address', validators=[InputRequired(), Email()])
    username = StringField('Name', validators=[InputRequired(), Length(min=4, max=15)])
    new_password = PasswordField('New Password', validators=[Optional(),
    ])
    loginPrivateKey = StringField('loginPrivateKey')
    loginSalt = StringField('loginSalt')
    loginIV = StringField('loginIV')

    encPrivateKey = StringField('encPrivateKey')
    encSalt = StringField('encSalt')
    encIV = StringField('encIV')

    current_password = PasswordField('Current Password', validators=[Optional()])
    submitBtn = SubmitField('Update')

class AWSCredentialsForm(FlaskForm):
    accessKey = StringField('Access Key ID:', validators=[InputRequired()])
    secretAccessKey = StringField('Secret Access Key:', validators=[InputRequired()])
    bucketName = StringField('Bucket Name:', validators=[InputRequired()])
    region = StringField('Region:', validators=[InputRequired()])
    useARN = BooleanField('Use this Identity\'s Amazon Resource Name (ARN) for receiving shares')
    submit = SubmitField('Link Bucket')

class SharingConfigForm(FlaskForm):
    # gmail = StringField('Gmail for Google Drive:', validators=[Email(),Optional()])
    # OneDriveMail = StringField('Email for Microsoft OneDrive:', validators=[Email(),Optional()])
    # AWSArn = StringField('ARN for Amazon Web Services (AWS):', validators=[])
    sharingOptions = RadioField("Do you wish to receive shared files?",
                                 choices=[('True','Yes'),('False','No')],default='disable')
    submit = SubmitField('Edit Configurations')

    def prefill(self):

        
        self.sharingOptions.data = str(current_user.allowSharing)

class ForgotPasswordForm(FlaskForm):
    email = StringField('Enter your registered email', validators=[InputRequired(), Email()])
    submit = SubmitField('Reset Password')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[
        InputRequired(),
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(),
        EqualTo('new_password', message="Passwords must match.")
    ])
    submit = SubmitField('Reset Password')
