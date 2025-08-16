from flask_login import UserMixin,login_user,logout_user
from flask import redirect, url_for,flash,session,current_app
from flask_sqlalchemy import SQLAlchemy
from app.extensions import bcrypt 
from . import db
from sqlalchemy.sql import func # for date / timestamp generation
from sqlalchemy import ForeignKey, Integer, DateTime, Boolean,Index
from sqlalchemy.orm import reconstructor
import os,base64,uuid
from sqlalchemy.ext.declarative import declarative_base
from app.static.tools.miscTools import verifySignature,formatFileSize,generateRandSalt
import shutil,os,threading

CLOUD_SERVERS_AVAILABLE = ['Amazon Web Services S3 bucket','GoogleDrive', 'Microsoft OneDrive']
MIN_AUTHORIZED_FOR_UPLOAD  = int(len(CLOUD_SERVERS_AVAILABLE) -1 ) # AWS, OneDrive, GoogleDrive


class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Optional, but recommended

    id = db.Column(db.Integer, primary_key=True,autoincrement=True	)
    username = db.Column(db.String(100),unique = True)
    email = db.Column(db.String(150), unique=True)
    role = db.Column(db.String(10))
    passSalt = db.Column(db.String(80))

    loginPublicKey = db.Column(db.Text)
    loginPrivateKey_encrypted = db.Column(db.Text)
    loginIV = db.Column(db.Text)
    loginSalt = db.Column(db.Text)

    # for password reset (login key): 
    resetPrivateKey_encrypted = db.Column(db.Text)
    resetIV = db.Column(db.Text)

    
    # for password reset ( enc key): 
    resetEncPrivateKey_encrypted = db.Column(db.Text)
    resetEncIV = db.Column(db.Text)


    encPublicKey = db.Column(db.Text)
    encPrivateKey_encrypted = db.Column(db.Text)
    encIV = db.Column(db.Text)
    encSalt = db.Column(db.Text)



    # to facilitate sharing
    # gmail = db.Column(db.String(150), unique=True)
    # oneDriveMail = db.Column(db.String(150), unique=True)
    # AWSARN =  db.Column(db.String(150), unique=True)
    

    allowSharing =db.Column(db.Boolean, default =False)
    
    # memberships = db.relationship('Membership', back_populates='user')

    __table_args__ = (
      
        Index('ix_username_publicKey',
               'username',
              'encPublicKey' ),      
        )

    def __init__(self,username, email, role, passSalt,
                 loginPublicKey,loginPrivateKey_encrypted,loginIV, loginSalt,
                 resetPrivateKey_encrypted,resetIV,
                 encPublicKey,encPrivateKey_encrypted, encIV, encSalt,
                 resetEncPrivateKey_encrypted,resetEncIV,
                   id=None):
        
        if id is not None:
            self.id = id
        self.username = username
        self.email = email
        self.role = role
        self.passSalt = passSalt
        if loginPublicKey is not None:
            self.loginPublicKey = loginPublicKey
        if loginPrivateKey_encrypted is not None:
            print("in init> "+loginPrivateKey_encrypted)
            self.loginPrivateKey_encrypted = loginPrivateKey_encrypted

        if resetPrivateKey_encrypted is not None:
            print("in init> "+resetPrivateKey_encrypted)
            self.resetPrivateKey_encrypted = resetPrivateKey_encrypted
        
        if resetEncPrivateKey_encrypted is not None:
            print("in init> "+resetEncPrivateKey_encrypted)
            self.resetEncPrivateKey_encrypted = resetEncPrivateKey_encrypted        

        if encPublicKey is not None:
            self.encPublicKey = encPublicKey
        if encPrivateKey_encrypted is not None:
            print("in init> "+encPrivateKey_encrypted)
            self.encPrivateKey_encrypted = encPrivateKey_encrypted

        self.resetIV = resetIV


        self.resetEncIV = resetEncIV

        
        self.loginIV = loginIV
        self.encIV =encIV
        self.loginSalt = loginSalt
        self.encSalt = encSalt


        self.userSetUp()

        print("CLOUDS:")
        for x in self.unAuthClouds:
            print (x)


    @reconstructor
    def initOnLoad(self):
        # Called after object is loaded from DB
        self.userSetUp()

    def userSetUp(self):
        
        self.numAuthorized = 0 # needs to be >= 2  for upload
        self.isAWSAuth = False
        self.isOneDriveAuth = False
        self.isGoogleDriveAuth = False
        self.isAuthorizedForUpload = False # needs to be true to allow upload
        self.cloudsInfo = {}
        self.unAuthClouds = []
        self.initCloudsInfo()
        self.updateCloudsInfoBySelf()

    def __str__(self):
        return (
            f"User(id={self.id}, "
            f"username={self.username}, "
            f"email={self.email}, "
            f"role={self.role}),"
            f"numAuthorized={self.numAuthorized}"
            f"isAuthorizedForUpload={self.isAuthorized}"
            
        )
    
    def updateDetails(self):
        try:
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Failed to update user {self.username}: {e}")
            return False


    def checkPassword(self, password): 
          concatPass = password
          #print(concatPass)
          return bcrypt.check_password_hash(self.hashedPass,concatPass)
    
    def checkUploadAbility(self): # find out how many clouds user is authorized in 
       return self.numAuthorized >= MIN_AUTHORIZED_FOR_UPLOAD

    def initCloudsInfo(self):
        self.cloudsInfo = {cloud:False for cloud in CLOUD_SERVERS_AVAILABLE}
    

    def updateInfo(self):
        self.updateShareInfoBySelf()
        self.updateCloudsInfoBySelf()

    def updateCloudsInfoBySelf(self):
        self.isAWSAuth = 'AWS_CREDS' in session
        self.isGoogleDriveAuth = 'GOOGLEDRIVE_CREDS' in session
        self.isOneDriveAuth = 'ONEDRIVE_CREDS' in session
        
        driveCreds = ['AWS_CREDS','GOOGLEDRIVE_CREDS','ONEDRIVE_CREDS']
        ctr = 0 
        for cred in driveCreds:
            if cred in session:
                if cred == 'AWS_CREDS': 
                    self.isAWSAuth = True
                    ctr +=1
                elif cred == 'GOOGLEDRIVE_CREDS': 
                    self.isGoogleDriveAuth = True
                    ctr +=1
                elif cred == 'ONEDRIVE_CREDS': 
                    self.isOneDriveAuth = True
                    ctr +=1
        self.numAuthorized = ctr
        if ctr >= MIN_AUTHORIZED_FOR_UPLOAD:
            self.isAuthorizedForUpload = True
        else:
            self.isAuthorizedForUpload = False
    
    def updateShareInfoBySelf(self):
        self.readyToReceiveShares =self.allowSharing
        
    @staticmethod
    def authenticate(username): #ENTITY login user
        # logs in and returns a user 
        # queries if user exists: 
        user = User.query.filter_by(username=username).first()
        #print("user->" + str(user))
        #a user is found: 
        
        login_user(user) 
        User.userSetUp(user)
        return user
    
    @staticmethod 
    def deleteUser(user): ## To update with cascading delete of other features ie files, groups later
        try:
            db.session.delete(user)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"deletion of user {user.username} failed: {e}")
            return False
        

    @staticmethod
    def logout(): 
        logout_user()
        return 0
    

    @staticmethod
    def registerUser(username,email,
                     loginPublicKey,loginPrivateKey_encrypted,loginIV,loginSalt,
                     resetPrivateKey_encrypted,resetIV,
                     resetEncPrivateKey_encrypted,resetEncIV,
                     encPublicKey,encPrivateKey_encrypted,encIV,encSalt):
        
        # check if username is taken: 
        if User.query.filter_by(username=username).first() != None:
            print('err at models')
            flash(f"ERROR: This username '{username}' is already taken, please choose another!",category="error")
            return None
        elif User.query.filter_by(email=email).first()  != None:
            print('err at models')
            flash("ERROR: This email is already registered!",category="error") 
            return None
        else: # create the user 
 
                passSalt = generateRandSalt() # have but not in use
                #hashedPass = bcrypt.generate_password_hash(password.encode('utf-8'),rounds=14).decode('utf-8')
                #hashedPass = hashlib.sha3_256(password.encode('utf-8')+passSalt.encode('utf-8')).hexdigest()
                newUser = User(loginPublicKey=loginPublicKey,loginPrivateKey_encrypted=loginPrivateKey_encrypted,loginIV=loginIV,loginSalt=loginSalt,
                               resetPrivateKey_encrypted=resetPrivateKey_encrypted,resetIV=resetIV,
                               resetEncPrivateKey_encrypted=resetEncPrivateKey_encrypted,resetEncIV=resetEncIV,
                               encPublicKey=encPublicKey,encPrivateKey_encrypted=encPrivateKey_encrypted,encIV=encIV,encSalt=encSalt,
                               username=username, email=email, role= 'user', passSalt=passSalt)
                
                #add the new user
                db.session.add(newUser)
                db.session.commit()
                flash ('Account created successfully!', category='success')
                return True

            

class File(db.Model):
    __tablename__ = 'file' 

    id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    fileName = db.Column(db.String(150))
    compressedFileSize = db.Column(db.String(20))
    actualFileSize = db.Column(db.String(20))
    fileType = db.Column(db.String(15))
    fileHash = db.Column(db.String(70))
    encHash = db.Column(db.String(70))
    ownerKey = db.Column(db.Text)
    encIV = db.Column(db.Text)
    localFileIdentifier = db.Column(db.String(200),unique=True, nullable=False)
    
    shareInstances = db.relationship(
    'SharedFile',
    cascade='all, delete-orphan',
    passive_deletes=True
)

     ###
    owner = db.Column(db.Integer,ForeignKey('users.id'))
    timeUploaded = db.Column(db.DateTime, default=func.now())
    fileMetaData = db.Column (db.Text)
    
    ownerUser = db.relationship('User', foreign_keys=[owner],
                                 backref='files', lazy=True)
    
    shareInstances = db.relationship('SharedFile',backref='file',
                                    lazy=True,
                                    cascade="all, delete-orphan",
                                    passive_deletes=True
                                )

    __table_args__ = (
        Index('ix_fileName_GoogleFileIdentifier_OneDriveFileIdentifier_AWSFileIdentifier_localFileIdentifier',
               'fileName','localFileIdentifier' ),
        )



    def __init__(self,actualFileSize,compressedFileSize, owner, fileType,fileName,localFileIdentifier,fileHash,encHash, fileMetaData,
                 ownerKey,encIV,id=None,key=None):
        
        if id is not None:
            self.id = id
        self.actualFileSize =actualFileSize
        self.compressedFileSize =compressedFileSize
        self.owner = owner
        self.key = key
        self.fileType = fileType
        self.fileName = fileName
        self.fileHash = fileHash
        self.encHash = encHash
        self.fileMetaData = fileMetaData
        self.ownerKey = ownerKey
        self.encIV = encIV
        
        self.localFileIdentifier =localFileIdentifier


    def setGoogleFileIdentifier(self, fileID):
        self.GoogleFileIdentifier = fileID
        db.session.add(self)
        db.session.commit()

    def setOneDriveFileIdentifier(self, fileID):
        self.OneDriveFileIdentifier = fileID
        db.session.add(self)
        db.session.commit()

    def setAWSFileIdentifier(self, fileID):
        self.AWSFileIdentifier = fileID
        db.session.add(self)
        db.session.commit()



    

    @reconstructor
    def init_on_load(self):
        # Called after object is loaded from DB
        self.fileSetUp()
    def fileSetUp(self):
        self.fileSizeString = formatFileSize(int(self.actualFileSize))

    @staticmethod
    def uploadFile(fileName,actualFileSize,compressedFileSize, fileMime, owner,localFileIdentifier,fileMetaData,encHash,fileHash,ownerKey,encIV):
        #check if file name exists: 
        ctr = 1

        nameAndExt = str(fileName).split('.',1) # gets xxx, .abc
        newName =nameAndExt[0]
        while  File.query.filter_by(fileName= newName + '.' + nameAndExt[1]).first(): # search to find xxx 
            # need to change the name: 
            newName= nameAndExt[0]+f"({ctr})"
            ctr +=1
        fileName = newName+"."+nameAndExt[1]

        file = File(localFileIdentifier=localFileIdentifier,actualFileSize=actualFileSize,compressedFileSize=compressedFileSize,fileType=fileMime,owner=owner,
                    fileName=fileName,encIV=encIV,ownerKey=ownerKey,encHash=encHash,fileHash=fileHash, fileMetaData=fileMetaData)
        db.session.add(file)
        db.session.commit()
        #flash("File uploaded successfully.",'success')
        return True
    
    @staticmethod
    def getFilesByUser(user):
        files = File.query.filter_by(owner=user).all()
        return files
    
    def getAllShareInstancesSharedPaths(self):
        toReturn = []
        instances = SharedFile.query.filter_by(file_id = self.id).all()
        for i in instances: 
            toReturn.append(i.shared_path)
        return toReturn
    
    
    def handleDelete(self):
        pathsToRemove = self.getAllShareInstancesSharedPaths()

        def delete_task(paths):
            try:
                for path in pathsToRemove:
                    if os.path.exists(path):
                        shutil.rmtree(path)
                print("[BACKGROUND - DELETIONS COMPLETED]")
            except Exception as e:
                print(e)
                print("[BACKGROUND - DELETIONS ERROR]")

        threading.Thread(target=delete_task,args=(pathsToRemove,), daemon=True).start()        
        return True
    
        


# class Group(db.Model):
#     __tablename__ = 'groups'

#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100))
#     owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     description = db.Column(db.String(20))
#     owner = db.relationship('User', backref='owned_groups', foreign_keys=[owner_id])
#     memberships = db.relationship('Membership', back_populates='group')

#     @staticmethod
#     def getAllEncPublicKeys(groupID):
#         group = Group.query.get(groupID)
#         if not group:
#             return {}
        
#         toReturn = {} 
#         # get each user and pubKey:
#         for member in group.memberships:
#             toReturn[member.user_id]=member.user.encPublicKey
#         return toReturn

#     @staticmethod
#     def createNewGroup(name,description,owner_id):
        
#         group = Group(name=name,description=description,owner_id=owner_id)
#         db.session.add(group)
#         db.session.commit()
        
#         return group
        
#     def getOwnerEncryptedSGK(self):
#         membership = Membership.query.filter_by(user_id=self.owner_id, group_id=self.id).first()
#         if membership:
#             return membership.encryptedSGKB64
        
#         return None  
#     def addMember(self,user_id):
#         Membership.createMemebershipOnGroup(self.id,user_id)
#         print(f"user {user_id} added to group: {self.name}-id:{self.id}")


# class Membership(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
#     group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))
#     encryptedSGKB64 = db.Column(db.Text, nullable=False)

#     user = db.relationship('User', back_populates='memberships')
#     group = db.relationship('Group', back_populates='memberships')

#     def getEncPublicKey(self):
#         return self.user.encPublicKey

#     @staticmethod
#     def createMemebershipOnGroup(group_id, user_id,encryptedSGKB64):
#         memebership = Membership(group_id=group_id,user_id=user_id,encryptedSGKB64=encryptedSGKB64)
#         db.session.add(memebership)
#         db.session.commit()
#     @staticmethod
#     def isUserInGroup(user_id, group_id):
#         return Membership.query.filter_by(user_id=user_id, group_id=group_id).first() is not None


# class Invitation(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
#     invited_user_id =  db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     token = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
#     encInviteeSGK = db.Column(db.Text, nullable=False)
#     accepted = db.Column(db.Boolean, default=False)

#     group = db.relationship('Group', foreign_keys=[group_id])
#     recipient = db.relationship('User', foreign_keys=[invited_user_id])

#     __table_args__ = (
#     db.UniqueConstraint('group_id', 'invited_user_id', name='uix_group_user_invite'),
#     )

    

#     @staticmethod
#     def getInvitationsByRecipient(user_id):
#         invites = Invitation.query.filter_by(invited_user_id=user_id).all()
#         if invites:
#             return invites
#         return None
    
#     @staticmethod
#     def isAlreadyinvited(user_id, group_id):
#         return Invitation.query.filter_by(invited_user_id=user_id,
#                                       group_id=group_id, accepted=False).first() is not None
    
#     @staticmethod
#     def createInvite(user_id,group_id,encInviteeSGK):
#         try: 
            
#             # check duplicate invite: 
#             dupe = Invitation.query.filter_by(invited_user_id = user_id, group_id=group_id).first()
#             if dupe:
#                 return False, "This user has already been invited!"

#             invitation = Invitation(group_id=group_id,
#                                     invited_user_id = user_id,
#                                     encInviteeSGK=encInviteeSGK)
#             db.session.add(invitation)
#             db.session.commit()
#             return True, "User invited!"

#         except Exception as e:
#             return False, e

class SharedFile(db.Model):
    tablename = 'shared_file'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id', ondelete="CASCADE"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    shared_by = db.Column(db.String(100), nullable=False)
    shared_to = db.Column(db.String(100), nullable=False)
    shared_path = db.Column(db.String(255), nullable=False)
    sharedKey = db.Column(db.String(255) )
    # isGroupShare = db.Column(db.Boolean, default=False )
    # groupKey = db.Column(db.String(255) )
    created_at = db.Column(db.DateTime, default=func.now())
    # is_active = db.Column(db.Boolean, default=True)

    fileObject = db.relationship('File', foreign_keys=[file_id], lazy=True)

    def init(self, file_id, filename, shared_by, shared_to, shared_path):
        self.file_id = file_id
        self.filename = filename
        self.shared_by = shared_by
        self.shared_to = shared_to
        self.shared_path = shared_path
    
    @staticmethod 
    def deleteByFileName(fileName): # mass delete
        try:
            sharedFiles = SharedFile.query.filter_by(filename=fileName).all()
            for file in sharedFiles:
                path = file.shared_path
                if os.path.exists(path):
                    shutil.rmtree(path)
                db.session.delete(file)
                db.session.commit()
                return True
        except Exception as e: 
            print(f"deleteFileByName Exception: {e}")
            return False
    
    @staticmethod 
    def deleteByFileIdAndRecipient(fileId,sharedTo):
        try:
            sharedFiles = SharedFile.query.filter_by(file_id=fileId,shared_to =sharedTo).all()
            for row in sharedFiles:
                path = row.shared_path
                if os.path.exists(path):
                    shutil.rmtree(path)
                db.session.delete(row)
                db.session.commit()
                return True
        except Exception as e: 
            print(f"deleteByFileIdAndRecipient Exception: {e}")
            return False
