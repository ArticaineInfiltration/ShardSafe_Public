import hashlib 
import os
import base64
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from app import socketio

def emitUpdate(data):
    print("EMITTING: "+str(data))
    socketio.emit("update", data)


def creds_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }


def getHash(page):
    x = hashlib.sha3_256(page.encode())
    return x.hexdigest()


def emptyToNone(value):
    return value if value.strip() else None


def generateRandSalt(length=16):
    return base64.b64encode(os.urandom(length)).decode()

def generateRandIV(length=12):
    return os.urandom(length)

def generateFakeKey():
    length = secrets.randbelow(101)+1400
    random_bytes = os.urandom(length)
    return base64.b64encode(random_bytes).decode('ascii')

def verifySignature(pubKey,nonce,signature):
    pubKeyDer = base64.b64decode(pubKey)
    publicKey = load_der_public_key(pubKeyDer)

    try:
        publicKey.verify(
            base64.b64decode(signature),
            nonce.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()

        )
        return True
    except Exception as e:
        print("sig verification failed ",e)
        return False




def formatFileSize(size_in_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024
    return f"{size_in_bytes:.2f} PB"

def getExtensionsFromMime(mime_type):
    mimeMap = {
        'image/jpeg': '.jpg / .jpeg',
        'image/png': '.png',
        'text/plaint': '.txt',
        'video/mp4': '.mp4',
        'application/pdf': '.pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document':'.docx',
        'text/plain': '.txt',
        'other': 'other'
    }
    return mimeMap.get(mime_type)


