from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os,shutil,tempfile


load_dotenv()


def encryptFile(inputFile):
   print("fernet encrypt")
   key = os.getenv('FERNET_KEY')
   fernet = Fernet (key.encode())

   with tempfile.NamedTemporaryFile(delete=False) as tmp:
      with open(inputFile,'rb') as original: 
         data = original.read()
         enc = fernet.encrypt(data)
         tmp.write(enc)
   shutil.move(tmp.name,inputFile)


def decryptFileInMemory(enc_data):
    key = os.getenv('FERNET_KEY')
    fernet = Fernet(key.encode())
    return fernet.decrypt(enc_data)


def decryptFile(inputFile):
   print("fernet decrypt")
   key = os.getenv('FERNET_KEY')
   fernet = Fernet (key.encode())
   if not os.path.exists(inputFile):
        raise FileNotFoundError(f"{inputFile} does not exist")

   if os.path.getsize(inputFile) == 0:
        raise ValueError("File is empty, cannot decrypt.")

   with tempfile.NamedTemporaryFile(delete=False) as tmp:
        with open(inputFile, 'rb') as original:
            enc = original.read()
            try:
                data = fernet.decrypt(enc)
            except Exception as e:
                raise ValueError(f"Decryption failed: {e}")
            tmp.write(data)
   shutil.move(tmp.name, inputFile)