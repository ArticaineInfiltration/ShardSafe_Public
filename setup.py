import os
import secrets
from cryptography.fernet import Fernet



def createEnvFile(filename=".env"):
    env_vars = {
        "FLASK_APP": "app.py",
        "SECRET_KEY": secrets.token_hex(32),
        "SQLALCHEMY_DATABASE_URI": "sqlite:///database.db",
        "SQLALCHEMY_TRACK_MODIFICATIONS" : False,
        "SPARE_KEY_1":  secrets.token_hex(32),
        "SPARE_KEY_2":  secrets.token_hex(32),
        "SPARE_KEY_3":  secrets.token_hex(32)
    }
    

        
    if os.path.exists(filename):
        print(f"\n{filename} already exists. Aborting to avoid overwrite.")
    else:

        with open(filename, "w") as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
            key = Fernet.generate_key().decode()
            f.write(f'\nFERNET_KEY=\'{key}\'\n')
            f.write(f'\nCLIENT_ID=\'{key}\'\n')
            f.write(f'\nCLIENT_SECRET=\'{key}\'\n')
            print(f"\n{filename} has been created successfully.")

    # create UPLOADSfolder
    folder_path = './sharing'  # relative path to current working directory

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"\nFolder created: {folder_path}")
        
    else:
        print("folder already exists\n")


        

if __name__ == "__main__":
    createEnvFile()
    print("please run the following to generate SSL keys:\n")
    print("openssl req -x509 -newkey rsa:2048 -nodes -keyout localhost-key.pem -out localhost.pem -days 365")
    