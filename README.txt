to run: 

open a terminal in the folder

!!!
IF you have problems with pip: 
    1. IF you are in (venv) ( ie you already activated it):
        use this command: 
        > deactivate
    
    2. now that you are out of venv, DELETE the venv folder 
    3. run this command: 
        py -m venv venv
    
    4. proceed with below to activate venv

    Note that as of most recent update, Venv file will not be pushed to commit 
    ( idk why ive been doing that)
!!!

run this command: 
    > .\venv\Scripts\activate

run this: 
   (venv) >  pip install -r requirements.txt


run this to setup environment variables:
(venv) > py setup.py 

For Windows, run this powershell script to generate ssl keys (required) in the same directory as the app
> openssl req -x509 -newkey rsa:2048 -nodes -keyout localhost-key.pem -out localhost.pem -days 365

then, run this: 
    (venv) > py run.py 
    // those that need to change py to python or python3, pls use that 


EXPLANATIONS: 

    html pages go in templates folder
    " entities" - from BCE- go to models folder 
    each "section" of the code has its own folder, which has its own route.py file
        the route.py file will contain all the required routing / functions