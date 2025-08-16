from app import create_app,socketio
app = create_app()

socketio.async_mode = 'threading'

if __name__ == '__main__':
#    app.run(debug=True, ssl_context='adhoc') ## WITH HTTPS , ANNOYING TO KEEP CLICKING AWAY SO USE BELOW ONE
    #socketio.run(app,port=443,host='127.0.0.1',debug=True,ssl_context=('cert_file.pem', 'pkey_file.pem')) ## usually use this 
    socketio.run(app,port=443,host='127.0.0.1',debug=True,ssl_context=('localhost.pem', 'localhost-key.pem')) ## usually use this 

#    app.run(host='0.0.0.0',debug=True) ## FOR TESTING W LOCAL NETWORK (IE MOBILE DEVICES )
