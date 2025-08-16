from tests.conftest import client
from app.static.tools.miscTools import getHash


## pages involved: 
# login.html - when registration succeeds 
# register.html - when registration fails 

valid_user_data = {
    'username': 'unittest',
    'email': 'unittest@mail.com',
    'password': 'unitTest123!',
    'password2': 'unitTest123!',
    'encPublicKey': 'fake_enc_pub',
    'encPrivateKey': 'fake_enc_priv',
    'encIV': 'iv1',
    'encSalt': 'salt1',
    'loginPublicKey': 'fake_login_pub',
    'loginPrivateKey': 'fake_login_priv',
    'loginIV': 'iv2',
    'loginSalt': 'salt2',
    'resetPrivateKey_encrypted': 'reset1',
    'resetIV': 'riv1',
    'resetEncPrivateKey_encrypted': 'resetEnc1',
    'resetEncIV': 'riv2'
}

def test_register_controller_success(client, app):
    response = client.post('/register', data=valid_user_data, follow_redirects=True)

    with app.test_request_context():
        assert response.status_code == 200
        assert getHash('login.html') in response.data.decode()

        # Check DB for user
        with app.app_context():
            from app.models import User  # adjust if needed
            user = User.query.filter_by(username='unittest').first()
            assert user is not None
            assert user.email == 'unittest@mail.com'

def test_register_controller_failBadCreds(client, app):
    # All required fields in your form
    required_fields = [
        'username', 'email', 'password', 'password2',
        'encPublicKey', 'encPrivateKey', 'encIV', 'encSalt',
        'loginPublicKey', 'loginPrivateKey', 'loginIV', 'loginSalt',
        'resetPrivateKey_encrypted', 'resetIV',
        'resetEncPrivateKey_encrypted', 'resetEncIV'
    ]

    for field in required_fields:
        test_data = valid_user_data.copy()
        test_data[field] = ''  # simulate missing or empty field
        test_data['username'] = f'unittest_{field}'  # ensure it's unique every loop

        response = client.post('/register', data=test_data, follow_redirects=True)

        print(f"Testing missing field: {field}")
        print(response.data.decode()[:500])  # optional: print for debugging

        assert response.status_code == 200
        assert b'id="flashError"' in response.data

        with app.test_request_context():
            from app.models import User
            user = User.query.filter_by(username=f'unittest_{field}').first()
            assert user is None  # user should not be created

def test_register_controller_failDuplicateUser(client, app):
    validUserData = {
        'username': 'unittest',
        'email': 'unittest@mail.com',
        'password': 'unitTest123!',
        'password2': 'unitTest123!',
        'encPublicKey': 'fake_enc_pub',
        'encPrivateKey': 'fake_enc_priv',
        'encIV': 'iv1',
        'encSalt': 'salt1',
        'loginPublicKey': 'fake_login_pub',
        'loginPrivateKey': 'fake_login_priv',
        'loginIV': 'iv2',
        'loginSalt': 'salt2',
        'resetPrivateKey_encrypted': 'reset1',
        'resetIV': 'riv1',
        'resetEncPrivateKey_encrypted': 'resetEnc1',
        'resetEncIV': 'riv2'
    }
    response = client.post('/register', data=validUserData, follow_redirects=True)# proper registration
    with app.test_request_context():
        assert response.status_code == 200
        assert getHash('login.html') in response.data.decode()
        
        with app.app_context():
            from app.models import User
            user = User.query.filter_by(username='unittest').first()
            assert user is not None
            assert user.email ==validUserData['email']
            print('proper reg done')

        # register the user again ( same username test )
    testUser = validUserData.copy()
    testUser['email'] = 'differentmail@mail.com'
    response = client.post('/register', data=testUser, follow_redirects=True)
    #print(response.data.decode()[:1500])
    with app.test_request_context():
        assert response.status_code == 200
        assert b'ERROR' in response.data
        # Check DB for user
        with app.app_context():
            from app.models import User
            user = User.query.filter_by(username='unittest').first()
            assert user is  not None # user prev created
            print(' same username done')

    # register the user again ( same email test )
    testUser = validUserData.copy()
    testUser['username'] = 'differentuser'
    response = client.post('/register', data=testUser, follow_redirects=True)
    #print(response.data.decode()[:1500])
    with app.test_request_context():
        assert response.status_code == 200
        assert b'ERROR' in response.data
        # Check DB for user
        with app.app_context():
            from app.models import User
            user = User.query.filter_by(username='unittest').first()
            assert user is  not None # user prev created
            print('proper same email done')