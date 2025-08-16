import pytest
from flask_bcrypt import Bcrypt
from app.models import User
from flask import session
from tests.conftest import client

"""
TODO: 
checkUploadAbility(self)
nitCloudsInfo(self)
updateCloudsInfoBySelf(self)
"""
@pytest.fixture
def user_data():
    return {
        'username': 'testuser',
        'email': 'testuser@mail.com',
        'password': 'testPassword123!'
    }

mockPubKey = "RSAPubKey"
mockPvtKey = "RSAPrivateKey"

# test statics 
def test_registerUser_success(app):
            with app.app_context():
                with app.test_request_context():
                    result = User.registerUser('testuser',
                                               'test@mail.com',
                                               loginPublicKey='lpub',
                                               loginPrivateKey_encrypted='lpriv',
                                               loginIV='liv',
                                               loginSalt='lsalt',
                                               encPublicKey='epub',
                                               encPrivateKey_encrypted='epriv',
                                               encIV='eiv',
                                               encSalt='esalt',
                                               resetPrivateKey_encrypted='rpvt',
                                               resetIV='riv',
                                               resetEncPrivateKey_encrypted='repvt',
                                               resetEncIV='reiv')
                    assert result is True
                    user = User.query.filter_by(username='testuser').first()
                    assert user is not None
                    assert user.email == 'test@mail.com'


def test_registerUser_failDuplicateUser(app):
    with app.test_request_context():
        # normal register - should pass
        result = User.registerUser(
            'testuser',
            'test@mail.com',
            loginPublicKey='lpub',
            loginPrivateKey_encrypted='lpriv',
            loginIV='liv',
            loginSalt='lsalt',
            encPublicKey='epub',
            encPrivateKey_encrypted='epriv',
            encIV='eiv',
            encSalt='esalt',
            resetPrivateKey_encrypted='rpvt',
            resetIV='riv',
            resetEncPrivateKey_encrypted='repvt',
            resetEncIV='reiv'
        )
        assert result is True

        # re-register same username
        result = User.registerUser(
            'testuser',
            'othermail@mail.com',
            loginPublicKey='lpub',
            loginPrivateKey_encrypted='lpriv',
            loginIV='liv',
            loginSalt='lsalt',
            encPublicKey='epub',
            encPrivateKey_encrypted='epriv',
            encIV='eiv',
            encSalt='esalt',
            resetPrivateKey_encrypted='rpvt',
            resetIV='riv',
            resetEncPrivateKey_encrypted='repvt',
            resetEncIV='reiv'
        )
        assert result is None

        # re-register same email
        result = User.registerUser(
            'otheruser',
            'test@mail.com',
            loginPublicKey='lpub',
            loginPrivateKey_encrypted='lpriv',
            loginIV='liv',
            loginSalt='lsalt',
            encPublicKey='epub',
            encPrivateKey_encrypted='epriv',
            encIV='eiv',
            encSalt='esalt',
            resetPrivateKey_encrypted='rpvt',
            resetIV='riv',
            resetEncPrivateKey_encrypted='repvt',
            resetEncIV='reiv'
        )
        assert result is None

def test_authenticate(app):
    with app.test_request_context():
        # Register user with valid fields (no password parameter)
        User.registerUser(
            'testuser',               # username
            'test@mail.com',          # email
            'lpub',                   # loginPublicKey
            'lpriv',                  # loginPrivateKey_encrypted
            'liv',                    # loginIV
            'lsalt',                  # loginSalt
            'rpvt',                   # resetPrivateKey_encrypted
            'riv',                    # resetIV
            'repvt',                  # resetEncPrivateKey_encrypted
            'reiv',                   # resetEncIV
            'epub',                   # encPublicKey
            'epriv',                  # encPrivateKey_encrypted
            'eiv',                    # encIV
            'esalt'                   # encSalt
        )

        # Check user was created correctly
        user = User.query.filter_by(username='testuser').first()
        assert user.email == 'test@mail.com'

        # Simulate login (calls login_user internally)
        user = User.authenticate('testuser')  # Only takes username
        assert user.email == 'test@mail.com'

        # Negative test: non-existent user
        user = User.authenticate('nonexistent_user')
        assert user is None


def test_logout(app):
    with app.test_request_context():
        from flask_login import login_user, current_user

        # Create and log in a user manually
        user = User.registerUser('logoutuser', 'logout@mail.com', 'logoutpass',publicKey=mockPubKey,privateKey=mockPvtKey)
        user = User.query.filter_by(username='logoutuser').first()
        login_user(user) # bypass the authenticate function, manual login

        assert current_user.is_authenticated is True

        result = User.logout() # fn being tested 
        assert result == 0
        assert current_user.is_authenticated is False


bcrypt = Bcrypt()
def test_checkPassword(app):
    with app.test_request_context():
        User.registerUser(
            'testuser',
            'test@mail.com',
            'lpub', 'lpriv', 'liv', 'lsalt',
            'rpvt', 'riv',
            'repvt', 'reiv',
            'epub', 'epriv', 'eiv', 'esalt'
        )

        user = User.query.filter_by(username='testuser').first()
        assert user is not None

        # Manually simulate a hashed password for testing
        password = 'correctPassword!'
        hashed = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')
        user.hashedPass = hashed

        # Positive password check
        assert user.checkPassword('correctPassword!')

        # Negative password check
        assert not user.checkPassword('wrongPassword!')
