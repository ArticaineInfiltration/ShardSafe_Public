from app.forms import RegisterForm
from tests.conftest import app

validUser = {
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

shortnameUser = {
    'username': 'uni',
 'email':'unittest@mail.com',
 'password':'unitTest123!',
 'password2':'unitTest123!',
}   

badMailUser = {
    'username': 'uni',
 'email': None,
 'password':'unitTest123!',
 'password2':'unitTest123!',
}   

badPasswordUser = {
    'username': 'uni',
 'email':'unittest@mail.com',
 'password':None,
 'password2':None,
}   

def test_userRegistration_success(app):
    with app.test_request_context('/register', method='POST', data=validUser):
        form = RegisterForm()
        assert form.validate() == True

def test_userRegistration_fail_EmptyUsername(app):
    validUser['username'] = ''
    with app.test_request_context('/register', method='POST', data=validUser):
        form = RegisterForm()
        assert form.validate() == False, f"Form errors: {form.errors}"


def test_userRegistration_fail_EmptyEmail(app):
    validUser['email'] = ''
    with app.test_request_context('/register', method='POST', data=validUser):
        form = RegisterForm()
        assert form.validate() == False, f"Form errors: {form.errors}"


def test_userRegistration_fail_EmptyPassword(app):
    validUser['password'] = ''
    with app.test_request_context('/register', method='POST', data=validUser):
        form = RegisterForm()
        assert form.validate() == False, f"Form errors: {form.errors}"


def test_userRegistration_fail_EmptyConfirmPass(app):
    validUser['password2'] = ''
    with app.test_request_context('/register', method='POST', data=validUser):
        form = RegisterForm()
        assert form.validate() == False, f"Form errors: {form.errors}"



def test_userRegistration_fail_NameTooShort(app):
    with app.test_request_context('/register', method='POST', data=shortnameUser):
        form = RegisterForm()
        assert form.validate() == False

def test_userRegistration_fail_BadMail(app):
    badMails  = ['user@mail','@mail.com', 'user@mail']

    for badMail in badMails:
        testUser = badMailUser
        testUser['email'] =badMail
        with app.test_request_context('/register', method='POST', data=testUser):
            form = RegisterForm()
            assert form.validate() == False

def test_userRegistration_fail_invalidPassword(app):
    badPasswords  = ['short', # too short
                    'short1234', # no Uppercase and symbol
                    'Short1234', # no symbol
                    'Shortpass', #no number
                    '123!!pass',]  # no uppercase

    for badPass in badPasswords:
        testUser = badPasswordUser
        testUser['password'] =badPass
        testUser['password2'] =badPass
        with app.test_request_context('/register', method='POST', data=testUser):
            form = RegisterForm()
            assert form.validate() == False


def test_userRegistration_fail_PasswordMatch(app):
    validPassword = 'aValidPassword123!'
    testUser = badPasswordUser
    testUser['password'] = validPassword
    testUser['password2'] = 'anotherValidPassword123!' # different passw should fail

    with app.test_request_context('/register', method='POST', data=testUser):
        form = RegisterForm()
        assert form.validate() == False, f"Form errors: {form.errors}"