import pytest
from app import create_app,db
import os 


@pytest.fixture

def app():
    print("in test: "+os.getcwd())
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()  # Clean up after test

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()