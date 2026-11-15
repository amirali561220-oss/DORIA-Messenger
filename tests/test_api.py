import os
import tempfile

# Isolated database before importing the application.
_test_dir = tempfile.TemporaryDirectory()
os.environ['DORIA_DB_PATH'] = os.path.join(_test_dir.name, 'test_doria.db')
os.environ['DORIA_SECRET_KEY'] = 'test-only-secret-key-that-is-long-enough-123456'
os.environ['DORIA_ENV'] = 'test'
os.environ['DORIA_ALLOWED_ORIGINS'] = '*'

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def register_user(username):
    response = client.post('/register', json={'username': username, 'display_name': username.title(), 'password': 'test-password-123', 'accept_rules': True})
    assert response.status_code == 201, response.text
    return response.json()['user_id']

def login_headers(username):
    response = client.post('/login', json={'username': username, 'password': 'test-password-123'})
    assert response.status_code == 200, response.text
    return {'Authorization': 'Bearer ' + response.json()['access_token']}

def test_health_endpoint():
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json()['ok'] is True

def test_registration_requires_rules_and_strong_password():
    rejected = client.post('/register', json={'username': 'rulesuser', 'display_name': 'Rules', 'password': 'test-password-123', 'accept_rules': False})
    assert rejected.status_code == 400
    weak = client.post('/register', json={'username': 'weakuser', 'display_name': 'Weak', 'password': 'short', 'accept_rules': True})
    assert weak.status_code == 422

def test_register_login_and_private_message():
    register_user('sender1')
    receiver_id = register_user('receiver1')
    sender_headers = login_headers('sender1')
    login_headers('receiver1')
    sent = client.post('/messages', headers=sender_headers, json={'receiver_id': receiver_id, 'body': 'Hello from DORIA'})
    assert sent.status_code == 201
    conversation = client.get(f'/messages/{receiver_id}', headers=sender_headers)
    assert conversation.status_code == 200
    assert conversation.json()[0]['body'] == 'Hello from DORIA'
    assert client.get(f'/messages/{receiver_id}').status_code == 401

def test_block_prevents_private_messages():
    register_user('blocker1')
    target_id = register_user('blocked1')
    headers = login_headers('blocker1')
    assert client.post(f'/blocks/{target_id}', headers=headers).status_code == 201
    sent = client.post('/messages', headers=headers, json={'receiver_id': target_id, 'body': 'Blocked message'})
    assert sent.status_code == 403
    listed = client.get('/blocks', headers=headers)
    assert listed.status_code == 200
    assert any(item['id'] == target_id for item in listed.json())

def test_group_membership_and_messages():
    register_user('groupowner')
    headers = login_headers('groupowner')
    created = client.post('/groups', headers=headers, json={'name': 'Test Group'})
    assert created.status_code == 201
    group_id = created.json()['group_id']
    sent = client.post(f'/groups/{group_id}/messages', headers=headers, json={'body': 'Group hello'})
    assert sent.status_code == 201
    messages = client.get(f'/groups/{group_id}/messages', headers=headers)
    assert messages.status_code == 200
    assert messages.json()[0]['body'] == 'Group hello'
