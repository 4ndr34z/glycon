import sys
import os
import pytest
import json
from flask import Flask

# Add the project root directory to sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from glycon.routes import api

@pytest.fixture
def client():
    app = Flask(__name__)
    api.init_api_routes(app, None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_shellcode_output_success(client):
    data = {
        "agent_id": "test-agent-123",
        "status": "success",
        "message": "Shellcode executed"
    }
    response = client.post('/api/shellcode_output', json=data)
    assert response.status_code == 200
    resp_json = response.get_json()
    assert resp_json['status'] == 'success'

def test_shellcode_output_missing_fields(client):
    data = {
        "agent_id": "test-agent-123"
    }
    response = client.post('/api/shellcode_output', json=data)
    assert response.status_code == 400
    resp_json = response.get_json()
    assert resp_json['status'] == 'error'

def test_shellcode_output_non_json(client):
    response = client.post('/api/shellcode_output', data="notjson", content_type='text/plain')
    assert response.status_code == 400
    resp_json = response.get_json()
    assert resp_json['status'] == 'error'
