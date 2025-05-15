from flask import Flask, request, url_for
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_cors import CORS
from glycon.config import CONFIG
from glycon.routes.auth import init_auth_routes
from glycon.routes.views import init_view_routes
from glycon.routes.api import init_api_routes
from glycon.routes.sockets import init_socket_handlers
from glycon.routes.screenshots import init_screenshot_handlers
import logging
import os
from threading import Thread
import time
import json
import traceback  # For detailed error reporting


def agent_status_monitor(app, socketio):
    with app.app_context():
        while True:
            try:
                print("\n[Monitor] Starting agent status check...")
               
                client = app.test_client()
                
                # Makeing sure to include Content-Type header
                response = client.post(
                    '/api/check_agent_status',
                    headers={
                        'Authorization': f'Bearer {CONFIG.monitor_token}',
                        'Content-Type': 'application/json'
                    },
                    data=json.dumps({}),  # Empty JSON payload
                    content_type='application/json'
                )
                
                #print(f"[Monitor] Response status: {response.status_code}")
                #print(f"[Monitor] Response data: {response.get_json()}")
                
            except Exception as e:
                print(f"\n[Monitor ERROR] {str(e)}")
                traceback.print_exc()
            time.sleep(60)

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.secret_key = CONFIG.secret_key
    app.config['MAX_CONTENT_LENGTH'] = CONFIG.max_content_length
    app.config['HOST'] = CONFIG.host
    app.config['PORT'] = CONFIG.port
    app.config['BASE_URL'] = os.getenv('BASE_URL', '').rstrip('/')
    app.logger.setLevel(logging.DEBUG)

   

    # Enable CORS for all domains
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Initialize SocketIO
    socketio = SocketIO(app, 
                    cors_allowed_origins="*",
                    async_mode='eventlet',
                    logger=True,
                    engineio_logger=True)

    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    # Initialize routes
    init_auth_routes(app, login_manager)
    init_view_routes(app)
    init_api_routes(app, socketio)
    
    # Initialize both socket handlers
    init_socket_handlers(socketio)
    init_screenshot_handlers(socketio) 

    return app, socketio

app, socketio = create_app()

# Start the agent status monitor thread
monitor_thread = Thread(target=agent_status_monitor, args=(app, socketio))
monitor_thread.daemon = True
monitor_thread.start()
