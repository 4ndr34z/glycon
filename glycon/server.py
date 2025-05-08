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