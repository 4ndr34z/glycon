from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_cors import CORS
from glycon.config import CONFIG
from glycon.routes.auth import init_auth_routes
from glycon.routes.views import init_view_routes
from glycon.routes.api import init_api_routes
from glycon.routes.sockets import init_socket_handlers

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.secret_key = CONFIG.secret_key
    app.config['MAX_CONTENT_LENGTH'] = CONFIG.max_content_length
    app.config['HOST'] = CONFIG.host
    app.config['PORT'] = CONFIG.port

    # Initialize extensions
    # Enable CORS for all domains
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Initialize SocketIO with proper async_mode
    socketio = SocketIO(app, 
                    cors_allowed_origins="*",
                    async_mode='eventlet',  # or 'eventlet' if you prefer
                    logger=True,
                    engineio_logger=True)

    
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    # Initialize routes
    init_auth_routes(app, login_manager)
    init_view_routes(app)
    init_api_routes(app, socketio)
    init_socket_handlers(socketio)

    return app, socketio

app, socketio = create_app()