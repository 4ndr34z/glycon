from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
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
    socketio = SocketIO(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    # Initialize routes
    init_auth_routes(app, login_manager)
    init_view_routes(app)
    init_api_routes(app, socketio)
    init_socket_handlers(socketio)

    return app, socketio

app, socketio = create_app()