from glycon.server import app, socketio
import eventlet
import eventlet.wsgi
from OpenSSL import SSL
import os
from werkzeug.middleware.dispatcher import DispatcherMiddleware

if __name__ == "__main__":
    base_url = os.getenv('BASE_URL', '').rstrip('/')
    
    # HTTPS Server (root /)
    ssl_sock = eventlet.wrap_ssl(
        eventlet.listen((app.config['HOST'], app.config['PORT'])),
        certfile='cert.pem',
        keyfile='key.pem',
        server_side=True
    )

    # HTTP Server (with base URL)
    http_sock = eventlet.listen((app.config['HOST'], 5555))
    
    def run_https_server():
        eventlet.wsgi.server(ssl_sock, app, log_output=False)
    
    def run_http_server():
        if base_url:
            # Mount app under base_url
            prefixed_app = DispatcherMiddleware(app, {
                base_url: app
            })
            eventlet.wsgi.server(http_sock, prefixed_app, log_output=False)
        else:
            eventlet.wsgi.server(http_sock, app, log_output=False)

    # Initialize both servers
    socketio.start_background_task(run_https_server)
    socketio.start_background_task(run_http_server)
    
    # Correct SocketIO configuration
    socketio.run(app, 
                debug=app.config.get('DEBUG', False))