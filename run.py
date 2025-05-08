from glycon.server import app, socketio
import eventlet
import eventlet.wsgi
from OpenSSL import SSL
import os
from werkzeug.middleware.dispatcher import DispatcherMiddleware

if __name__ == "__main__":
    # Create SSL socket for HTTPS
    ssl_sock = eventlet.wrap_ssl(
        eventlet.listen((app.config['HOST'], app.config['PORT'])),
        certfile='cert.pem',
        keyfile='key.pem',
        server_side=True
    )

    # Create HTTP socket on port 5555
    http_sock = eventlet.listen((app.config['HOST'], 5555))
    
    # Get base URL from environment variable or use default
    base_url = os.getenv('BASE_URL', '')

    # Run the HTTPS server
    def run_https_server():
        eventlet.wsgi.server(ssl_sock, app, log_output=True)
    
    # Run the HTTP server with potential base URL
    def run_http_server():
        if base_url:
            # Create a new app with the base URL prefix
            prefixed_app = DispatcherMiddleware(app, {
                base_url.rstrip('/'): app
            })
            eventlet.wsgi.server(http_sock, prefixed_app, log_output=False)
        else:
            eventlet.wsgi.server(http_sock, app, log_output=True)

    # Initialize both servers
    socketio.start_background_task(run_https_server)
    socketio.start_background_task(run_http_server)
    socketio.run(app, debug=app.config.get('DEBUG', False))