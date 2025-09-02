from glycon.server import app, socketio
import eventlet
import eventlet.wsgi
from OpenSSL import SSL
import os
from werkzeug.middleware.dispatcher import DispatcherMiddleware
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Glycon server with options for SSL and HTTP port.")
    parser.add_argument('--no-ssl', action='store_true', help='Disable HTTPS server on port 443')
    parser.add_argument('--http-port', type=int, default=5555, help='Port for HTTP server (default: 5555)')
    args = parser.parse_args()

    base_url = os.getenv('BASE_URL', '').rstrip('/')

    if not args.no_ssl:
        # HTTPS Server (root /)
        ssl_sock = eventlet.wrap_ssl(
            eventlet.listen((app.config['HOST'], app.config['PORT'])),
            certfile='cert.pem',
            keyfile='key.pem',
            server_side=True
        )

        def run_https_server():
            eventlet.wsgi.server(ssl_sock, app, log_output=False)

        socketio.start_background_task(run_https_server)

    # HTTP Server (with base URL)
    http_sock = eventlet.listen((app.config['HOST'], args.http_port))

    def run_http_server():
        if base_url:
            # Mount app under base_url
            prefixed_app = DispatcherMiddleware(app, {
                base_url: app
            })
            eventlet.wsgi.server(http_sock, prefixed_app, log_output=False)
        else:
            eventlet.wsgi.server(http_sock, app, log_output=False)

    socketio.start_background_task(run_http_server)

    # Correct SocketIO configuration
    socketio.run(app,
                debug=app.config.get('DEBUG', False))
