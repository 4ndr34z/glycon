from glycon.server import app, socketio
import eventlet
import eventlet.wsgi
from OpenSSL import SSL
import os
from werkzeug.middleware.dispatcher import DispatcherMiddleware

class FixedDispatcherMiddleware(DispatcherMiddleware):
    def __call__(self, environ, start_response):
        path = environ['PATH_INFO']
        # Sort mounts by length descending to prioritize longer prefixes
        sorted_mounts = sorted(self.mounts.items(), key=lambda x: len(x[0]), reverse=True)
        for mount_point, app in sorted_mounts:
            if path.startswith(mount_point):
                environ['SCRIPT_NAME'] = mount_point
                environ['PATH_INFO'] = path[len(mount_point):] or '/'
                return app(environ, start_response)
        # If no match, return 404
        start_response('404 Not Found', [('Content-Type', 'text/plain')])
        return [b'Not Found']
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
            # Mount app under both root (/) and base_url
            prefixed_app = FixedDispatcherMiddleware(app, {
                '/': app,
                base_url: app
            })
            eventlet.wsgi.server(http_sock, prefixed_app, log_output=False)
        else:
            eventlet.wsgi.server(http_sock, app, log_output=False)

    socketio.start_background_task(run_http_server)

    # Correct SocketIO configuration
    socketio.run(app,
                debug=app.config.get('DEBUG', False))
