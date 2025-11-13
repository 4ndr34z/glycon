from glycon.server import app, socketio
import os
from werkzeug.middleware.dispatcher import DispatcherMiddleware
import argparse

class FixedDispatcherMiddleware(DispatcherMiddleware):
    def __call__(self, environ, start_response):
        path = environ['PATH_INFO']
        # Allow Socket.IO paths to pass through to the main app regardless of BASE_URL
        if path.startswith('/socket.io/'):
            return self.app(environ, start_response)
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

    @property
    def debug(self):
        # Return the debug attribute from the first mounted app that has it
        for mount_point, app in self.mounts.items():
            if hasattr(app, 'debug'):
                return app.debug
        return False

    @debug.setter
    def debug(self, value):
        # Set the debug attribute on all mounted apps that have it
        for mount_point, app in self.mounts.items():
            if hasattr(app, 'debug'):
                app.debug = value

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Glycon server with options for SSL and HTTP port.")
    parser.add_argument('--no-ssl', action='store_true', help='Disable HTTPS server on port 443')
    parser.add_argument('--http-port', type=int, default=5555, help='Port for HTTP server (default: 5555)')
    args = parser.parse_args()

    base_url = os.getenv('BASE_URL', '').rstrip('/')

    # Prepare the app for mounting
    if base_url:
        prefixed_app = FixedDispatcherMiddleware(app, {
            '/': app,
            base_url: app
        })
    else:
        prefixed_app = app

    if not args.no_ssl:
        # HTTPS Server
        socketio.start_background_task(lambda: socketio.run(prefixed_app, host=app.config['HOST'], port=app.config['PORT'], ssl_context=('cert.pem', 'key.pem'), debug=False))

    # HTTP Server
    socketio.run(prefixed_app, host=app.config['HOST'], port=args.http_port, debug=False)
