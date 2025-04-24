from glycon.server import app, socketio
import eventlet
import eventlet.wsgi
from OpenSSL import SSL

if __name__ == "__main__":
    # Create SSL socket
    sock = eventlet.wrap_ssl(
        eventlet.listen((app.config['HOST'], app.config['PORT'])),
        certfile='cert.pem',
        keyfile='key.pem',
        server_side=True
    )

    # Run the server
    def run_server():
        eventlet.wsgi.server(sock, app, log_output=False)
    
    # Initialize socketio server
    socketio.start_background_task(run_server)
    socketio.run(app, debug=app.config.get('DEBUG', False))