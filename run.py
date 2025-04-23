from glycon.server import app, socketio
import eventlet
import eventlet.wsgi
from OpenSSL import SSL

if __name__ == "__main__":
    # Generate SSL context
    ssl_context = {
        'certfile': 'cert.pem',
        'keyfile': 'key.pem',
        'server_side': True
    }
    
    # Create eventlet WSGI server with SSL
    listener = eventlet.wrap_ssl(
        eventlet.listen((app.config['HOST'], app.config['PORT'])),
        certfile='cert.pem',
        keyfile='key.pem',
        server_side=True
    )
    
    # Run the server
    eventlet.wsgi.server(listener, app)