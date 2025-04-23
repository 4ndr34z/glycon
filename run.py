from glycon.server import app, socketio

if __name__ == '__main__':
    print(f"Starting C2 server on {app.config['HOST']}:{app.config['PORT']}")
    socketio.run(app, 
                host=app.config['HOST'], 
                port=app.config['PORT'], 
                ssl_context='adhoc', 
                debug=True)