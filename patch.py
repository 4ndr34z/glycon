with open('glycon/routes/sockets.py', 'r') as f:
    content = f.read()

old = """    # Add screen info and scale factors handlers
    @socketio.on('screen_info', namespace='/remote_desktop')
    def handle_screen_info(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            if not agent_id:
                print("[SocketIO] screen_info event missing agent_id")
                return
            print(f"[SocketIO] Forwarding screen info from agent {agent_id}")
            emit('screen_info', data, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')

    @socketio.on('scale_factors', namespace='/remote_desktop')
    def handle_scale_factors(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            if not agent_id:
                print("[SocketIO] scale_factors event missing agent_id")
                return
            print(f"[SocketIO] Forwarding scale factors from agent {agent_id}")
            emit('scale_factors', data, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')"""

new = """    # Add screen info and scale factors handlers
    @socketio.on('screen_info', namespace='/remote_desktop')
    def handle_screen_info(data):
        # Forward from agent to UI, so no current_user.is_authenticated check
        agent_id = data.get('agent_id')
        if not agent_id:
            print("[SocketIO] screen_info event missing agent_id")
            return
        print(f"[SocketIO] Forwarding screen info from agent {agent_id}")
        emit('screen_info', data, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')

    @socketio.on('scale_factors', namespace='/remote_desktop')
    def handle_scale_factors(data):
        # Forward from agent to UI, so no current_user.is_authenticated check
        agent_id = data.get('agent_id')
        if not agent_id:
            print("[SocketIO] scale_factors event missing agent_id")
            return
        print(f"[SocketIO] Forwarding scale factors from agent {agent_id}")
        emit('scale_factors', data, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')"""

content = content.replace(old, new)
with open('glycon/routes/sockets.py', 'w') as f:
    f.write(content)
