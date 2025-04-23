from flask import render_template, request, redirect, url_for, send_from_directory
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash
import sqlite3
from glycon.config import CONFIG
from glycon.models import User


def init_auth_routes(app, login_manager):
    @login_manager.user_loader
    def load_user(user_id):
        return User(user_id)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                return render_template('login.html', error="Username and password required")
            
            conn = sqlite3.connect(CONFIG.database)
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
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/static/<path:filename>')
    def static_files(filename):
        return send_from_directory('static', filename)