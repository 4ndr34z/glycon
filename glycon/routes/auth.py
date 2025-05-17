from flask import render_template, request, redirect, url_for, send_from_directory, jsonify
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
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

    # New route to get list of users
    @app.route('/api/users', methods=['GET'])
    def get_users():
        if not current_user.is_authenticated:
            return jsonify({'error': 'Unauthorized'}), 401
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT id, username, email FROM users")
        users = [{'id': row[0], 'username': row[1], 'email': row[2]} for row in c.fetchall()]
        conn.close()
        return jsonify(users)

    # New route to add a new user
    @app.route('/api/users', methods=['POST'])
    def add_user():
        if not current_user.is_authenticated:
            return jsonify({'error': 'Unauthorized'}), 401
        data = request.json
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        if not username or not password or not email:
            return jsonify({'error': 'Username, password, and email are required'}), 400
        hashed_password = generate_password_hash(password)
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, hashed_password, email))
            conn.commit()
            conn.close()
            return jsonify({'message': 'User added successfully'})
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists'}), 400

    # New route to change password
    @app.route('/api/users/<int:user_id>/change_password', methods=['POST'])
    def change_password(user_id):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Unauthorized'}), 401
        data = request.json
        new_password = data.get('new_password')
        if not new_password:
            return jsonify({'error': 'New password is required'}), 400
        hashed_password = generate_password_hash(new_password)
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Password changed successfully'})

    # New route to delete a user
    @app.route('/api/users/<int:user_id>', methods=['DELETE'])
    def delete_user(user_id):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Unauthorized'}), 401
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User deleted successfully'})

    # New route to update user info (username, email)
    @app.route('/api/users/<int:user_id>', methods=['PUT'])
    def update_user(user_id):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Unauthorized'}), 401
        data = request.json
        username = data.get('username')
        email = data.get('email')
        if not username or not email:
            return jsonify({'error': 'Username and email are required'}), 400
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            c.execute("UPDATE users SET username=?, email=? WHERE id=?", (username, email, user_id))
            conn.commit()
            conn.close()
            return jsonify({'message': 'User updated successfully'})
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists'}), 400
