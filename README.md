<div align="center">
  <img src="glycon/static/images/glycon2.png" alt="Glycon Logo" width="200"/>
  <h1>🛡️ Glycon - C2 Framework</h1>
  <p><em>Small Command and Control Framework for Red Team Operations and Pentesting</em></p>
</div>

---

## 📋 Table of Contents
- [🚀 Quick Start](#-quick-start)
- [⚙️ Installation](#️-installation)
- [🎯 Usage](#-usage)
- [📚 Features](#-features)
- [🔄 Version History](#-version-history)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Virtual environment support

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd glycon

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running Glycon
```bash
# Basic run (HTTPS on 443 + HTTP on 5555)
python3 run.py

# Development mode (HTTP only)
python3 run.py --no-ssl --http-port 3000
```

**Default Credentials:**
- 👤 Username: `admin`
- 🔑 Password: `password`

---

## ⚙️ Installation

### Detailed Setup
```bash
# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Optional) For shellcode functionality - Install Donut
git clone https://github.com/TheWover/donut
cd donut
docker build -t donut .
```

---

## 🎯 Usage

### Command Line Options
Glycon supports flexible server configuration through command-line arguments:

#### Basic Usage Examples
```bash
# 🔒 Production mode (default)
python3 run.py

# 🧪 Development/Testing mode
python3 run.py --no-ssl --http-port 3000

# 🌐 Custom HTTP port with SSL
python3 run.py --http-port 8080

# 🚀 HTTP only mode
python3 run.py --no-ssl
```

#### Available Options
| Flag | Description | Default |
|------|-------------|---------|
| `--no-ssl` | Disable HTTPS server (port 443) | `false` |
| `--http-port PORT` | Specify HTTP server port | `5555` |

#### Advanced Usage Scenarios

**🔧 Development Environment:**
```bash
python3 run.py --no-ssl --http-port 3000
# Runs HTTP server on port 3000 without SSL
```

**🏭 Production with SSL:**
```bash
python3 run.py
# Runs both HTTPS (443) and HTTP (5555) servers
```

**🔀 Reverse Proxy Setup:**
```bash
export BASE_URL=/your-secret-path
python3 run.py --no-ssl --http-port 5555
# Perfect for setups with SSL termination at proxy
```

**🌍 Custom Configuration:**
```bash
python3 run.py --http-port 8080
# HTTPS on 443, HTTP on 8080
```

### Web Interface Access
- **HTTPS:** `https://localhost` (port 443)
- **HTTP:** `http://localhost:5555` (or custom port)

---

## 📚 Features

### Core Functionality
- ✅ **Agent Management** - Deploy and control remote agents
- ✅ **Real-time Terminal** - Interactive shell access with command history
- ✅ **Screenshot Capture** - Remote desktop monitoring
- ✅ **Webcam Capture** - Check if someone is at the remote machine, before taking over the Remote Desktop
- ✅ **Remote Desktop** - Interactive remote desktop 
- ✅ **Browser Cookie Stealing** - Extract browser cookies
- ✅ **Browser Credential Stealing** - Extract browser credentials
- ✅ **Browser History Stealing** - Extract browser history
- ✅ **Shellcode Execution** - Run shellcode payloads via Donut
- ✅ **Python In-Memory Execution** - Execute arbitrary Python scripts directly in agent memory

### Advanced Features
- 🔐 **Dual Server Support** - HTTPS + HTTP simultaneous operation
- 🛡️ **Privilege Escalation** - Elevate to `NT AUTHORITY\SYSTEM` using `#getsystem`
- 🛡️ **SSL/TLS Encryption** - Secure communications
- 🛡️ **IP Whitelisting** - Restrict server access to specified IP addresses
- 🌐 **Reverse Proxy Ready** - Base URL support for proxy deployments
- ⏰ **Killdate Support** - Automatic agent self-destruction
- 📊 **Agent Monitoring** - Real-time status and health checks
- 🎯 **Keylogger** - Capture keystrokes from agents
- 📁 **Database Storage** - Persistent data storage for all operations
- ⌨️ **Terminal Shortcuts** - Execute C2 tasks directly from the terminal with `#` commands (e.g., `#screenshot`, `#upload`, `#creds`)
- 📂 **Bidirectional File Transfer** - Upload files via dialog or exfiltrate via terminal command
- 🦊 **Live Browser Looting** - Custom mozLz4 decompressor for Firefox session extraction
- 🎭 **Fake Ransomware Module** - Deploy a professional-looking, full-screen ransom note with a live countdown timer and automatic `explorer.exe` lockdown.

### Supported Platforms
- 🪟 Windows agents (Full support + Elevation)
- 🐧 Linux agents (Basic support + Root detection)
- 🍎 macOS agents

---

## 🔄 Version History

### Version 2.0 (Current)
- ⚡ **Privilege Escalation**: Added `#getsystem` to elevate administrative agents to `NT AUTHORITY\SYSTEM` via a transient Windows Service.
- 🛡️ **Visual Privilege Indicators**: Added icons to the agent list to distinguish between `User`, `Administrator`, and `SYSTEM` sessions.
- 🎭 **Ransomware Module**: Added `#fakeransom` command to simulate a high-impact ransomware attack with countdown timer and UI lockdown.
- 🧹 **System Recovery**: Added `#clearransom` to restore the target system, restart explorer, and clean up artifacts.
- ⌨️ **Expanded Help System**: Integrated `#help` directly into the terminal for better discoverability.
- 📝 **In-Memory Python**: Agents now support `execute_python` task type, allowing for arbitrary code execution without disk artifacts.
- 🛡️ **Stealth Improvements**: Enhanced explorer lockdown logic for ransomware simulation scenarios.

### Version 1.9
- ⌨️ **Enhanced Terminal**: Added `#` shortcuts for all C2 tasks (screenshot, creds, webcam, etc.)
- 📂 **Interactive Uploads**: Terminal `#upload` now opens a file picker for local files.
- 📤 **File Exfiltration**: Added `#exfiltrate` command for easy file retrieval from agents.
- 🦊 **Firefox Session Recovery**: Implemented custom mozLz4 decompression to extract cookies from active Firefox sessions.
- 🍪 **Universal Cookie Export**: Standardized JSON format for easy import into browser extensions.
- 🛠️ **Stability**: Fixed Base64 logging overhead and improved agent template compatibility.

### Version 1.5.3
- Fixed bug in Remote desktop
- Added webcam capture

### Version 1.5.2
- Developed a "Remote Desktop" prototype to serve as a high-impact presentation asset for engaging management and securing buy-in.  

### Version 1.5.1
- Added IP whitelisting feature to restrict access to the C2 server based on allowed IP addresses.
- If you lock yourself out, you can reset the whitelist by running: `sqlite3 c2.db "DELETE FROM ip_whitelist;"`


### Version 1.5
- added browser password stealing functionality
- added browser history stealing functionality

### Version 1.4.9.8
- added output from shellcode-execution

### Version 1.4.9.7
- 🔄 Improved shellcode runner with obfuscaion and encryption.
- 🐛 Fixed an issue where the terminal would not load properly when accessing agents through the web interface.
- Fixed an issue where the cookie-stealer would not work properly with newer versions of Chrome and Edge.

### Version 1.4.9.5
- 🐛 Fixed the shellcode runner. It now generates shellcode from executable files (with or without arguments) and loads it reflectively on the target.
- Raw shellcode loaded from file or pasted as hex also works

### Version 1.4.9.4
- 🐛 Corrected winget deployment
- 🥷 Updated Firefox cookiestealing

### Version 1.4.9.2
- 🐛 Fixed shellcode-runner bug

### Version 1.4.9.1
- 🔧 Fixed terminal instability issues

### Version 1.4.9
- 📝 Ascending order in keylogger logs
- 🍪 Updated cookie stealer functionality

### Version 1.4.8
- ⌨️ Enhanced keylogger functionality

### Version 1.4.7
- 💾 Agent settings saved to database

### Version 1.4.6
- 🚀 Improved shellcode-runner with in-memory execution

### Version 1.4.5
- 📅 Killdate display in agent info
- 📦 Auto-install missing modules
- ⏱️ Checkin interval display
- 👻 Inactive agent management
- 🐧 Nix agent support
- 📥 Winget deployment commands

### Version 1.4.4
- 💀 Kill-pill functionality
- 🛡️ Trusted certificate support
- 🎨 Updated logo

### Version 1.4.3
- 🌐 Dual server instances (HTTPS + HTTP)
- 🔀 Reverse proxy support with BASE_URL

### Version 1.4.2
- 🔧 Multiple shellcode runner formats (exe/dll/binary/hex)
- 🐛 Fixed headless agent execution

### Version 1.4.1
- 🐳 Donut integration via Docker

### Version 1.4
- 🧵 Shellcode execution with Donut

### Version 1.3
- 📅 Killdate functionality
- ⚡ Instant first checkin with jitter

### Version 1.2
- ➕ Agent deployment and deletion functions

### Version 1.1
- 🍪 Cookie stealer module

### Version 1.0
- 🔗 Basic agent connectivity
- 📸 Screenshot functionality
- 💻 WebSocket terminal with history and directory tracking

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. 💾 Commit your changes (`git commit -m 'Add amazing feature'`)
4. 🚀 Push to the branch (`git push origin feature/amazing-feature`)
5. 📝 Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest

# Format code
black .
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <p><strong>⚠️ Disclaimer:</strong> This tool is for educational and authorized testing purposes only. Use responsibly and in compliance with applicable laws.</p>
  <p>Made with ❤️ for the cybersecurity community</p>
</div>

---

<div align="center">
  <p><strong>⚠️ Disclaimer:</strong> This tool is for educational and authorized testing purposes only. Use responsibly and in compliance with applicable laws.</p>
  <p>Made with ❤️ for the cybersecurity community</p>
</div>
