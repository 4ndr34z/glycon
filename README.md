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
- Python 3.7+
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
- ✅ **Cookie Stealing** - Extract browser credentials
- ✅ **Shellcode Execution** - Run custom payloads via Donut

### Advanced Features
- 🔐 **Dual Server Support** - HTTPS + HTTP simultaneous operation
- 🛡️ **SSL/TLS Encryption** - Secure communications
- 🌐 **Reverse Proxy Ready** - Base URL support for proxy deployments
- ⏰ **Killdate Support** - Automatic agent self-destruction
- 📊 **Agent Monitoring** - Real-time status and health checks
- 🎯 **Keylogger** - Capture keystrokes from agents
- 📁 **Database Storage** - Persistent data storage for all operations

### Supported Platforms
- 🪟 Windows agents
- 🐧 Linux agents
- 🍎 macOS agents

---

## 🔄 Version History

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
