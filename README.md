# glycon
Glycon - C2 framework

### Install
```bash
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

### Run
```bash
python3 run.py
```

admin/password

## Version 1.0
<p>Basic connectivity, screenshots, websocket terminal</p>
* Terminal has command history and directory tracking. 


## Version 1.1
<p>Added Cookie Stealer</p>

## Version 1.2
<p>Functions for deployment and deleting agents</p>

## Version 1.3
* Added killdate
* First aagent checkin is now instant and the rest follows interval with jitter

## Version 1.4
* Added Shellcode-Runner. Uses Donut, so Donut must be install and in PATH on the server
### Version 1.4.1
* Using Donut in docker. 
```bash
git clone https://github.com/TheWover/donut
cd donut
docker build -t donut .
```

### Version 1.4.2
* Added support for multiple shellcode runners; exe/dll/binary and hex
* Fixed headless agent shellcode execution problem

Know issues: When using custom shellcode, it has to be exited as thread.

### Version 1.4.3
Running 2 server instances. 
1 listening on 443 using HTTPS
1 listening on 5555 using HTTP 

This to support reverse-proxy with SSL-tunnel terminated on the proxy. Forwarding to port 5555 HTTP on Glycon
Start it by setting environment variable for base_url (for the reverse-proxy setup)
```export BASE_URL=/8b7c699211b2d90cbbf58545dd708;python3 run.py```

### Version 1.4.4
* Added kill-pill function
* Added "Trusted certificate" for agent deployment command. 
* Changed logo

### Version 1.4.5
* Added killdate in agent info
* Added functionality to install missing modules if needed 
* Added checkin interval in agent info
* Added logic for controlling and displaying inactive agents
* Supports Nix agents
* Added deployment command using Winget

### Version 1.4.6
* Changed shellcode-runner. Now generates a loader-script, that is downloaded and executed in memory.

### Version 1.4.7
* Saving agent settings in database

