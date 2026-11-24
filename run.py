#!/usr/bin/env python3
import argparse
import datetime
import getpass
import hashlib
import ipaddress
import os
import sqlite3
import subprocess
import sys
import venv

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(PROJECT_DIR, "venv")
REQUIREMENTS_FILE = os.path.join(PROJECT_DIR, "requirements.txt")
REQ_HASH_FILE = os.path.join(VENV_DIR, ".requirements_sha256")


def _get_venv_python() -> str:
    if os.name == "nt":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def _in_project_venv() -> bool:
    venv_py = _get_venv_python()
    if not os.path.isfile(venv_py):
        return False
    return os.path.abspath(sys.prefix) == os.path.abspath(VENV_DIR)


def _compute_req_hash() -> str:
    if not os.path.isfile(REQUIREMENTS_FILE):
        return ""
    with open(REQUIREMENTS_FILE, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _needs_pip_install(venv_py: str) -> bool:
    if not os.path.isfile(REQ_HASH_FILE):
        return True
    try:
        with open(REQ_HASH_FILE, "r", encoding="utf-8") as f:
            saved_hash = f.read().strip()
        if saved_hash != _compute_req_hash():
            return True
        res = subprocess.run(
            [venv_py, "-c", "import flask, flask_socketio, cryptography, eventlet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return res.returncode != 0
    except Exception:
        return True


def install_requirements(venv_py: str, force: bool = False) -> bool:
    if not os.path.isfile(REQUIREMENTS_FILE):
        print(f"[!] Could not find {REQUIREMENTS_FILE}.")
        return False

    if not force and not _needs_pip_install(venv_py):
        return True

    print("[*] Upgrading pip and installing packages from requirements.txt...")
    try:
        subprocess.run(
            [venv_py, "-m", "pip", "install", "--upgrade", "pip"],
            check=True,
        )
        subprocess.run(
            [venv_py, "-m", "pip", "install", "-r", REQUIREMENTS_FILE],
            check=True,
        )
        with open(REQ_HASH_FILE, "w", encoding="utf-8") as f:
            f.write(_compute_req_hash())
        print("[+] All dependencies in requirements.txt have been installed.")
        return True
    except subprocess.CalledProcessError as err:
        print(f"[!] Failed to install packages: {err}")
        return False


def bootstrap_venv():
    """Ensures venv exists, installs requirements, and re-executes run.py inside venv."""
    os.chdir(PROJECT_DIR)
    venv_py = _get_venv_python()
    first_time_venv = not os.path.isfile(venv_py)

    if first_time_venv:
        print(f"[*] Virtual environment (venv) not found. Creating {VENV_DIR} ...")
        builder = venv.EnvBuilder(with_pip=True)
        builder.create(VENV_DIR)
        print("[+] Virtual environment created.")

    if not _in_project_venv():
        install_requirements(venv_py, force=first_time_venv)
        print(f"[*] Activating venv and starting Glycon with {venv_py} ...\n")
        os.environ["VIRTUAL_ENV"] = VENV_DIR
        venv_bin = os.path.dirname(venv_py)
        os.environ["PATH"] = f"{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}"
        os.execv(venv_py, [venv_py, os.path.abspath(__file__)] + sys.argv[1:])
    else:
        install_requirements(venv_py, force=False)


def generate_self_signed_cert(cert_path="cert.pem", key_path="key.pem", common_name="localhost", days=365):
    """Generate a self-signed X.509 SSL certificate and private key."""
    common_name = (common_name or "localhost").strip()
    print(f"[*] Generating self-signed SSL certificate for '{common_name}' (valid for {days} days)...")

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Glycon C2"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        san_entries = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]

        try:
            ip_obj = ipaddress.ip_address(common_name)
            if ip_obj not in [ipaddress.ip_address("127.0.0.1")]:
                san_entries.append(x509.IPAddress(ip_obj))
        except ValueError:
            if common_name.lower() != "localhost":
                san_entries.append(x509.DNSName(common_name))

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"[+] SSL certificate saved to '{cert_path}' and private key to '{key_path}'.")
        return True

    except ImportError:
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-out", cert_path, "-keyout", key_path,
            "-days", str(days),
            "-subj", f"/C=NO/O=Glycon C2/CN={common_name}"
        ]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
            print(f"[+] SSL certificate generated via OpenSSL CLI ('{cert_path}', '{key_path}').")
            return True
        except Exception as err:
            print(f"[!] Failed to generate SSL certificate: {err}")
            return False


def update_admin_credentials(username: str, password: str):
    """Updates or creates the admin user in c2.db."""
    from werkzeug.security import generate_password_hash
    from glycon.config import CONFIG

    conn = sqlite3.connect(CONFIG.database)
    c = conn.cursor()
    pw_hash = generate_password_hash(password)
    c.execute("SELECT id FROM users WHERE id = 1")
    if c.fetchone():
        c.execute("UPDATE users SET username = ?, password = ? WHERE id = 1", (username, pw_hash))
    else:
        c.execute(
            "INSERT INTO users (id, username, password, email) VALUES (1, ?, ?, ?)",
            (username, pw_hash, f"{username}@home.no"),
        )
    conn.commit()
    conn.close()
    print(f"[+] Administrator account updated (username: '{username}').")


def interactive_setup_menu(default_host="0.0.0.0", default_http_port=5555, default_https_port=443):
    """Interactive setup and startup menu for Glycon C2."""
    cert_path, key_path = "cert.pem", "key.pem"
    certs_exist = os.path.isfile(cert_path) and os.path.isfile(key_path)

    config_state = {
        "host": default_host,
        "http_port": default_http_port,
        "https_port": default_https_port,
        "use_ssl": True,
        "base_url": os.getenv("BASE_URL", ""),
    }

    if not sys.stdin.isatty():
        if not certs_exist:
            generate_self_signed_cert(cert_path=cert_path, key_path=key_path)
        return config_state

    try:
        from bump_version import get_version
        ver_str = get_version()
    except Exception:
        ver_str = "2.1"

    try:
        while True:
            certs_exist = os.path.isfile(cert_path) and os.path.isfile(key_path)
            ssl_status = f"Enabled (Port {config_state['https_port']})" if config_state["use_ssl"] else "Disabled (HTTP Only)"
            cert_status = "Found (cert.pem / key.pem)" if certs_exist else "Missing!"

            print("\n" + "=" * 62)
            print(f"   GLYCON C2 v.{ver_str} — SETUP & STARTUP MENU")
            print("=" * 62)
            print(f"   Virtual Env    : {VENV_DIR} (Active)")
            print(f"   Bind Address   : {config_state['host']}")
            print(f"   HTTP Port      : {config_state['http_port']}")
            print(f"   HTTPS / SSL    : {ssl_status} [{cert_status}]")
            print(f"   Base URL       : {config_state['base_url'] or '/ (root)'}")
            print("-" * 62)
            print("   [1] Quick Start with current settings (Default)")
            print("   [2] Configure Setup (Ports, SSL, Certificates, Admin User)")
            print("   [3] Re-install / update packages from requirements.txt")
            print("   [4] Exit")
            print("=" * 62)

            choice = input("[?] Select an option [1-4, Enter=1]: ").strip() or "1"

            if choice == "1":
                if config_state["use_ssl"] and not certs_exist:
                    ans = input("[?] SSL certificates not found. Generate self-signed certificate now? [Y/n]: ").strip().lower()
                    if ans in ("", "y", "yes", "j", "ja"):
                        cn = input("[?] Enter Common Name or IP [default: localhost]: ").strip() or "localhost"
                        if not generate_self_signed_cert(cert_path, key_path, common_name=cn):
                            config_state["use_ssl"] = False
                    else:
                        print("[!] Continuing without HTTPS (--no-ssl).")
                        config_state["use_ssl"] = False
                break

            elif choice == "2":
                print("\n--- Network & Ports ---")
                host_in = input(f"[?] Bind IP Address [{config_state['host']}]: ").strip()
                if host_in:
                    config_state["host"] = host_in

                http_in = input(f"[?] HTTP Port [{config_state['http_port']}]: ").strip()
                if http_in.isdigit():
                    config_state["http_port"] = int(http_in)

                ssl_in = input("[?] Enable HTTPS/SSL server? [Y/n]: ").strip().lower()
                config_state["use_ssl"] = ssl_in in ("", "y", "yes", "j", "ja")

                if config_state["use_ssl"]:
                    https_in = input(f"[?] HTTPS Port [{config_state['https_port']}]: ").strip()
                    if https_in.isdigit():
                        config_state["https_port"] = int(https_in)

                    gen_prompt = "[?] Generate new SSL certificates? [y/N]: " if certs_exist else "[?] SSL certificates missing. Generate now? [Y/n]: "
                    gen_in = input(gen_prompt).strip().lower()
                    should_gen = gen_in in ("y", "yes", "j", "ja") if certs_exist else gen_in in ("", "y", "yes", "j", "ja")
                    if should_gen:
                        cn = input("[?] Common Name / IP for certificate [default: localhost]: ").strip() or "localhost"
                        days_in = input("[?] Validity in days [365]: ").strip()
                        days = int(days_in) if days_in.isdigit() else 365
                        generate_self_signed_cert(cert_path, key_path, common_name=cn, days=days)

                base_in = input(f"[?] Optional Base URL prefix (e.g. /c2, empty for root) [{config_state['base_url']}]: ").strip()
                if base_in:
                    config_state["base_url"] = "/" + base_in.strip("/")

                print("\n--- Administrator Account ---")
                adm_in = input("[?] Do you want to update the admin username/password in the database? [y/N]: ").strip().lower()
                if adm_in in ("y", "yes", "j", "ja"):
                    adm_user = input("[?] Admin username [admin]: ").strip() or "admin"
                    adm_pass = getpass.getpass("[?] New admin password: ").strip()
                    if adm_pass:
                        update_admin_credentials(adm_user, adm_pass)
                    else:
                        print("[!] Password was empty — keeping existing password.")

                start_now = input("\n[?] Start Glycon server with these settings now? [Y/n]: ").strip().lower()
                if start_now in ("", "y", "yes", "j", "ja"):
                    break

            elif choice == "3":
                install_requirements(_get_venv_python(), force=True)

            elif choice in ("4", "q", "exit"):
                print("[*] Exiting.")
                sys.exit(0)
            else:
                print("[!] Invalid selection, please try again.")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Aborted by user.")
        sys.exit(0)

    return config_state


if __name__ == "__main__":
    # 1. Ensure venv is created, activated, and requirements are installed
    bootstrap_venv()

    # 2. Now running inside venv — import Werkzeug and parse arguments
    from werkzeug.middleware.dispatcher import DispatcherMiddleware

    class FixedDispatcherMiddleware(DispatcherMiddleware):
        def __call__(self, environ, start_response):
            path = environ["PATH_INFO"]
            if path.startswith("/socket.io/"):
                return self.app(environ, start_response)
            sorted_mounts = sorted(self.mounts.items(), key=lambda x: len(x[0]), reverse=True)
            for mount_point, mounted_app in sorted_mounts:
                if path.startswith(mount_point):
                    environ["SCRIPT_NAME"] = mount_point
                    environ["PATH_INFO"] = path[len(mount_point):] or "/"
                    return mounted_app(environ, start_response)
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"Not Found"]

        @property
        def debug(self):
            for mount_point, mounted_app in self.mounts.items():
                if hasattr(mounted_app, "debug"):
                    return mounted_app.debug
            return False

        @debug.setter
        def debug(self, value):
            for mount_point, mounted_app in self.mounts.items():
                if hasattr(mounted_app, "debug"):
                    mounted_app.debug = value

    started_without_args = len(sys.argv) == 1

    parser = argparse.ArgumentParser(description="Start Glycon C2 with automatic venv setup and configuration menu.")
    parser.add_argument("--no-ssl", action="store_true", help="Disable HTTPS server")
    parser.add_argument("--gen-ssl", action="store_true", help="Generate new self-signed SSL certificates (cert.pem & key.pem)")
    parser.add_argument("--ssl-cn", type=str, default="localhost", help="Common Name / IP for SSL certificate (default: localhost)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind IP address (default: 0.0.0.0)")
    parser.add_argument("--http-port", type=int, default=5555, help="Port for HTTP server (default: 5555)")
    parser.add_argument("--https-port", type=int, default=443, help="Port for HTTPS server (default: 443)")
    parser.add_argument("--no-menu", action="store_true", help="Skip interactive setup menu and start immediately")
    args = parser.parse_args()

    if started_without_args and not args.no_menu:
        setup_cfg = interactive_setup_menu(
            default_host=args.host,
            default_http_port=args.http_port,
            default_https_port=args.https_port,
        )
        bind_host = setup_cfg["host"]
        http_port = setup_cfg["http_port"]
        https_port = setup_cfg["https_port"]
        use_ssl = setup_cfg["use_ssl"]
        if setup_cfg["base_url"]:
            os.environ["BASE_URL"] = setup_cfg["base_url"]
    else:
        bind_host = args.host
        http_port = args.http_port
        https_port = args.https_port
        use_ssl = not args.no_ssl
        if use_ssl:
            if args.gen_ssl:
                use_ssl = generate_self_signed_cert(common_name=args.ssl_cn)
            elif not (os.path.isfile("cert.pem") and os.path.isfile("key.pem")):
                use_ssl = generate_self_signed_cert(common_name=args.ssl_cn)

    os.environ["GLYCON_HOST"] = bind_host
    os.environ["GLYCON_HTTPS_PORT"] = str(https_port)

    # Import server after interactive prompts so background threads don't interfere with input
    from glycon.server import app, socketio

    app.config["HOST"] = bind_host
    app.config["PORT"] = https_port

    base_url = os.getenv("BASE_URL", "").rstrip("/")

    if base_url:
        prefixed_app = FixedDispatcherMiddleware(app, {
            "/": app,
            base_url: app,
        })
    else:
        prefixed_app = app

    print(f"\n[*] Starting Glycon C2 on {bind_host} (HTTP: {http_port}" + (f", HTTPS: {https_port})" if use_ssl else ")"))

    if use_ssl:
        socketio.start_background_task(
            lambda: socketio.run(
                prefixed_app,
                host=bind_host,
                port=https_port,
                ssl_context=("cert.pem", "key.pem"),
                debug=False,
            )
        )

    socketio.run(prefixed_app, host=bind_host, port=http_port, debug=False)
