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
        print(f"[!] Fant ikke {REQUIREMENTS_FILE}.")
        return False

    if not force and not _needs_pip_install(venv_py):
        return True

    print("[*] Oppgraderer pip og installerer pakker fra requirements.txt...")
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
        print("[+] Alle avhengigheter i requirements.txt er installert.")
        return True
    except subprocess.CalledProcessError as err:
        print(f"[!] Feil under installasjon av pakker: {err}")
        return False


def bootstrap_venv():
    """Sørger for at venv eksisterer, installerer requirements og re-eksekverer run.py i venv."""
    os.chdir(PROJECT_DIR)
    venv_py = _get_venv_python()
    first_time_venv = not os.path.isfile(venv_py)

    if first_time_venv:
        print(f"[*] Virtuelt miljø (venv) ble ikke funnet. Oppretter {VENV_DIR} ...")
        builder = venv.EnvBuilder(with_pip=True)
        builder.create(VENV_DIR)
        print("[+] Virtuelt miljø opprettet.")

    if not _in_project_venv():
        install_requirements(venv_py, force=first_time_venv)
        print(f"[*] Aktiverer venv og starter Glycon med {venv_py} ...\n")
        os.environ["VIRTUAL_ENV"] = VENV_DIR
        venv_bin = os.path.dirname(venv_py)
        os.environ["PATH"] = f"{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}"
        os.execv(venv_py, [venv_py, os.path.abspath(__file__)] + sys.argv[1:])
    else:
        install_requirements(venv_py, force=False)


def generate_self_signed_cert(cert_path="cert.pem", key_path="key.pem", common_name="localhost", days=365):
    """Generate a self-signed X.509 SSL certificate and private key."""
    common_name = (common_name or "localhost").strip()
    print(f"[*] Genererer selvsignert SSL-sertifikat for '{common_name}' (gyldig i {days} dager)...")

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

        print(f"[+] SSL-sertifikat lagret til '{cert_path}' og privat nøkkel til '{key_path}'.")
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
            print(f"[+] SSL-sertifikat generert via OpenSSL CLI ('{cert_path}', '{key_path}').")
            return True
        except Exception as err:
            print(f"[!] Kunne ikke generere SSL-sertifikat: {err}")
            return False


def update_admin_credentials(username: str, password: str):
    """Oppdaterer eller oppretter admin-bruker i c2.db."""
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
    print(f"[+] Administrator-konto oppdatert (brukernavn: '{username}').")


def interactive_setup_menu(default_host="0.0.0.0", default_http_port=5555, default_https_port=443):
    """Interaktiv oppstarts- og oppsettmeny for Glycon C2."""
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
            ssl_status = f"Aktivert (Port {config_state['https_port']})" if config_state["use_ssl"] else "Deaktivert (Kun HTTP)"
            cert_status = "Funnet (cert.pem / key.pem)" if certs_exist else "Mangler!"

            print("\n" + "=" * 62)
            print(f"   GLYCON C2 v.{ver_str} — OPPSETT- OG OPPSTARTSMENY")
            print("=" * 62)
            print(f"   Virtuelt miljø : {VENV_DIR} (Aktivt)")
            print(f"   Lytteadresse   : {config_state['host']}")
            print(f"   HTTP-port      : {config_state['http_port']}")
            print(f"   HTTPS / SSL    : {ssl_status} [{cert_status}]")
            print(f"   Base URL       : {config_state['base_url'] or '/ (rot)'}")
            print("-" * 62)
            print("   [1] Hurtigstart med gjeldende innstillinger (Standard)")
            print("   [2] Konfigurer oppsett (Porter, SSL, Sertifikat, Admin-bruker)")
            print("   [3] Re-installer / oppdater pakker fra requirements.txt")
            print("   [4] Avslutt")
            print("=" * 62)

            choice = input("[?] Velg et alternativ [1-4, Enter=1]: ").strip() or "1"

            if choice == "1":
                if config_state["use_ssl"] and not certs_exist:
                    ans = input("[?] SSL-sertifikater mangler. Generere selvsignert sertifikat nå? [J/n]: ").strip().lower()
                    if ans in ("", "j", "ja", "y", "yes"):
                        cn = input("[?] Fyll inn Common Name eller IP [standard: localhost]: ").strip() or "localhost"
                        if not generate_self_signed_cert(cert_path, key_path, common_name=cn):
                            config_state["use_ssl"] = False
                    else:
                        print("[!] Fortsetter uten HTTPS (--no-ssl).")
                        config_state["use_ssl"] = False
                break

            elif choice == "2":
                print("\n--- Nettverk og Porter ---")
                host_in = input(f"[?] Lytteadresse (Bind IP) [{config_state['host']}]: ").strip()
                if host_in:
                    config_state["host"] = host_in

                http_in = input(f"[?] HTTP-port [{config_state['http_port']}]: ").strip()
                if http_in.isdigit():
                    config_state["http_port"] = int(http_in)

                ssl_in = input("[?] Aktivere HTTPS/SSL-server? [J/n]: ").strip().lower()
                config_state["use_ssl"] = ssl_in in ("", "j", "ja", "y", "yes")

                if config_state["use_ssl"]:
                    https_in = input(f"[?] HTTPS-port [{config_state['https_port']}]: ").strip()
                    if https_in.isdigit():
                        config_state["https_port"] = int(https_in)

                    gen_prompt = "[?] Generere nye SSL-sertifikater? [j/N]: " if certs_exist else "[?] SSL-sertifikater mangler. Generere nå? [J/n]: "
                    gen_in = input(gen_prompt).strip().lower()
                    should_gen = gen_in in ("j", "ja", "y", "yes") if certs_exist else gen_in in ("", "j", "ja", "y", "yes")
                    if should_gen:
                        cn = input("[?] Common Name / IP for sertifikatet [standard: localhost]: ").strip() or "localhost"
                        days_in = input("[?] Gyldighet i antall dager [365]: ").strip()
                        days = int(days_in) if days_in.isdigit() else 365
                        generate_self_signed_cert(cert_path, key_path, common_name=cn, days=days)

                base_in = input(f"[?] Valgfri Base URL-prefiks (f.eks. /c2, tom for rot) [{config_state['base_url']}]: ").strip()
                if base_in:
                    config_state["base_url"] = "/" + base_in.strip("/")
                elif base_in == "":
                    pass

                print("\n--- Administrator-konto ---")
                adm_in = input("[?] Vil du endre admin-brukernavn/passord i databasen? [j/N]: ").strip().lower()
                if adm_in in ("j", "ja", "y", "yes"):
                    adm_user = input("[?] Admin-brukernavn [admin]: ").strip() or "admin"
                    adm_pass = getpass.getpass("[?] Nytt admin-passord: ").strip()
                    if adm_pass:
                        update_admin_credentials(adm_user, adm_pass)
                    else:
                        print("[!] Passord var tomt – beholder eksisterende passord.")

                start_now = input("\n[?] Starte Glycon-serveren med disse innstillingene nå? [J/n]: ").strip().lower()
                if start_now in ("", "j", "ja", "y", "yes"):
                    break

            elif choice == "3":
                install_requirements(_get_venv_python(), force=True)

            elif choice in ("4", "q", "exit"):
                print("[*] Avslutter.")
                sys.exit(0)
            else:
                print("[!] Ugyldig valg, prøv igjen.")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Avbrutt av bruker.")
        sys.exit(0)

    return config_state


if __name__ == "__main__":
    # 1. Sørg for at venv er opprettet, aktivert og requirements installert
    bootstrap_venv()

    # 2. Nå kjører vi garantert inne i venv – importer Werkzeug og argumenter
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

    parser = argparse.ArgumentParser(description="Start Glycon C2 med automatisk venv-oppsett og konfigurasjonsmeny.")
    parser.add_argument("--no-ssl", action="store_true", help="Deaktiver HTTPS-server")
    parser.add_argument("--gen-ssl", action="store_true", help="Generer nye selvsignerte SSL-sertifikater (cert.pem & key.pem)")
    parser.add_argument("--ssl-cn", type=str, default="localhost", help="Common Name / IP for SSL-sertifikat (standard: localhost)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Lytteadresse / Bind IP (standard: 0.0.0.0)")
    parser.add_argument("--http-port", type=int, default=5555, help="Port for HTTP-server (standard: 5555)")
    parser.add_argument("--https-port", type=int, default=443, help="Port for HTTPS-server (standard: 443)")
    parser.add_argument("--no-menu", action="store_true", help="Hopp over interaktiv oppsettmeny og start direkte")
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

    # Importer server etter at menyen er ferdig slik at bakgrunnstråder ikke forstyrrer input
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

    print(f"\n[*] Starter Glycon C2 på {bind_host} (HTTP: {http_port}" + (f", HTTPS: {https_port})" if use_ssl else ")"))

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
