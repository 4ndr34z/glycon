#!/usr/bin/env python3
import argparse
import datetime
import getpass
import hashlib
import ipaddress
import os
import shutil
import sqlite3
import subprocess
import sys
import venv

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(PROJECT_DIR, "venv")
REQUIREMENTS_FILE = os.path.join(PROJECT_DIR, "requirements.txt")
REQ_HASH_FILE = os.path.join(VENV_DIR, ".requirements_sha256")
DNS_CREDS_DIR = os.path.join(PROJECT_DIR, ".dns_credentials")
LETSENCRYPT_DIR = os.path.join(PROJECT_DIR, ".letsencrypt")

# Supported DNS providers for Certbot DNS-01 validation
DNS_PROVIDERS = {
    "1": {
        "id": "domeneshop",
        "name": "Domeneshop (certbot-dns-domeneshop)",
        "pip_pkg": "certbot-dns-domeneshop",
        "plugin": "dns-domeneshop",
        "prop_prefix": "dns_domeneshop",
        "fields": [
            ("client_token", "Domeneshop API Client Token", False),
            ("client_secret", "Domeneshop API Client Secret", True),
        ],
    },
    "2": {
        "id": "cloudflare",
        "name": "Cloudflare (certbot-dns-cloudflare)",
        "pip_pkg": "certbot-dns-cloudflare",
        "plugin": "dns-cloudflare",
        "prop_prefix": "dns_cloudflare",
        "fields": [
            ("api_token", "Cloudflare API Token (Zone:DNS:Edit)", True),
        ],
    },
    "3": {
        "id": "digitalocean",
        "name": "DigitalOcean (certbot-dns-digitalocean)",
        "pip_pkg": "certbot-dns-digitalocean",
        "plugin": "dns-digitalocean",
        "prop_prefix": "dns_digitalocean",
        "fields": [
            ("token", "DigitalOcean Personal Access Token", True),
        ],
    },
    "4": {
        "id": "route53",
        "name": "AWS Route53 (certbot-dns-route53)",
        "pip_pkg": "certbot-dns-route53",
        "plugin": "dns-route53",
        "prop_prefix": "aws",
        "is_env": True,
        "fields": [
            ("AWS_ACCESS_KEY_ID", "AWS Access Key ID", False),
            ("AWS_SECRET_ACCESS_KEY", "AWS Secret Access Key", True),
        ],
    },
    "5": {
        "id": "hetzner",
        "name": "Hetzner DNS (certbot-dns-hetzner)",
        "pip_pkg": "certbot-dns-hetzner",
        "plugin": "dns-hetzner",
        "prop_prefix": "dns_hetzner",
        "fields": [
            ("api_token", "Hetzner DNS API Token", True),
        ],
    },
    "6": {
        "id": "linode",
        "name": "Linode / Akamai (certbot-dns-linode)",
        "pip_pkg": "certbot-dns-linode",
        "plugin": "dns-linode",
        "prop_prefix": "dns_linode",
        "fields": [
            ("key", "Linode Personal Access Token", True),
            ("version", "Linode API Version (default: 4)", False),
        ],
    },
    "7": {
        "id": "ovh",
        "name": "OVH (certbot-dns-ovh)",
        "pip_pkg": "certbot-dns-ovh",
        "plugin": "dns-ovh",
        "prop_prefix": "dns_ovh",
        "fields": [
            ("endpoint", "OVH Endpoint (e.g. ovh-eu)", False),
            ("application_key", "OVH Application Key", False),
            ("application_secret", "OVH Application Secret", True),
            ("consumer_key", "OVH Consumer Key", True),
        ],
    },
    "8": {
        "id": "gandi",
        "name": "Gandi LiveDNS (certbot-plugin-gandi)",
        "pip_pkg": "certbot-plugin-gandi",
        "plugin": "dns-gandi",
        "prop_prefix": "dns_gandi",
        "fields": [
            ("api_key", "Gandi LiveDNS Personal Access Token / API Key", True),
        ],
    },
    "9": {
        "id": "namecheap",
        "name": "Namecheap (certbot-dns-namecheap)",
        "pip_pkg": "certbot-dns-namecheap",
        "plugin": "dns-namecheap",
        "prop_prefix": "dns_namecheap",
        "fields": [
            ("username", "Namecheap Username", False),
            ("api_key", "Namecheap API Key", True),
        ],
    },
    "10": {
        "id": "porkbun",
        "name": "Porkbun (certbot_dns_porkbun)",
        "pip_pkg": "certbot_dns_porkbun",
        "plugin": "dns-porkbun",
        "prop_prefix": "dns_porkbun",
        "fields": [
            ("key", "Porkbun API Key", False),
            ("secret", "Porkbun API Secret Key", True),
        ],
    },
}


def _get_venv_python() -> str:
    if os.name == "nt":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def _get_venv_bin(binary_name: str) -> str:
    if os.name == "nt":
        return os.path.join(VENV_DIR, "Scripts", f"{binary_name}.exe")
    return os.path.join(VENV_DIR, "bin", binary_name)


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


def get_certificate_summary(cert_path="cert.pem", key_path="key.pem") -> str:
    """Inspect cert.pem and return a concise status string (Subject, Issuer, Expiry)."""
    if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        return "Missing (cert.pem / key.pem not found)"
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else "Unknown"
        issuer = issuer_attrs[0].value if issuer_attrs else "Self-Signed"
        exp = cert.not_valid_after_utc.strftime("%Y-%m-%d") if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.strftime("%Y-%m-%d")
        return f"CN={cn} | Issuer={issuer} | Exp={exp}"
    except Exception:
        return "Found (cert.pem / key.pem)"


def ensure_certbot_installed(extra_package: str = None) -> str:
    """Ensures certbot (and optional DNS plugin) is installed inside the project venv."""
    venv_py = _get_venv_python()
    packages = ["certbot"]
    if extra_package:
        packages.append(extra_package)

    print(f"[*] Ensuring {', '.join(packages)} is installed in venv...")
    try:
        subprocess.run(
            [venv_py, "-m", "pip", "install", "--upgrade"] + packages,
            check=True,
        )
    except subprocess.CalledProcessError as err:
        print(f"[!] Failed to install Certbot / DNS plugin via pip: {err}")
        return ""

    certbot_bin = _get_venv_bin("certbot")
    if os.path.isfile(certbot_bin):
        return certbot_bin
    return shutil.which("certbot") or ""


def configure_dns_provider_credentials(provider_cfg: dict) -> str:
    """Prompts for or reuses DNS API credentials and writes a 0600 INI file in .dns_credentials/."""
    os.makedirs(DNS_CREDS_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(DNS_CREDS_DIR, 0o700)
    except OSError:
        pass

    cred_file = os.path.join(DNS_CREDS_DIR, f"{provider_cfg['id']}.ini")

    if os.path.isfile(cred_file):
        reuse = input(f"[?] Existing credentials found at '{cred_file}'. Reuse existing credentials? [Y/n]: ").strip().lower()
        if reuse in ("", "y", "yes", "j", "ja"):
            return cred_file

    print(f"\n--- Configure {provider_cfg['name']} Credentials ---")
    lines = []
    for field_key, label, is_secret in provider_cfg["fields"]:
        while True:
            if is_secret:
                val = getpass.getpass(f"[?] {label}: ").strip()
            else:
                val = input(f"[?] {label}: ").strip()
            if not val and field_key == "version":
                val = "4"
            if val:
                break
            print("[!] This field cannot be empty.")

        if provider_cfg.get("is_env"):
            lines.append(f"{field_key}={val}")
        else:
            lines.append(f"{provider_cfg['prop_prefix']}_{field_key} = {val}")

    with open(cred_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    try:
        os.chmod(cred_file, 0o600)
    except OSError:
        pass

    print(f"[+] Credentials securely saved to '{cred_file}' (permissions 0600, gitignored).")
    return cred_file


def _copy_issued_letsencrypt_certs(domain: str, cert_out="cert.pem", key_out="key.pem") -> bool:
    """Locates the issued fullchain.pem and privkey.pem in .letsencrypt/live/ and copies them to cert.pem & key.pem."""
    primary_domain = domain.split(",")[0].strip().lstrip("*.")
    live_root = os.path.join(LETSENCRYPT_DIR, "config", "live")
    if not os.path.isdir(live_root):
        return False

    candidate_dir = os.path.join(live_root, primary_domain)
    if not os.path.isdir(candidate_dir):
        # Fallback: find matching directory
        dirs = [
            os.path.join(live_root, d)
            for d in os.listdir(live_root)
            if os.path.isdir(os.path.join(live_root, d)) and d.startswith(primary_domain)
        ]
        if not dirs:
            dirs = [
                os.path.join(live_root, d)
                for d in os.listdir(live_root)
                if os.path.isdir(os.path.join(live_root, d))
            ]
        if not dirs:
            return False
        candidate_dir = sorted(dirs, key=lambda p: os.path.getmtime(p), reverse=True)[0]

    fullchain = os.path.join(candidate_dir, "fullchain.pem")
    privkey = os.path.join(candidate_dir, "privkey.pem")

    if not (os.path.isfile(fullchain) and os.path.isfile(privkey)):
        return False

    shutil.copyfile(fullchain, cert_out)
    shutil.copyfile(privkey, key_out)
    try:
        os.chmod(key_out, 0o600)
    except OSError:
        pass

    print(f"[+] Let's Encrypt certificate deployed to '{cert_out}' and private key to '{key_out}'.")
    return True


def request_letsencrypt_menu():
    """Interactive submenu for requesting Let's Encrypt certificates via DNS API, HTTP-01, or importing files."""
    while True:
        print("\n" + "-" * 62)
        print("   LET'S ENCRYPT & SSL CERTIFICATE MANAGER")
        print("-" * 62)
        print(f"   Active Certificate : {get_certificate_summary()}")
        print("-" * 62)
        print("   [1] Request Let's Encrypt Certificate via DNS API (DNS-01 / Wildcard support)")
        print("   [2] Request Let's Encrypt Certificate via Web / Standalone HTTP-01 (Port 80)")
        print("   [3] Request Let's Encrypt Certificate via Local Webroot Directory (HTTP-01)")
        print("   [4] Import Existing Certificate & Key from File Path (PEM)")
        print("   [5] Generate Self-Signed Certificate (cert.pem & key.pem)")
        print("   [6] Manage / Pre-configure DNS Provider API Credentials")
        print("   [0] Back to Main Setup Menu")
        print("-" * 62)

        sub = input("[?] Select an option [0-6]: ").strip()

        if sub == "0" or not sub:
            break

        elif sub == "1":
            print("\n--- Select DNS API Provider ---")
            for key, p in DNS_PROVIDERS.items():
                cred_path = os.path.join(DNS_CREDS_DIR, f"{p['id']}.ini")
                status_tag = " [Configured]" if os.path.isfile(cred_path) else ""
                print(f"   [{key:>2}] {p['name']}{status_tag}")
            print("   [ 0] Cancel")

            p_choice = input("[?] Choose DNS provider [1-10]: ").strip()
            if p_choice not in DNS_PROVIDERS:
                continue

            provider = DNS_PROVIDERS[p_choice]
            cred_file = configure_dns_provider_credentials(provider)
            if not cred_file:
                continue

            if provider["id"] == "domeneshop":
                try:
                    from domeneshop.client import Client as DomeneshopClient
                    ds_creds = {}
                    with open(cred_file, "r", encoding="utf-8") as f:
                        for line in f:
                            if "=" in line:
                                k, v = line.split("=", 1)
                                ds_creds[k.strip()] = v.strip()
                    ds_client = DomeneshopClient(
                        token=ds_creds.get("dns_domeneshop_client_token"),
                        secret=ds_creds.get("dns_domeneshop_client_secret"),
                    )
                    ds_domains = [d.get("domain") for d in ds_client.get_domains() if d.get("domain")]
                    if ds_domains:
                        print(f"[*] Domeneshop account verified. Accessible base domains ({len(ds_domains)}): {', '.join(ds_domains)}")
                    else:
                        print("[!] Warning: This Domeneshop API token authenticated, but has 0 accessible domains.")
                except ImportError:
                    pass
                except Exception as err:
                    print(f"[!] Warning: Could not list Domeneshop domains with current API token: {err}")

            domains_raw = input("[?] Domain(s) (comma-separated, e.g. c2.example.com,*.example.com): ").strip()
            if not domains_raw:
                print("[!] Domain is required.")
                continue
            domains = [d.strip() for d in domains_raw.split(",") if d.strip()]

            email = input("[?] Email for Let's Encrypt notifications (leave empty to register without email): ").strip()
            prop_sec = input("[?] DNS propagation wait time in seconds [default: 60]: ").strip()
            propagation_seconds = int(prop_sec) if prop_sec.isdigit() else 60
            staging_in = input("[?] Use Let's Encrypt Staging/Test environment first? [y/N]: ").strip().lower()
            use_staging = staging_in in ("y", "yes", "j", "ja")

            certbot_bin = ensure_certbot_installed(provider["pip_pkg"])
            if not certbot_bin:
                continue

            config_dir = os.path.join(LETSENCRYPT_DIR, "config")
            work_dir = os.path.join(LETSENCRYPT_DIR, "work")
            logs_dir = os.path.join(LETSENCRYPT_DIR, "logs")
            for d in (config_dir, work_dir, logs_dir):
                os.makedirs(d, mode=0o700, exist_ok=True)

            cmd = [
                certbot_bin, "certonly",
                "--non-interactive",
                "--agree-tos",
                "--config-dir", config_dir,
                "--work-dir", work_dir,
                "--logs-dir", logs_dir,
                "--authenticator", provider["plugin"],
                f"--{provider['plugin']}-propagation-seconds", str(propagation_seconds),
            ]

            env = os.environ.copy()
            if provider.get("is_env"):
                # Load AWS env vars from cred_file
                with open(cred_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            env[k.strip()] = v.strip()
            else:
                cmd.extend([f"--{provider['plugin']}-credentials", cred_file])

            if email:
                cmd.extend(["--email", email])
            else:
                cmd.append("--register-unsafely-without-email")

            if use_staging:
                cmd.append("--staging")

            for d in domains:
                cmd.extend(["-d", d])

            print(f"\n[*] Running Certbot DNS-01 challenge via {provider['name']}...")
            try:
                subprocess.run(cmd, env=env, check=True)
                _copy_issued_letsencrypt_certs(domains[0])
            except subprocess.CalledProcessError as err:
                print(f"[!] Certbot DNS-01 validation failed (exit code {err.returncode}). Check logs in {logs_dir}.")

        elif sub in ("2", "3"):
            mode = "standalone" if sub == "2" else "webroot"
            domains_raw = input("[?] Domain(s) (comma-separated, e.g. c2.example.com): ").strip()
            if not domains_raw:
                print("[!] Domain is required.")
                continue
            domains = [d.strip() for d in domains_raw.split(",") if d.strip()]

            webroot_path = ""
            if mode == "webroot":
                default_wr = os.path.join(PROJECT_DIR, "uploads", "vaporlink_www")
                os.makedirs(default_wr, exist_ok=True)
                webroot_path = input(f"[?] Local webroot path [{default_wr}]: ").strip() or default_wr
                if not os.path.isdir(webroot_path):
                    os.makedirs(webroot_path, exist_ok=True)
            else:
                http_01_port = input("[?] HTTP-01 listen port for standalone server [default: 80]: ").strip() or "80"

            email = input("[?] Email for Let's Encrypt notifications (leave empty to skip): ").strip()
            staging_in = input("[?] Use Let's Encrypt Staging/Test environment? [y/N]: ").strip().lower()
            use_staging = staging_in in ("y", "yes", "j", "ja")

            certbot_bin = ensure_certbot_installed()
            if not certbot_bin:
                continue

            config_dir = os.path.join(LETSENCRYPT_DIR, "config")
            work_dir = os.path.join(LETSENCRYPT_DIR, "work")
            logs_dir = os.path.join(LETSENCRYPT_DIR, "logs")
            for d in (config_dir, work_dir, logs_dir):
                os.makedirs(d, mode=0o700, exist_ok=True)

            cmd = [
                certbot_bin, "certonly",
                "--non-interactive",
                "--agree-tos",
                "--config-dir", config_dir,
                "--work-dir", work_dir,
                "--logs-dir", logs_dir,
            ]

            if mode == "standalone":
                cmd.extend(["--standalone", "--http-01-port", http_01_port])
            else:
                cmd.extend(["--webroot", "-w", webroot_path])

            if email:
                cmd.extend(["--email", email])
            else:
                cmd.append("--register-unsafely-without-email")

            if use_staging:
                cmd.append("--staging")

            for d in domains:
                cmd.extend(["-d", d])

            print(f"\n[*] Requesting Let's Encrypt certificate via HTTP-01 ({mode})...")
            try:
                subprocess.run(cmd, check=True)
                _copy_issued_letsencrypt_certs(domains[0])
            except subprocess.CalledProcessError as err:
                print(f"[!] Certbot HTTP-01 validation failed (exit code {err.returncode}). Check logs in {logs_dir}.")

        elif sub == "4":
            print("\n--- Import Certificate & Private Key from Files ---")
            src_cert = input("[?] Path to certificate / fullchain PEM file: ").strip()
            src_key = input("[?] Path to private key PEM file: ").strip()

            if not (os.path.isfile(src_cert) and os.path.isfile(src_key)):
                print("[!] One or both file paths do not exist.")
                continue

            try:
                shutil.copyfile(src_cert, "cert.pem")
                shutil.copyfile(src_key, "key.pem")
                os.chmod("key.pem", 0o600)
                print(f"[+] Imported certificate ({get_certificate_summary()}) to cert.pem & key.pem.")
            except Exception as err:
                print(f"[!] Failed to import certificate files: {err}")

        elif sub == "5":
            cn = input("[?] Common Name / IP for self-signed certificate [default: localhost]: ").strip() or "localhost"
            days_in = input("[?] Validity in days [365]: ").strip()
            days = int(days_in) if days_in.isdigit() else 365
            generate_self_signed_cert("cert.pem", "key.pem", common_name=cn, days=days)

        elif sub == "6":
            print("\n--- Pre-configure DNS Provider API Credentials ---")
            for key, p in DNS_PROVIDERS.items():
                cred_path = os.path.join(DNS_CREDS_DIR, f"{p['id']}.ini")
                status_tag = " [Configured]" if os.path.isfile(cred_path) else ""
                print(f"   [{key:>2}] {p['name']}{status_tag}")
            p_choice = input("[?] Select provider to configure [1-10]: ").strip()
            if p_choice in DNS_PROVIDERS:
                configure_dns_provider_credentials(DNS_PROVIDERS[p_choice])


def update_admin_credentials(username: str, password: str):
    """Updates or creates the admin user in c2.db."""
    from werkzeug.security import generate_password_hash
    from glycon.config import CONFIG

    CONFIG.init_db()
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


def _parse_base_url_input(raw_input: str, use_ssl: bool = True) -> tuple[str, str]:
    """
    Parses user input for Base URL in setup.
    Supports:
      - Path prefixes: '/c2', 'c2' -> base_url='/c2', server_url=''
      - Full URLs / domains: 'https://c2.example.com', 'https://c2.example.com/c2', 'c2.example.com/c2'
        -> extracts path prefix as base_url (e.g. '' or '/c2') and full callback URL as server_url.
      - '/', 'root', 'none', '-' -> resets base_url='', server_url=''
    """
    from urllib.parse import urlparse

    val = (raw_input or "").strip()
    if not val or val.lower() in ("/", "root", "none", "-"):
        return "", ""

    first_segment = val.split("/")[0]
    is_full_url_or_host = "://" in val or "." in first_segment or ":" in first_segment

    if is_full_url_or_host:
        scheme = "https" if use_ssl else "http"
        full_candidate = val if "://" in val else f"{scheme}://{val}"
        parsed = urlparse(full_candidate)
        clean_path = "/" + parsed.path.strip("/") if parsed.path.strip("/") else ""
        server_url = f"{parsed.scheme}://{parsed.netloc}{clean_path}"
        return clean_path, server_url

    clean_path = "/" + val.strip("/")
    return clean_path, ""


def load_saved_setup_config(default_host="0.0.0.0", default_http_port=5555, default_https_port=443) -> dict:
    """Loads persisted setup configuration from c2.db settings table."""
    from glycon.config import CONFIG

    CONFIG.init_db()
    state = {
        "host": default_host,
        "http_port": default_http_port,
        "https_port": default_https_port,
        "use_ssl": True,
        "base_url": os.getenv("BASE_URL", "").rstrip("/"),
        "server_url": "",
    }
    try:
        conn = sqlite3.connect(CONFIG.database)
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings WHERE key LIKE 'setup_%'")
        rows = dict(c.fetchall())
        conn.close()

        if rows.get("setup_host"):
            state["host"] = rows["setup_host"]
        if rows.get("setup_http_port", "").isdigit():
            state["http_port"] = int(rows["setup_http_port"])
        if rows.get("setup_https_port", "").isdigit():
            state["https_port"] = int(rows["setup_https_port"])
        if "setup_use_ssl" in rows:
            state["use_ssl"] = rows["setup_use_ssl"] == "1"
        if not os.getenv("BASE_URL") and "setup_base_url" in rows:
            state["base_url"] = (rows["setup_base_url"] or "").rstrip("/")
        if "setup_server_url" in rows:
            state["server_url"] = (rows["setup_server_url"] or "").rstrip("/")
    except Exception:
        pass
    return state


def save_setup_config(config_state: dict):
    """Persists setup configuration to c2.db settings and syncs agent_configurations server_url."""
    from urllib.parse import urlparse
    from glycon.config import CONFIG

    CONFIG.init_db()
    conn = sqlite3.connect(CONFIG.database)
    c = conn.cursor()

    pairs = {
        "setup_host": str(config_state.get("host", "0.0.0.0")),
        "setup_http_port": str(config_state.get("http_port", 5555)),
        "setup_https_port": str(config_state.get("https_port", 443)),
        "setup_use_ssl": "1" if config_state.get("use_ssl", True) else "0",
        "setup_base_url": config_state.get("base_url", ""),
        "setup_server_url": config_state.get("server_url", ""),
    }
    for k, v in pairs.items():
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))

    base_url = (config_state.get("base_url") or "").rstrip("/")
    server_url = (config_state.get("server_url") or "").rstrip("/")

    # Sync agent_configurations server_url with configured Base URL / Server URL
    c.execute("SELECT id, server_url FROM agent_configurations ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    if row:
        cfg_id, existing_url = row
        if server_url:
            new_url = server_url
        elif existing_url:
            parsed = urlparse(existing_url if "://" in existing_url else f"https://{existing_url}")
            new_url = f"{parsed.scheme}://{parsed.netloc}{base_url}"
        else:
            new_url = ""
        if new_url and new_url != existing_url:
            c.execute("UPDATE agent_configurations SET server_url = ? WHERE id = ?", (new_url, cfg_id))
    elif server_url:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            """INSERT INTO agent_configurations
               (checkin_interval, server_url, take_screenshots, screenshot_frequency,
                take_webcam, webcam_frequency, killdate_enabled, killdate,
                trusted_certificate, aes_key, aes_iv, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                10,
                server_url,
                1,
                10,
                0,
                10,
                0,
                "",
                0,
                CONFIG.aes_key.decode("latin-1"),
                CONFIG.aes_iv.decode("latin-1"),
                now_str,
            ),
        )

    conn.commit()
    conn.close()


def interactive_setup_menu(default_host="0.0.0.0", default_http_port=5555, default_https_port=443):
    """Interactive setup and startup menu for Glycon C2."""
    cert_path, key_path = "cert.pem", "key.pem"
    certs_exist = os.path.isfile(cert_path) and os.path.isfile(key_path)

    config_state = load_saved_setup_config(
        default_host=default_host,
        default_http_port=default_http_port,
        default_https_port=default_https_port,
    )

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
            cert_summary = get_certificate_summary(cert_path, key_path)
            if config_state.get("server_url") and config_state.get("base_url"):
                base_display = f"{config_state['base_url']} (Server URL: {config_state['server_url']})"
            elif config_state.get("server_url"):
                base_display = f"/ (Server URL: {config_state['server_url']})"
            else:
                base_display = config_state["base_url"] or "/ (root)"

            print("\n" + "=" * 68)
            print(f"   GLYCON C2 v.{ver_str} — SETUP & STARTUP MENU")
            print("=" * 68)
            print(f"   Virtual Env    : {VENV_DIR} (Active)")
            print(f"   Bind Address   : {config_state['host']}")
            print(f"   HTTP Port      : {config_state['http_port']}")
            print(f"   HTTPS / SSL    : {ssl_status}")
            print(f"   Certificate    : {cert_summary}")
            print(f"   Base URL       : {base_display}")
            print("-" * 68)
            print("   [1] Quick Start with current settings (Default)")
            print("   [2] Configure Network, Ports & Admin Account")
            print("   [3] Let's Encrypt & SSL Certificate Setup (DNS API / Web / File)")
            print("   [4] Re-install / update packages from requirements.txt")
            print("   [5] Exit")
            print("=" * 68)

            choice = input("[?] Select an option [1-5, Enter=1]: ").strip() or "1"

            if choice == "1":
                if config_state["use_ssl"] and not certs_exist:
                    print("\n[!] SSL is enabled, but cert.pem / key.pem are missing.")
                    print("    [1] Generate Self-Signed Certificate now")
                    print("    [2] Open Let's Encrypt / Certificate Manager")
                    print("    [3] Continue without HTTPS (--no-ssl)")
                    sub_ans = input("[?] Choose action [1-3, Enter=1]: ").strip() or "1"
                    if sub_ans == "1":
                        cn = input("[?] Enter Common Name or IP [default: localhost]: ").strip() or "localhost"
                        if not generate_self_signed_cert(cert_path, key_path, common_name=cn):
                            config_state["use_ssl"] = False
                    elif sub_ans == "2":
                        request_letsencrypt_menu()
                        continue
                    else:
                        print("[!] Continuing without HTTPS (--no-ssl).")
                        config_state["use_ssl"] = False
                save_setup_config(config_state)
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

                current_base_hint = config_state.get("server_url") or config_state.get("base_url") or "/"
                base_in = input(
                    f"[?] Base URL prefix or full C2 URL (e.g. /c2 or https://c2.domain.com/c2, '/' for root) [{current_base_hint}]: "
                ).strip()
                if base_in:
                    parsed_path, parsed_srv_url = _parse_base_url_input(base_in, use_ssl=config_state["use_ssl"])
                    config_state["base_url"] = parsed_path
                    config_state["server_url"] = parsed_srv_url

                save_setup_config(config_state)
                print("[+] Network & Base URL configuration saved.")

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
                request_letsencrypt_menu()

            elif choice == "4":
                install_requirements(_get_venv_python(), force=True)

            elif choice in ("5", "q", "exit"):
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
        AGENT_CANONICAL_SUFFIXES = (
            "/a/p",
            "/a/d",
            "/api/checkin",
            "/api/task_result",
            "/api/shellcode_output",
            "/api/killdate_reached",
            "/api/agent_terminated",
            "/api/verify_termination",
            "/api/vaporlink/stage",
        )

        def __call__(self, environ, start_response):
            path = environ.get("PATH_INFO", "")
            while "//" in path:
                path = path.replace("//", "/")
            if path.startswith("/socket.io/") or "/socket.io/" in path:
                environ["PATH_INFO"] = path[path.index("/socket.io/"):]
                return self.app(environ, start_response)
            for suffix in self.AGENT_CANONICAL_SUFFIXES:
                if path == suffix or path.endswith(suffix):
                    environ["PATH_INFO"] = suffix
                    return self.app(environ, start_response)
            for marker in ("/api/download_shellcode/", "/api/download_runner/"):
                if marker in path:
                    environ["PATH_INFO"] = path[path.index(marker):]
                    return self.app(environ, start_response)
            environ["PATH_INFO"] = path
            sorted_mounts = sorted(self.mounts.items(), key=lambda x: len(x[0]), reverse=True)
            for mount_point, mounted_app in sorted_mounts:
                if path == mount_point or path.startswith(mount_point + "/"):
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
    parser.add_argument("--base-url", type=str, default=None, help="Base URL prefix or full C2 URL (e.g. /c2)")
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
        os.environ["BASE_URL"] = setup_cfg.get("base_url", "")
        configured_server_url = setup_cfg.get("server_url", "")
    else:
        saved_cfg = load_saved_setup_config(
            default_host=args.host,
            default_http_port=args.http_port,
            default_https_port=args.https_port,
        )
        bind_host = args.host if "--host" in sys.argv else saved_cfg["host"]
        http_port = args.http_port if "--http-port" in sys.argv else saved_cfg["http_port"]
        https_port = args.https_port if "--https-port" in sys.argv else saved_cfg["https_port"]
        use_ssl = False if args.no_ssl else saved_cfg["use_ssl"]
        if args.base_url is not None:
            parsed_path, parsed_srv_url = _parse_base_url_input(args.base_url, use_ssl=use_ssl)
            os.environ["BASE_URL"] = parsed_path
            configured_server_url = parsed_srv_url
            saved_cfg["base_url"] = parsed_path
            saved_cfg["server_url"] = parsed_srv_url
            save_setup_config(saved_cfg)
        else:
            os.environ["BASE_URL"] = os.getenv("BASE_URL") or saved_cfg.get("base_url", "")
            configured_server_url = saved_cfg.get("server_url", "")

        if use_ssl:
            if args.gen_ssl:
                use_ssl = generate_self_signed_cert(common_name=args.ssl_cn)
            elif not (os.path.isfile("cert.pem") and os.path.isfile("key.pem")):
                use_ssl = generate_self_signed_cert(common_name=args.ssl_cn)

    os.environ["GLYCON_HOST"] = bind_host
    os.environ["GLYCON_HTTPS_PORT"] = str(https_port)

    # Import server after interactive prompts so background threads don't interfere with input
    from glycon.server import app, socketio

    if configured_server_url:
        try:
            from glycon.vaporlink import VAPORLINK_MANAGER
            VAPORLINK_MANAGER.sync_fqdn_from_url(configured_server_url)
        except Exception:
            pass

    app.config["HOST"] = bind_host
    app.config["PORT"] = https_port
    base_url = os.getenv("BASE_URL", "").rstrip("/")
    app.config["BASE_URL"] = base_url

    if base_url:
        prefixed_app = FixedDispatcherMiddleware(app, {
            base_url: app,
        })
    else:
        prefixed_app = app

    base_msg = f", Base URL: {base_url}" if base_url else ""
    print(f"\n[*] Starting Glycon C2 on {bind_host} (HTTP: {http_port}" + (f", HTTPS: {https_port}" if use_ssl else "") + f"{base_msg})")

    if use_ssl:
        socketio.start_background_task(
            lambda: socketio.run(
                prefixed_app,
                host=bind_host,
                port=https_port,
                certfile="cert.pem",
                keyfile="key.pem",
                debug=False,
            )
        )

    socketio.run(prefixed_app, host=bind_host, port=http_port, debug=False)
