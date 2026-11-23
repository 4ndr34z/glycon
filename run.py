import argparse
import datetime
import ipaddress
import os
import subprocess
import sys
from werkzeug.middleware.dispatcher import DispatcherMiddleware


class FixedDispatcherMiddleware(DispatcherMiddleware):
    def __call__(self, environ, start_response):
        path = environ['PATH_INFO']
        # Allow Socket.IO paths to pass through to the main app regardless of BASE_URL
        if path.startswith('/socket.io/'):
            return self.app(environ, start_response)
        # Sort mounts by length descending to prioritize longer prefixes
        sorted_mounts = sorted(self.mounts.items(), key=lambda x: len(x[0]), reverse=True)
        for mount_point, mounted_app in sorted_mounts:
            if path.startswith(mount_point):
                environ['SCRIPT_NAME'] = mount_point
                environ['PATH_INFO'] = path[len(mount_point):] or '/'
                return mounted_app(environ, start_response)
        # If no match, return 404
        start_response('404 Not Found', [('Content-Type', 'text/plain')])
        return [b'Not Found']

    @property
    def debug(self):
        # Return the debug attribute from the first mounted app that has it
        for mount_point, mounted_app in self.mounts.items():
            if hasattr(mounted_app, 'debug'):
                return mounted_app.debug
        return False

    @debug.setter
    def debug(self, value):
        # Set the debug attribute on all mounted apps that have it
        for mount_point, mounted_app in self.mounts.items():
            if hasattr(mounted_app, 'debug'):
                mounted_app.debug = value


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
        # Fallback to openssl CLI if python-cryptography is not installed in the current interpreter
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


def prompt_ssl_setup(cert_path="cert.pem", key_path="key.pem", force_gen=False, started_without_args=False):
    """Prompt user to generate SSL certificates when started without arguments or when certs are missing."""
    certs_exist = os.path.isfile(cert_path) and os.path.isfile(key_path)

    if force_gen:
        return generate_self_signed_cert(cert_path=cert_path, key_path=key_path)

    if not sys.stdin.isatty():
        if not certs_exist:
            print("[*] Missing SSL certificates in non-interactive mode. Auto-generating self-signed certificates...")
            return generate_self_signed_cert(cert_path=cert_path, key_path=key_path)
        return True

    try:
        if started_without_args and certs_exist:
            answer = input(f"[?] SSL certificates ({cert_path}, {key_path}) already exist. Generate new certificates? [y/N]: ").strip().lower()
            if answer in ("y", "yes", "j", "ja"):
                cn = input("[?] Enter Common Name or IP for certificate [default: localhost]: ").strip() or "localhost"
                return generate_self_signed_cert(cert_path=cert_path, key_path=key_path, common_name=cn)
            return True

        if not certs_exist:
            answer = input(f"[?] SSL certificates ({cert_path}, {key_path}) not found. Generate self-signed certificates now? [Y/n]: ").strip().lower()
            if answer in ("", "y", "yes", "j", "ja"):
                cn = input("[?] Enter Common Name or IP for certificate [default: localhost]: ").strip() or "localhost"
                return generate_self_signed_cert(cert_path=cert_path, key_path=key_path, common_name=cn)
            else:
                print("[!] Continuing without HTTPS (--no-ssl) because SSL certificates are missing.")
                return False
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Aborted by user.")
        sys.exit(0)

    return True


if __name__ == "__main__":
    started_without_args = len(sys.argv) == 1

    parser = argparse.ArgumentParser(description="Run Glycon server with options for SSL and HTTP port.")
    parser.add_argument('--no-ssl', action='store_true', help='Disable HTTPS server on port 443')
    parser.add_argument('--gen-ssl', action='store_true', help='Generate new self-signed SSL certificates (cert.pem & key.pem)')
    parser.add_argument('--ssl-cn', type=str, default='localhost', help='Common Name / IP when generating SSL certificate (default: localhost)')
    parser.add_argument('--http-port', type=int, default=5555, help='Port for HTTP server (default: 5555)')
    args = parser.parse_args()

    use_ssl = not args.no_ssl
    if use_ssl:
        if args.gen_ssl:
            use_ssl = generate_self_signed_cert(common_name=args.ssl_cn)
        else:
            use_ssl = prompt_ssl_setup(started_without_args=started_without_args)

    # Import server after interactive prompts so background monitor thread does not interrupt input
    from glycon.server import app, socketio

    base_url = os.getenv('BASE_URL', '').rstrip('/')

    # Prepare the app for mounting
    if base_url:
        prefixed_app = FixedDispatcherMiddleware(app, {
            '/': app,
            base_url: app
        })
    else:
        prefixed_app = app

    if use_ssl:
        # HTTPS Server
        socketio.start_background_task(
            lambda: socketio.run(
                prefixed_app,
                host=app.config['HOST'],
                port=app.config['PORT'],
                ssl_context=('cert.pem', 'key.pem'),
                debug=False
            )
        )

    # HTTP Server
    socketio.run(prefixed_app, host=app.config['HOST'], port=args.http_port, debug=False)
