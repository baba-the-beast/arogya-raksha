"""
Local TLS certificate generator using standard python 'cryptography' library.
Generates self-signed RSA-2048 or ECDSA certificate valid for localhost / 127.0.0.1.
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_local_certs(cert_dir="certs", cert_name="cert.pem", key_name="key.pem"):
    """Generates a self-signed X.509 certificate for local HTTPS testing."""
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = os.path.join(cert_dir, cert_name)
    key_path = os.path.join(cert_dir, key_name)

    if os.path.exists(cert_path) and os.path.exists(key_path):
        print(f"[*] TLS certificates already exist at {cert_path} and {key_path}")
        return cert_path, key_path

    print("[*] Generating local 2048-bit RSA TLS private key and certificate...")

    # Generate RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Subject & Issuer for self-signed cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KLE Technological University - CNS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] TLS certificate saved: {cert_path}")
    print(f"[+] TLS private key saved:  {key_path}")
    return cert_path, key_path

if __name__ == "__main__":
    generate_local_certs()
