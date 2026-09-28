"""
Application runner supporting standard HTTP and local HTTPS modes.

Coursework / Viva Notice (BUG-09):
  The built-in Werkzeug development server below is used intentionally for
  coursework evaluation, academic grading, and local demonstration.
  For production deployment, use a hardened WSGI application server (such as Gunicorn
  or uWSGI) behind a reverse proxy (such as NGINX or Caddy) with TLS termination.

Production WSGI Reference (Linux/POSIX):
  # gunicorn -w 4 -b 127.0.0.1:5000 "app:create_app()" --certfile=certs/cert.pem --keyfile=certs/key.pem

Usage:
  python run.py                 # Standard HTTP on port 5000
  python run.py --https         # Local HTTPS using self-signed cert on port 5000
  python run.py --port 8443     # Custom port
"""
import argparse

from app import create_app
from certs.generate_certs import generate_local_certs
from scripts.init_db import initialize_database


def main():
    parser = argparse.ArgumentParser(description="ArogyaRaksha")
    parser.add_argument("--https", action="store_true", help="Run with local HTTPS enabled")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Listening port (default: 5000)")
    parser.add_argument("--init-db", action="store_true", help="Auto-initialize database tables and seed users")
    args = parser.parse_args()

    app = create_app()

    # Explicit database initialization only when requested via flag
    if args.init_db:
        with app.app_context():
            initialize_database(app)

    ssl_context = None
    protocol = "http"

    if args.https:
        cert_path, key_path = generate_local_certs()
        ssl_context = (cert_path, key_path)
        protocol = "https"
        print(f"[*] HTTPS enabled using certificates: {cert_path}, {key_path}")

    url = f"{protocol}://{args.host}:{args.port}"
    print("=" * 60)
    print(" ArogyaRaksha")
    print(f" Listening at: {url}")
    print(" Default demo accounts:")
    print("   Doctor: doctor_alice  / DocSecurePass#2026")
    print("   Nurse:  nurse_bob     / NursePass#2026")
    print("   Admin:  admin_charlie / AdminMaster#2026")
    print("=" * 60)

    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        ssl_context=ssl_context
    )

if __name__ == "__main__":
    main()
