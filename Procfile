web: gunicorn -w 4 -b 0.0.0.0:${PORT:-5000} "app:create_app()"
worker: FLASK_APP="app:create_app()" flask process-outbox --loop
release: FLASK_APP="app:create_app()" flask init-db
