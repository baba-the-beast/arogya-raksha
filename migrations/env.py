import os
import sys
from logging.config import fileConfig
from alembic import context

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from app.config import Config, TestConfig
from app.extensions import db
# Ensure all models are imported so Alembic discovers their tables
from app.models.tenant import Tenant  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.patient import Patient  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.outbox import OutboxEvent  # noqa: F401

# Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Create Flask application to retrieve database URI and metadata
if os.getenv("TESTING") == "true" or os.getenv("PYTEST_CURRENT_TEST"):
    flask_app = create_app(TestConfig)
else:
    class MigrationConfig(Config):
        SECRET_KEY = os.getenv("SECRET_KEY") or "alembic-migration-ephemeral-secret-key-32b!!"
        MASTER_ENCRYPTION_KEY = Config.MASTER_ENCRYPTION_KEY or (b"\x01" * 32)
    flask_app = create_app(MigrationConfig)

target_metadata = db.metadata

# Ensure alembic uses the app's configured database URI
config.set_main_option("sqlalchemy.url", flask_app.config["SQLALCHEMY_DATABASE_URI"])


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    with flask_app.app_context():
        connectable = db.engine

        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,
            )

            with context.begin_transaction():
                context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
