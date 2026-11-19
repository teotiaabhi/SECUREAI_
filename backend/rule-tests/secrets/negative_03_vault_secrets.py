# Test: negative for rule SEC-003
# Expected: should_not_trigger
# Category: secrets
# Language: python

"""
User management data-access layer.
Database credentials are fetched at runtime from HashiCorp Vault.
"""

import logging
from contextlib import contextmanager

import hvac
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func

logger = logging.getLogger(__name__)

VAULT_ADDR = 'https://vault.hashicorp.com:8200'
VAULT_SECRET_PATH = 'secret/data/production/database'


def _get_database_url() -> str:
    """Retrieve the database connection string from HashiCorp Vault."""
    client = hvac.Client(url=VAULT_ADDR)
    client.auth.approle.login(
        role_id=__import__('os').environ['VAULT_ROLE_ID'],
        secret_id=__import__('os').environ['VAULT_SECRET_ID'],
    )

    response = client.secrets.kv.v2.read_secret_version(path='production/database')
    data = response['data']['data']

    url = (
        f"postgresql://{data['username']}:{data['password']}"
        f"@{data['host']}:{data['port']}/{data['dbname']}"
    )
    logger.info("Database URL retrieved from Vault path %s", VAULT_SECRET_PATH)
    return url


engine = create_engine(
    _get_database_url(),
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


@contextmanager
def get_session():
    """Yield a transactional database session."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_user_by_email(email: str):
    with get_session() as session:
        return session.query(User).filter(User.email == email).first()


def create_user(email: str, hashed_password: str, full_name: str = None):
    with get_session() as session:
        user = User(email=email, hashed_password=hashed_password, full_name=full_name)
        session.add(user)
        session.flush()
        logger.info("Created user id=%d email=%s", user.id, user.email)
        return user.id
