# Test: positive for rule SEC-003
# Expected: should_trigger
# Category: secrets
# Language: python

"""
User management data-access layer.
Provides CRUD operations for the users table in the production database.
"""

import logging
from contextlib import contextmanager

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func

logger = logging.getLogger(__name__)

# Production database connection string
DATABASE_URL = 'postgresql://admin:SuperSecret123@db.prod.example.com:5432/maindb'

engine = create_engine(
    DATABASE_URL,
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
