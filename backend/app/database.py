from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SECURITY NOTE: In production, we will verify this URL comes from a secure environment variable.
# For local dev, we use SQLite (a file), but we treat it like Postgres.
SQLALCHEMY_DATABASE_URL = "sqlite:///./secure_job_app.db"

# connect_args is needed only for SQLite. We will remove it when we switch to Postgres on the VM.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# This is the "Session Factory". Every request gets its own secure session.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# This class allows us to define tables as Python classes (ORM)
Base = declarative_base()

# Dependency Injection: This ensures the DB connection closes after every request.
# preventing "Connection Leak" attacks.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()