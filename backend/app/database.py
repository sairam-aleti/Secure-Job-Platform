from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# PROFESSIONAL DATABASE: PostgreSQL
# Connection format: postgresql://USER:PASSWORD@localhost/DB_NAME
SQLALCHEMY_DATABASE_URL = "postgresql://secureadmin:FortKnoxPass123!@localhost/securejobdb"

# Create the engine (No 'check_same_thread' needed for Postgres)
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# The Session Factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Dependency Injection for API routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()