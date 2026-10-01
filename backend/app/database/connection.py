from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config.settings import settings

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate():
    """Add columns introduced after the initial schema for existing databases."""
    log_file_cols = {
        "lines_total": "INTEGER",
        "lines_parsed": "INTEGER",
        "lines_skipped": "INTEGER",
        "detected_format": "VARCHAR(50)",
        "processing_notes": "TEXT",
    }
    try:
        inspector = inspect(engine)
        existing = {c["name"] for c in inspector.get_columns("log_files")}
        for col, col_type in log_file_cols.items():
            if col not in existing:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE log_files ADD COLUMN {col} {col_type}"))
    except Exception:
        # Table may not exist yet (fresh DB); create_all will handle it.
        pass


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate()
