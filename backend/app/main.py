from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config.settings import settings
from app.database.connection import init_db
from app.api import auth_router, logs_router, events_router, incidents_router, analytics_router, demo_router

app = FastAPI(
    title="LogTrace AI",
    description="Cybersecurity Log Analysis and Incident Investigation Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(events_router)
app.include_router(incidents_router)
app.include_router(analytics_router)
app.include_router(demo_router)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "version": "1.0.0"}
