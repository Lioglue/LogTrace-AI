from app.api.auth import router as auth_router
from app.api.logs import router as logs_router
from app.api.events import router as events_router
from app.api.incidents import router as incidents_router
from app.api.analytics import router as analytics_router
from app.api.demo import router as demo_router

__all__ = [
    "auth_router", "logs_router", "events_router",
    "incidents_router", "analytics_router", "demo_router",
]
