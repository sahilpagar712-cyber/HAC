"""RedactZero FastAPI backend — main application entry point."""

import os
import sys

# Ensure the backend directory is on the Python path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from database import engine, Base
import models  # noqa: F401 — registers all models with Base

# Create all tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="RedactZero API",
    description="Backend API for the RedactZero PII Sanitization & Privacy Compliance application.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS
origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route modules
from routes.auth_routes import router as auth_router
from routes.scans import router as scans_router
from routes.alerts import router as alerts_router
from routes.activity import router as activity_router
from routes.dashboard import router as dashboard_router
from routes.settings import router as settings_router
from routes.network import router as network_router
from routes.privacy import router as privacy_router
from routes.firewall import router as firewall_router
from routes.image_scanner import router as image_scanner_router

app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(alerts_router)
app.include_router(activity_router)
app.include_router(dashboard_router)
app.include_router(settings_router)
app.include_router(network_router)
app.include_router(privacy_router)
app.include_router(firewall_router)
app.include_router(image_scanner_router)


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "RedactZero API", "version": "1.0.0"}


# Seed initial data on first run
@app.on_event("startup")
def seed_initial_data():
    from database import SessionLocal
    db = SessionLocal()
    try:
        # Only seed if no alerts exist
        if db.query(models.ThreatAlert).count() == 0:
            seed_alerts = [
                models.ThreatAlert(
                    severity="high",
                    title="Suspicious Activity Blocked",
                    detail="Attempted access from unknown IP pattern detected in uploaded logs",
                    source="pii_scanner",
                ),
                models.ThreatAlert(
                    severity="info",
                    title="Scan Completed",
                    detail="No threats found in system scan",
                    source="scanner",
                ),
                models.ThreatAlert(
                    severity="info",
                    title="Firewall Updated",
                    detail="Latest CSP rules applied successfully",
                    source="firewall",
                ),
                models.ThreatAlert(
                    severity="medium",
                    title="PII Exposure Risk",
                    detail="Unredacted credit card numbers detected in sample dataset",
                    source="pii_scanner",
                ),
            ]
            db.add_all(seed_alerts)

            seed_activity = [
                models.ActivityLog(level="SAFE", message="System Scan Completed", subtext="No threats found", source="system"),
                models.ActivityLog(level="INFO", message="Firewall Rules Updated", subtext="Security rules are up to date", source="firewall"),
                models.ActivityLog(level="INFO", message="USB Device Scanned", subtext="No risks detected", source="scanner"),
                models.ActivityLog(level="ALERT", message="Blocked Malicious Connection", subtext="From 185.199.110.153", source="firewall"),
                models.ActivityLog(level="SAFE", message="CSP Policy Verified", subtext="connect-src 'self' enforced", source="system"),
            ]
            db.add_all(seed_activity)

            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
