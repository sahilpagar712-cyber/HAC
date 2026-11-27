"""Dashboard stats endpoint: aggregated counts from all tables."""

from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from database import get_db
import models
from auth import get_current_user
from schemas import DashboardStats, ScanResponse, AlertResponse, ActivityResponse

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    # Scan stats
    scan_query = db.query(models.SecurityScan)
    if user:
        scan_query = scan_query.filter(models.SecurityScan.user_id == user.id)

    total_scans = scan_query.count()
    scan_agg = scan_query.with_entities(
        func.coalesce(func.sum(models.SecurityScan.total_pii_found), 0),
        func.coalesce(func.sum(models.SecurityScan.total_redacted), 0),
        func.coalesce(func.sum(models.SecurityScan.luhn_rejected), 0),
    ).first()

    total_pii = int(scan_agg[0]) if scan_agg else 0
    total_redacted = int(scan_agg[1]) if scan_agg else 0
    total_luhn = int(scan_agg[2]) if scan_agg else 0

    # Alerts
    total_alerts = db.query(models.ThreatAlert).count()
    unack_alerts = db.query(models.ThreatAlert).filter(
        models.ThreatAlert.is_acknowledged == False
    ).count()

    # Activity
    activity_query = db.query(models.ActivityLog)
    if user:
        activity_query = activity_query.filter(
            (models.ActivityLog.user_id == user.id) | (models.ActivityLog.user_id.is_(None))
        )
    total_activity = activity_query.count()

    # Recent items
    recent_scans = [
        ScanResponse.model_validate(s)
        for s in scan_query.order_by(desc(models.SecurityScan.created_at)).limit(5).all()
    ]
    recent_alerts = [
        AlertResponse.model_validate(a)
        for a in db.query(models.ThreatAlert).order_by(desc(models.ThreatAlert.created_at)).limit(5).all()
    ]
    recent_activity = [
        ActivityResponse.model_validate(a)
        for a in activity_query.order_by(desc(models.ActivityLog.created_at)).limit(10).all()
    ]

    return DashboardStats(
        total_scans=total_scans,
        total_pii_found=total_pii,
        total_redacted=total_redacted,
        total_luhn_rejected=total_luhn,
        total_alerts=total_alerts,
        unacknowledged_alerts=unack_alerts,
        total_activity_events=total_activity,
        recent_scans=recent_scans,
        recent_alerts=recent_alerts,
        recent_activity=recent_activity,
    )
