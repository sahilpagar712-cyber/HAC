"""Threat alert endpoints: list, create, acknowledge."""

import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
import models
from auth import get_current_user
from schemas import AlertCreateRequest, AlertResponse

router = APIRouter(prefix="/api/alerts", tags=["Threat Alerts"])


@router.get("/", response_model=list[AlertResponse])
def list_alerts(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    query = db.query(models.ThreatAlert)
    if severity:
        query = query.filter(models.ThreatAlert.severity == severity)
    if acknowledged is not None:
        query = query.filter(models.ThreatAlert.is_acknowledged == acknowledged)
    return [
        AlertResponse.model_validate(a)
        for a in query.order_by(desc(models.ThreatAlert.created_at)).offset(skip).limit(limit).all()
    ]


@router.post("/", response_model=AlertResponse, status_code=201)
def create_alert(
    req: AlertCreateRequest,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    alert = models.ThreatAlert(
        severity=req.severity,
        title=req.title,
        detail=req.detail,
        source=req.source,
    )
    db.add(alert)

    log = models.ActivityLog(
        user_id=user.id if user else None,
        level="ALERT" if req.severity in ("critical", "high") else "WARN",
        message=f"Alert created: {req.title}",
        subtext=req.detail,
        source="alerts",
    )
    db.add(log)
    db.commit()
    db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    alert = db.query(models.ThreatAlert).filter(models.ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_acknowledged = True
    alert.acknowledged_at = datetime.datetime.utcnow()

    log = models.ActivityLog(
        user_id=user.id if user else None,
        level="INFO",
        message=f"Alert acknowledged: {alert.title}",
        subtext=f"Alert #{alert_id} marked as handled",
        source="alerts",
    )
    db.add(log)
    db.commit()
    db.refresh(alert)

    return AlertResponse.model_validate(alert)
