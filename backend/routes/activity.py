"""Activity log endpoints: list events and create new entries."""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
import models
from auth import get_current_user
from schemas import ActivityCreateRequest, ActivityResponse

router = APIRouter(prefix="/api/activity", tags=["Activity Logs"])


@router.get("/", response_model=list[ActivityResponse])
def list_activity(
    skip: int = 0,
    limit: int = 50,
    level: Optional[str] = Query(None, pattern="^(SAFE|INFO|WARN|ALERT)$"),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    query = db.query(models.ActivityLog)
    if user:
        query = query.filter(
            (models.ActivityLog.user_id == user.id) | (models.ActivityLog.user_id.is_(None))
        )
    if level:
        query = query.filter(models.ActivityLog.level == level)
    if search:
        query = query.filter(
            models.ActivityLog.message.ilike(f"%{search}%")
            | models.ActivityLog.subtext.ilike(f"%{search}%")
        )
    return [
        ActivityResponse.model_validate(a)
        for a in query.order_by(desc(models.ActivityLog.created_at)).offset(skip).limit(limit).all()
    ]


@router.post("/", response_model=ActivityResponse, status_code=201)
def create_activity(
    req: ActivityCreateRequest,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    log = models.ActivityLog(
        user_id=user.id if user else None,
        level=req.level,
        message=req.message,
        subtext=req.subtext,
        source=req.source,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return ActivityResponse.model_validate(log)
