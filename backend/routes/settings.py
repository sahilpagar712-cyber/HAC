"""User settings endpoints: get and save settings."""

import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
import models
from auth import require_auth
from schemas import SettingSaveRequest, SettingsResponse

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("/", response_model=SettingsResponse)
def get_settings(user: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    rows = db.query(models.AppSetting).filter(models.AppSetting.user_id == user.id).all()
    settings = {}
    for row in rows:
        try:
            settings[row.setting_key] = json.loads(row.setting_value)
        except (json.JSONDecodeError, TypeError):
            settings[row.setting_key] = row.setting_value
    return SettingsResponse(settings=settings)


@router.put("/", response_model=SettingsResponse)
def save_settings(
    req: SettingSaveRequest,
    user: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    for key, value in req.settings.items():
        existing = db.query(models.AppSetting).filter(
            models.AppSetting.user_id == user.id,
            models.AppSetting.setting_key == key,
        ).first()

        serialized = json.dumps(value) if not isinstance(value, str) else value

        if existing:
            existing.setting_value = serialized
        else:
            new_setting = models.AppSetting(
                user_id=user.id,
                setting_key=key,
                setting_value=serialized,
            )
            db.add(new_setting)

    log = models.ActivityLog(
        user_id=user.id,
        level="INFO",
        message="Settings updated",
        subtext=f"Updated {len(req.settings)} setting(s)",
        source="settings",
    )
    db.add(log)
    db.commit()

    return get_settings(user=user, db=db)
