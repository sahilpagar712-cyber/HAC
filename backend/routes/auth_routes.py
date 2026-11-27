"""Authentication endpoints: register, login, logout, me."""

import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
import models
from auth import hash_password, verify_password, create_access_token, require_auth, ACCESS_TOKEN_EXPIRE_MINUTES
from schemas import RegisterRequest, LoginRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    # Check existing username
    if db.query(models.User).filter(models.User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    # Check existing email
    if db.query(models.User).filter(models.User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = models.User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create token
    expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data={"sub": str(user.id)}, expires_delta=expires)

    # Store session
    session = models.AuthSession(
        user_id=user.id,
        token=token,
        expires_at=datetime.datetime.utcnow() + expires,
    )
    db.add(session)

    # Log the registration
    log = models.ActivityLog(
        user_id=user.id,
        level="INFO",
        message=f"User '{user.username}' registered",
        subtext="New account created via API",
        source="auth",
    )
    db.add(log)
    db.commit()

    return TokenResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data={"sub": str(user.id)}, expires_delta=expires)

    session = models.AuthSession(
        user_id=user.id,
        token=token,
        expires_at=datetime.datetime.utcnow() + expires,
    )
    db.add(session)

    log = models.ActivityLog(
        user_id=user.id,
        level="INFO",
        message=f"User '{user.username}' logged in",
        subtext="Authentication successful",
        source="auth",
    )
    db.add(log)
    db.commit()

    return TokenResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout")
def logout(user: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    # Revoke all active sessions for this user
    db.query(models.AuthSession).filter(
        models.AuthSession.user_id == user.id,
        models.AuthSession.is_revoked == False,
    ).update({"is_revoked": True})

    log = models.ActivityLog(
        user_id=user.id,
        level="INFO",
        message=f"User '{user.username}' logged out",
        subtext="All sessions revoked",
        source="auth",
    )
    db.add(log)
    db.commit()

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
def get_me(user: models.User = Depends(require_auth)):
    return UserResponse.model_validate(user)
