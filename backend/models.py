"""SQLAlchemy ORM models for RedactZero backend."""

import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    sessions = relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("SecurityScan", back_populates="user", cascade="all, delete-orphan")
    settings = relationship("AppSetting", back_populates="user", cascade="all, delete-orphan")


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(500), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)

    user = relationship("User", back_populates="sessions")


class SecurityScan(Base):
    __tablename__ = "security_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    filename = Column(String(255), nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True)
    file_size = Column(Integer, nullable=True)
    scan_type = Column(String(50), default="pii_detection")
    status = Column(String(20), default="completed")  # pending, running, completed, failed
    total_pii_found = Column(Integer, default=0)
    total_redacted = Column(Integer, default=0)
    luhn_rejected = Column(Integer, default=0)
    redaction_mode = Column(String(30), nullable=True)
    results_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("security_scans.id"), nullable=False)
    pii_type = Column(String(30), nullable=False)
    matched_value = Column(String(500), nullable=True)
    start_offset = Column(Integer, nullable=True)
    end_offset = Column(Integer, nullable=True)
    validation_method = Column(String(100), nullable=True)
    is_valid = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("SecurityScan", back_populates="results")


class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    title = Column(String(255), nullable=False)
    detail = Column(Text, nullable=True)
    source = Column(String(100), nullable=True)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    level = Column(String(10), nullable=False)  # SAFE, INFO, WARN, ALERT
    message = Column(String(500), nullable=False)
    subtext = Column(String(500), nullable=True)
    source = Column(String(50), default="system")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class NetworkInfo(Base):
    __tablename__ = "network_info"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=True)
    local_ip = Column(String(45), nullable=True)
    interfaces_json = Column(JSON, nullable=True)
    checked_at = Column(DateTime, default=datetime.datetime.utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    setting_key = Column(String(100), nullable=False)
    setting_value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = relationship("User", back_populates="settings")


class ImageScan(Base):
    __tablename__ = "image_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    filename = Column(String(255), nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    file_format = Column(String(30), nullable=False)
    mime_type = Column(String(80), nullable=True)
    file_size = Column(Integer, nullable=False)
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    thumbnail_b64 = Column(Text, nullable=True)
    exif_json = Column(JSON, nullable=True)
    security_checks_json = Column(JSON, nullable=True)
    findings_json = Column(JSON, nullable=True)
    risk_score = Column(Integer, nullable=False, default=100)
    risk_category = Column(String(10), nullable=False, default="GREEN")  # GREEN, YELLOW, RED
    score_reasons_json = Column(JSON, nullable=True)
    scan_status = Column(String(20), nullable=False, default="completed")
    clamav_status = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class PrivacyCheckReport(Base):
    __tablename__ = "privacy_check_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    overall_score = Column(Integer, nullable=False, default=100)
    risk_level = Column(String(20), nullable=False, default="GOOD")
    https_enabled = Column(Boolean, default=False)
    origin = Column(String(255), nullable=True)
    browser_info_json = Column(JSON, nullable=True)
    permissions_json = Column(JSON, nullable=True)
    cookie_summary_json = Column(JSON, nullable=True)
    storage_summary_json = Column(JSON, nullable=True)
    third_party_indicators_json = Column(JSON, nullable=True)
    password_summary = Column(String(255), nullable=True)
    recommendations_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class PrivacySetting(Base):
    __tablename__ = "privacy_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    settings_json = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

