"""Pydantic request/response schemas for the RedactZero API."""

from __future__ import annotations
import datetime
from typing import Optional, Any
from pydantic import BaseModel, EmailStr, Field


# ── Auth ──────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=6, max_length=128)

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ── Scans ─────────────────────────────────────────────
class ScanCreateRequest(BaseModel):
    filename: Optional[str] = None
    content: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size: Optional[int] = None
    scan_type: str = "pii_detection"
    total_pii_found: int = 0
    total_redacted: int = 0
    luhn_rejected: int = 0
    redaction_mode: Optional[str] = None
    results_json: Optional[Any] = None

class ScanResponse(BaseModel):
    id: int
    user_id: Optional[int]
    filename: Optional[str]
    file_hash_sha256: Optional[str]
    file_size: Optional[int]
    scan_type: str
    status: str
    total_pii_found: int
    total_redacted: int
    luhn_rejected: int
    redaction_mode: Optional[str]
    results_json: Optional[Any]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ── Alerts ────────────────────────────────────────────
class AlertCreateRequest(BaseModel):
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    title: str = Field(..., min_length=1, max_length=255)
    detail: Optional[str] = None
    source: Optional[str] = None

class AlertResponse(BaseModel):
    id: int
    severity: str
    title: str
    detail: Optional[str]
    source: Optional[str]
    is_acknowledged: bool
    acknowledged_at: Optional[datetime.datetime]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ── Activity ──────────────────────────────────────────
class ActivityCreateRequest(BaseModel):
    level: str = Field(..., pattern="^(SAFE|INFO|WARN|ALERT)$")
    message: str = Field(..., min_length=1, max_length=500)
    subtext: Optional[str] = None
    source: str = "frontend"

class ActivityResponse(BaseModel):
    id: int
    user_id: Optional[int]
    level: str
    message: str
    subtext: Optional[str]
    source: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ── Dashboard ─────────────────────────────────────────
class DashboardStats(BaseModel):
    total_scans: int
    total_pii_found: int
    total_redacted: int
    total_luhn_rejected: int
    total_alerts: int
    unacknowledged_alerts: int
    total_activity_events: int
    recent_scans: list[ScanResponse]
    recent_alerts: list[AlertResponse]
    recent_activity: list[ActivityResponse]


# ── Settings ──────────────────────────────────────────
class SettingSaveRequest(BaseModel):
    settings: dict[str, Any]

class SettingsResponse(BaseModel):
    settings: dict[str, Any]


# ── Network ───────────────────────────────────────────
class NetworkInfoResponse(BaseModel):
    hostname: str
    local_ip: str
    interfaces: list[dict[str, Any]]
    checked_at: datetime.datetime


# ── Privacy / Password ────────────────────────────────
class PasswordStrengthRequest(BaseModel):
    password: str = Field(..., min_length=1)

class PasswordStrengthResponse(BaseModel):
    score: int  # 0-5
    label: str  # Very Weak, Weak, Fair, Good, Strong, Very Strong
    suggestions: list[str]
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digit: bool
    has_special: bool


# ── Firewall ──────────────────────────────────────────
class FirewallStatusResponse(BaseModel):
    csp_policy: str
    connect_src_locked: bool
    backend_note: str
    recommendations: list[str]


# ── Image Security Scanner ────────────────────────────
class ImageUploadResponse(BaseModel):
    upload_id: str
    filename: str
    file_size: int
    detected_format: str
    mime_type: str
    sha256_hash: str


class ImageScanResponse(BaseModel):
    id: int
    user_id: Optional[int]
    filename: str
    sha256_hash: str
    file_format: str
    mime_type: Optional[str]
    file_size: int
    width: Optional[int]
    height: Optional[int]
    thumbnail_b64: Optional[str]
    exif_json: Optional[Any]
    security_checks_json: Optional[Any]
    findings_json: Optional[Any]
    risk_score: int
    risk_category: str
    score_reasons_json: Optional[Any]
    scan_status: str
    clamav_status: Optional[str]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ── Privacy Guard ─────────────────────────────────────
class PrivacyCheckRequest(BaseModel):
    https_enabled: bool
    is_secure_context: bool = False
    origin: str = ""
    dnt: Optional[str] = None
    cookies_enabled: bool = True
    user_agent: str = ""
    platform: str = ""
    cookie_names: list[str] = Field(default_factory=list)
    local_storage_keys: list[dict[str, Any]] = Field(default_factory=list)
    session_storage_keys: list[dict[str, Any]] = Field(default_factory=list)
    permissions: dict[str, str] = Field(default_factory=dict)
    third_party_origins: list[str] = Field(default_factory=list)
    mixed_content_count: int = 0
    password_summary: Optional[str] = None


class PrivacyCheckReportResponse(BaseModel):
    id: int
    user_id: Optional[int]
    overall_score: int
    risk_level: str
    https_enabled: bool
    origin: Optional[str]
    browser_info_json: Optional[Any]
    permissions_json: Optional[Any]
    cookie_summary_json: Optional[Any]
    storage_summary_json: Optional[Any]
    third_party_indicators_json: Optional[Any]
    password_summary: Optional[str]
    recommendations_json: Optional[Any]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class PrivacySettingsRequest(BaseModel):
    auto_flag_sensitive_storage: bool = True
    check_third_party_resources: bool = True
    warn_on_http: bool = True
    prefer_session_over_local: bool = True


