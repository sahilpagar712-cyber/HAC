"""Privacy Guard endpoints: dashboard, check, history, recommendations, PDF report, settings."""

import io
import re
from typing import Optional
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import desc
from sqlalchemy.orm import Session

import models
from auth import get_current_user
from database import get_db
from schemas import (
    PasswordStrengthRequest,
    PasswordStrengthResponse,
    PrivacyCheckReportResponse,
    PrivacyCheckRequest,
    PrivacySettingsRequest,
)

router = APIRouter(prefix="/api/privacy", tags=["Privacy Guard"])

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "michael", "shadow", "123123", "654321", "000000", "password1",
    "admin", "admin123", "root", "toor", "pass", "test", "guest",
}

SENSITIVE_KEY_RE = re.compile(r"(token|auth|secret|password|passwd|pwd|api_?key|jwt|session|ssn|aadhaar|pan|card)", re.I)


def _evaluate_privacy(req: PrivacyCheckRequest) -> tuple[int, str, list[dict], dict, dict]:
    """Compute transparent privacy score, risk level, recommendations, and sanitized summaries."""
    score = 100
    recommendations = []

    # 1. HTTPS Check
    if not req.https_enabled:
        score -= 20
        recommendations.append({
            "id": "use-https",
            "severity": "high",
            "title": "Use HTTPS in Production",
            "why_it_matters": "Unencrypted HTTP traffic can be intercepted or modified on local networks (MITM). Always deploy with TLS/HTTPS.",
            "status": "Action Needed",
        })
    else:
        recommendations.append({
            "id": "https-ok",
            "severity": "info",
            "title": "HTTPS Transport Active",
            "why_it_matters": "Your connection is encrypted in transit, protecting session tokens and PII from eavesdropping.",
            "status": "Verified",
        })

    # 2. Mixed content
    if req.mixed_content_count > 0:
        score -= 15
        recommendations.append({
            "id": "mixed-content",
            "severity": "high",
            "title": f"Resolve {req.mixed_content_count} Mixed-Content Resource(s)",
            "why_it_matters": "Loading HTTP assets inside an HTTPS page weakens transport security and exposes users to tampering.",
            "status": "Action Needed",
        })

    # 3. Third-party tracking indicators
    if len(req.third_party_origins) > 0:
        score -= min(15, 5 * len(req.third_party_origins))
        recommendations.append({
            "id": "third-party-origins",
            "severity": "medium",
            "title": f"Review {len(req.third_party_origins)} External Resource Origin(s)",
            "why_it_matters": "Third-party scripts or assets can observe user IP addresses, referrer headers, or set tracking cookies.",
            "status": "Review",
        })

    # 4. Permissions
    granted_perms = [k for k, v in (req.permissions or {}).items() if v == "granted"]
    if granted_perms:
        score -= min(10, 4 * len(granted_perms))
        recommendations.append({
            "id": "review-permissions",
            "severity": "medium",
            "title": f"Review Granted Browser Permissions ({', '.join(granted_perms)})",
            "why_it_matters": "Granted hardware or sensor permissions (camera, mic, location, clipboard) remain active for this origin until revoked.",
            "status": "Review",
        })

    # 5. Storage analysis (keys/sizes only — no values)
    flagged_local = [
        item for item in req.local_storage_keys
        if SENSITIVE_KEY_RE.search(str(item.get("key", "")))
    ]
    if flagged_local:
        score -= 15
        recommendations.append({
            "id": "avoid-sensitive-localstorage",
            "severity": "medium",
            "title": f"Sensitive-Looking Key(s) in localStorage ({len(flagged_local)})",
            "why_it_matters": "Data in localStorage persists across browser restarts and is readable by any JavaScript running on the origin (XSS risk). Prefer HttpOnly cookies or sessionStorage.",
            "status": "Review",
        })

    # 6. Cookie analysis (names only — no values)
    if len(req.cookie_names) > 0:
        recommendations.append({
            "id": "secure-cookies",
            "severity": "low",
            "title": f"Verify Secure / HttpOnly / SameSite Flags on {len(req.cookie_names)} Cookie(s)",
            "why_it_matters": "Cookies visible to document.cookie lack the HttpOnly flag and could be accessed by client scripts. Set HttpOnly, Secure, and SameSite=Lax/Strict server-side.",
            "status": "Advisory",
        })

    # 7. Do Not Track
    if req.dnt != "1":
        score -= 5
        recommendations.append({
            "id": "enable-dnt",
            "severity": "low",
            "title": "Enable Browser Privacy Protections / Do Not Track",
            "why_it_matters": "Enabling strict tracking protection and Do Not Track signals reduces cross-site profiling.",
            "status": "Advisory",
        })

    score = max(0, min(100, score))
    risk_level = "GOOD" if score >= 80 else ("MODERATE" if score >= 55 else "ATTENTION")

    cookie_summary = {
        "accessible_count": len(req.cookie_names),
        "cookie_names": req.cookie_names[:50],
        "cookies_enabled": req.cookies_enabled,
        "limitation_note": (
            "Browser same-origin policy restricts document.cookie to non-HttpOnly cookies on this origin only. "
            "HttpOnly cookies and third-party website cookies cannot be inspected by client-side JavaScript."
        ),
    }

    storage_summary = {
        "local_storage_count": len(req.local_storage_keys),
        "local_storage_bytes": sum(int(i.get("bytes", 0)) for i in req.local_storage_keys),
        "local_storage_keys": req.local_storage_keys[:50],
        "session_storage_count": len(req.session_storage_keys),
        "session_storage_bytes": sum(int(i.get("bytes", 0)) for i in req.session_storage_keys),
        "session_storage_keys": req.session_storage_keys[:50],
        "flagged_sensitive_keys": [i.get("key") for i in flagged_local],
    }

    return score, risk_level, recommendations, cookie_summary, storage_summary


@router.get("/dashboard")
def get_privacy_dashboard(
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    query = db.query(models.PrivacyCheckReport)
    if user:
        query = query.filter((models.PrivacyCheckReport.user_id == user.id) | (models.PrivacyCheckReport.user_id.is_(None)))
    else:
        query = query.filter(models.PrivacyCheckReport.user_id.is_(None))

    latest = query.order_by(desc(models.PrivacyCheckReport.created_at)).first()
    total_checks = query.count()
    recent = query.order_by(desc(models.PrivacyCheckReport.created_at)).limit(10).all()

    settings_row = db.query(models.PrivacySetting).filter(
        models.PrivacySetting.user_id == (user.id if user else None)
    ).first()

    return {
        "total_checks": total_checks,
        "latest_report": PrivacyCheckReportResponse.model_validate(latest) if latest else None,
        "recent_checks": [PrivacyCheckReportResponse.model_validate(r) for r in recent],
        "settings": settings_row.settings_json if settings_row else {
            "auto_flag_sensitive_storage": True,
            "check_third_party_resources": True,
            "warn_on_http": True,
            "prefer_session_over_local": True,
        },
    }


@router.post("/check", response_model=PrivacyCheckReportResponse, status_code=201)
def run_privacy_check(
    req: PrivacyCheckRequest,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    """Store a real browser privacy check summary (never stores passwords or cookie values)."""
    score, risk_level, recommendations, cookie_summary, storage_summary = _evaluate_privacy(req)

    browser_info = {
        "user_agent": req.user_agent[:300],
        "platform": req.platform[:80],
        "dnt": req.dnt,
        "cookies_enabled": req.cookies_enabled,
        "is_secure_context": req.is_secure_context,
    }

    third_party = {
        "external_origins_count": len(req.third_party_origins),
        "external_origins": req.third_party_origins[:30],
        "mixed_content_count": req.mixed_content_count,
    }

    report = models.PrivacyCheckReport(
        user_id=user.id if user else None,
        overall_score=score,
        risk_level=risk_level,
        https_enabled=req.https_enabled,
        origin=req.origin[:255],
        browser_info_json=browser_info,
        permissions_json=req.permissions,
        cookie_summary_json=cookie_summary,
        storage_summary_json=storage_summary,
        third_party_indicators_json=third_party,
        password_summary=(req.password_summary or "Not evaluated")[:255],
        recommendations_json=recommendations,
    )
    db.add(report)

    db.add(
        models.ActivityLog(
            user_id=user.id if user else None,
            level="SAFE" if risk_level == "GOOD" else "WARN",
            message=f"Privacy Guard Check Completed ({risk_level})",
            subtext=f"Score: {score}/100 | HTTPS: {req.https_enabled} | Origin: {req.origin[:60]}",
            source="privacy_guard",
        )
    )
    db.commit()
    db.refresh(report)
    return PrivacyCheckReportResponse.model_validate(report)


@router.get("/history", response_model=list[PrivacyCheckReportResponse])
def get_privacy_history(
    limit: int = 30,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    query = db.query(models.PrivacyCheckReport)
    if user:
        query = query.filter((models.PrivacyCheckReport.user_id == user.id) | (models.PrivacyCheckReport.user_id.is_(None)))
    else:
        query = query.filter(models.PrivacyCheckReport.user_id.is_(None))
    rows = query.order_by(desc(models.PrivacyCheckReport.created_at)).limit(limit).all()
    return [PrivacyCheckReportResponse.model_validate(r) for r in rows]


@router.get("/recommendations")
def get_privacy_recommendations(
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    query = db.query(models.PrivacyCheckReport)
    if user:
        query = query.filter((models.PrivacyCheckReport.user_id == user.id) | (models.PrivacyCheckReport.user_id.is_(None)))
    else:
        query = query.filter(models.PrivacyCheckReport.user_id.is_(None))
    latest = query.order_by(desc(models.PrivacyCheckReport.created_at)).first()
    if latest and latest.recommendations_json:
        return {"report_id": latest.id, "recommendations": latest.recommendations_json}
    return {
        "report_id": None,
        "recommendations": [
            {
                "id": "run-check",
                "severity": "info",
                "title": "Run a Browser Privacy Check",
                "why_it_matters": "Click 'Check Privacy' to inspect HTTPS, permissions, storage keys, and cookies on your current origin.",
                "status": "Pending",
            }
        ],
    }


@router.post("/settings")
def save_privacy_settings(
    req: PrivacySettingsRequest,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    uid = user.id if user else None
    existing = db.query(models.PrivacySetting).filter(models.PrivacySetting.user_id == uid).first()
    data = req.model_dump()
    if existing:
        existing.settings_json = data
    else:
        db.add(models.PrivacySetting(user_id=uid, settings_json=data))
    db.commit()
    return {"saved": True, "settings": data}


@router.get("/report/{report_id}")
def download_privacy_report_pdf(
    report_id: int,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    """Export a non-sensitive Privacy Guard PDF report."""
    report = db.query(models.PrivacyCheckReport).filter(models.PrivacyCheckReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Privacy report not found")
    if report.user_id is not None and (user is None or report.user_id != user.id):
        raise HTTPException(status_code=403, detail="Not authorized to access this report")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=48, leftMargin=48, topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("PrivTitle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#1e3a8a"))
    h2_style = ParagraphStyle("PrivH2", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#0f172a"), spaceBefore=10)
    body_style = ParagraphStyle("PrivBody", parent=styles["Normal"], fontSize=9.5, leading=13)

    b_info = report.browser_info_json or {}
    c_sum = report.cookie_summary_json or {}
    s_sum = report.storage_summary_json or {}
    tp_info = report.third_party_indicators_json or {}

    elements = [
        Paragraph("SecureX / RedactZero — Privacy Guard Report", title_style),
        Spacer(1, 6),
        Paragraph(f"Report ID: #{report.id} &nbsp;|&nbsp; Checked At: {report.created_at.isoformat()} UTC", body_style),
        Spacer(1, 12),
    ]

    summary_rows = [
        ["Overall Privacy Score", f"{report.overall_score} / 100 ({report.risk_level})"],
        ["Origin", xml_escape(str(report.origin or "n/a"))],
        ["HTTPS Enabled", "Yes" if report.https_enabled else "No (HTTP)"],
        ["Secure Context", "Yes" if b_info.get("is_secure_context") else "No"],
        ["Platform / DNT", f"{xml_escape(str(b_info.get('platform', 'n/a')))} | DNT: {b_info.get('dnt') or 'unset'}"],
        ["Cookies (Same-Origin JS)", f"{c_sum.get('accessible_count', 0)} non-HttpOnly cookie(s) (values omitted)"],
        ["Local / Session Storage", f"{s_sum.get('local_storage_count', 0)} localStorage key(s), {s_sum.get('session_storage_count', 0)} sessionStorage key(s)"],
        ["Third-Party Origins", f"{tp_info.get('external_origins_count', 0)} external resource origin(s)"],
        ["Password Strength Summary", xml_escape(str(report.password_summary or "Not evaluated"))],
    ]
    t = Table(summary_rows, colWidths=[2.0 * inch, 4.7 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.extend([t, Spacer(1, 12)])

    elements.append(Paragraph("Browser Permissions", h2_style))
    perms = report.permissions_json or {}
    perm_text = ", ".join(f"{xml_escape(k)}: {xml_escape(str(v))}" for k, v in perms.items()) or "Not queried"
    elements.append(Paragraph(perm_text, body_style))

    elements.append(Paragraph("Privacy Recommendations", h2_style))
    for rec in (report.recommendations_json or []):
        sev = xml_escape(str(rec.get("severity", "info")).upper())
        title = xml_escape(str(rec.get("title", "")))
        why = xml_escape(str(rec.get("why_it_matters", "")))
        elements.append(Paragraph(f"<b>[{sev}] {title}</b>: {why}", body_style))

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Privacy & Scope Notice", h2_style))
    elements.append(Paragraph(
        "This report never includes entered passwords, private cookie values, or raw GPS coordinates. "
        "Due to browser same-origin restrictions, cookie and storage checks apply only to the current origin; "
        "HttpOnly cookies and unrelated third-party websites cannot be inspected by client-side scripts.",
        body_style,
    ))

    doc.build(elements)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="securex_privacy_report_{report.id}.pdf"'},
    )


@router.post("/check-password-strength", response_model=PasswordStrengthResponse)
def check_password_strength(req: PasswordStrengthRequest):
    """Legacy endpoint kept for compatibility; frontend evaluates passwords 100% locally."""
    pw = req.password
    score = 0
    suggestions = []
    length = len(pw)
    has_upper = bool(re.search(r"[A-Z]", pw))
    has_lower = bool(re.search(r"[a-z]", pw))
    has_digit = bool(re.search(r"\d", pw))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", pw))
    if length >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters")
    if length >= 12:
        score += 1
    if has_upper and has_lower:
        score += 1
    if has_digit:
        score += 0.5
    if has_special:
        score += 0.5
    if pw.lower() in COMMON_PASSWORDS:
        score = max(0, score - 2)
        suggestions.insert(0, "Avoid commonly used passwords")
    score = int(min(5, max(0, round(score))))
    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
    return PasswordStrengthResponse(
        score=score,
        label=labels[score],
        suggestions=suggestions or ["Your password meets all strength criteria!"],
        length=length,
        has_uppercase=has_upper,
        has_lowercase=has_lower,
        has_digit=has_digit,
        has_special=has_special,
    )
