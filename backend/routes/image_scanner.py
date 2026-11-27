"""Image Security Scanner endpoints: upload, deep static/metadata/visual analysis, history, and PDF reports."""

import base64
import datetime
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import uuid
from collections import defaultdict, deque
from typing import Optional
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from PIL import ExifTags, Image, ImageFile
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
from schemas import ImageScanResponse, ImageUploadResponse

# Protect against decompression bombs (max 25 megapixels)
Image.MAX_IMAGE_PIXELS = 25_000_000
ImageFile.LOAD_TRUNCATED_IMAGES = False

router = APIRouter(prefix="/api/image-scanner", tags=["Image Security Scanner"])

MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_DIMENSION_PX = 8000
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP", "GIF"}

TEMP_DIR = os.path.join(tempfile.gettempdir(), "redactzero_img_tmp")
os.makedirs(TEMP_DIR, exist_ok=True)

# Simple in-memory rate limiter: max 30 upload/scan requests per 60s per IP
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
RATE_LIMIT_MAX = 30
RATE_LIMIT_WINDOW = 60.0

# In-memory map of pending upload_id -> {path, filename, sha256, mime_type, detected_format, size, created_at}
_pending_uploads: dict[str, dict] = {}


def _check_rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please wait a minute before scanning more images.")
    bucket.append(now)


def _sanitize_filename(filename: Optional[str]) -> str:
    base = os.path.basename(filename or "uploaded_image")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._")
    return (cleaned or "uploaded_image")[:180]


def _cleanup_stale_uploads() -> None:
    now = time.time()
    stale = [uid for uid, meta in _pending_uploads.items() if now - meta["created_at"] > 900]
    for uid in stale:
        meta = _pending_uploads.pop(uid, None)
        if meta and os.path.exists(meta["path"]):
            try:
                os.remove(meta["path"])
            except OSError:
                pass


def _detect_magic_format(data: bytes) -> tuple[str, str]:
    """Detect actual image format and MIME type from magic bytes."""
    if len(data) < 12:
        return "UNKNOWN", "application/octet-stream"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG", "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG", "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP", "image/webp"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF", "image/gif"
    return "UNKNOWN", "application/octet-stream"


def _check_trailing_data(data: bytes, fmt: str) -> tuple[bool, int]:
    """Check for suspicious bytes appended after the valid image EOF marker."""
    if fmt == "JPEG":
        idx = data.rfind(b"\xff\xd9")
        if idx != -1:
            trailing = len(data) - (idx + 2)
            return trailing > 16, max(0, trailing)
    elif fmt == "PNG":
        idx = data.rfind(b"IEND")
        if idx != -1:
            # IEND chunk has 4 bytes 'IEND' + 4 bytes CRC
            end_pos = idx + 8
            trailing = len(data) - end_pos
            return trailing > 0, max(0, trailing)
    elif fmt == "WEBP":
        if len(data) >= 8:
            riff_size = struct.unpack("<I", data[4:8])[0] + 8
            trailing = len(data) - riff_size
            return trailing > 4, max(0, trailing)
    elif fmt == "GIF":
        idx = data.rfind(b"\x3b")
        if idx != -1:
            trailing = len(data) - (idx + 1)
            return trailing > 8, max(0, trailing)
    return False, 0


def _scan_embedded_signatures(data: bytes) -> list[str]:
    """Check raw bytes for embedded script or polyglot executable/archive signatures."""
    hits = []
    lower_sample = data.lower()
    patterns = [
        (b"<script", "Embedded <script> tag detected"),
        (b"<?php", "Embedded PHP tag (<?php) detected"),
        (b"eval(", "Suspicious eval() pattern detected"),
        (b"powershell", "Suspicious PowerShell reference detected"),
        (b"pk\x03\x04", "Embedded ZIP archive signature (PK\\x03\\x04) detected"),
        (b"%pdf-", "Embedded PDF header (%PDF-) detected"),
    ]
    for sig, desc in patterns:
        if sig in lower_sample:
            hits.append(desc)
    # Check PE/ELF only outside normal header if appended
    if b"MZ\x90\x00" in data[16:]:
        hits.append("Embedded Windows PE executable signature detected")
    if b"\x7fELF" in data[16:]:
        hits.append("Embedded ELF executable signature detected")
    return hits


def _extract_exif_summary(img: Image.Image) -> dict:
    """Extract EXIF metadata safely without exposing raw GPS coordinates."""
    summary = {
        "has_exif": False,
        "gps_present": False,
        "camera_make": None,
        "camera_model": None,
        "software": None,
        "date_time": None,
        "tag_count": 0,
        "suspicious_tags": [],
    }
    try:
        exif = img.getexif()
        if not exif:
            return summary
        summary["has_exif"] = True
        summary["tag_count"] = len(exif)

        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if tag_name == "GPSInfo" or tag_id == 34853:
                summary["gps_present"] = True
                continue
            val_str = str(value)
            if len(val_str) > 8192:
                summary["suspicious_tags"].append(f"Oversized EXIF tag '{tag_name}' ({len(val_str)} chars)")
            if re.search(r"(<script|<\?php|eval\(|powershell)", val_str, re.I):
                summary["suspicious_tags"].append(f"Suspicious payload in EXIF tag '{tag_name}'")

            if tag_name == "Make":
                summary["camera_make"] = val_str[:80]
            elif tag_name == "Model":
                summary["camera_model"] = val_str[:80]
            elif tag_name == "Software":
                summary["software"] = val_str[:80]
            elif tag_name in ("DateTime", "DateTimeOriginal"):
                summary["date_time"] = val_str[:40]
    except Exception:
        pass

    # Also check PNG text chunks or info dict for suspicious strings
    for k, v in (img.info or {}).items():
        if isinstance(v, (str, bytes)):
            v_str = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else v
            if re.search(r"(<script|<\?php|eval\()", v_str, re.I):
                summary["suspicious_tags"].append(f"Suspicious payload in metadata field '{k}'")
    return summary


def _run_optional_clamav(file_path: str) -> tuple[bool, Optional[str], str]:
    """Run ClamAV clamscan if installed on host; never pretend if not configured."""
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return False, None, "ClamAV not installed/configured on host"
    try:
        proc = subprocess.run(
            [clamscan, "--no-summary", file_path],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0:
            return True, None, "ClamAV scan clean (0 threats)"
        if proc.returncode == 1:
            return True, proc.stdout.strip() or "ClamAV detected threat", "ClamAV: THREAT DETECTED"
        return True, None, f"ClamAV returned code {proc.returncode}"
    except Exception as exc:
        return False, None, f"ClamAV execution error: {type(exc).__name__}"


def _analyze_image_bytes(
    data: bytes,
    filename: str,
    declared_mime: Optional[str],
    temp_path: str,
) -> dict:
    """Perform full A-E image security analysis and compute transparent risk score."""
    sha256_hash = hashlib.sha256(data).hexdigest()
    file_size = len(data)
    ext = os.path.splitext(filename)[1].lower()

    detected_format, actual_mime = _detect_magic_format(data)
    checks = []
    findings = []
    score = 100
    score_reasons = []
    confirmed_threat = False

    # A. File Integrity & Format Check
    if detected_format not in ALLOWED_FORMATS:
        score -= 40
        score_reasons.append("-40: Invalid or unsupported file signature (not JPG/PNG/WEBP/GIF)")
        findings.append({
            "category": "File Integrity",
            "severity": "high",
            "title": "Invalid Image Signature",
            "detail": f"File magic bytes do not match a valid JPG, PNG, WEBP, or GIF header.",
        })
        checks.append({"name": "File Signature", "status": "FAIL", "detail": "Unrecognized magic bytes"})
    else:
        checks.append({"name": "File Signature", "status": "PASS", "detail": f"Verified {detected_format} header"})

    # Extension & MIME consistency
    ext_expected = {
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".png": "PNG",
        ".webp": "WEBP",
        ".gif": "GIF",
    }.get(ext)
    mismatch = (ext_expected and detected_format != "UNKNOWN" and ext_expected != detected_format) or (
        declared_mime and actual_mime != "application/octet-stream" and declared_mime.lower() not in (actual_mime, "image/jpg")
        and declared_mime.startswith("image/")
    )
    if mismatch:
        score -= 15
        score_reasons.append(f"-15: Extension/MIME mismatch (ext={ext or 'none'}, actual={detected_format})")
        findings.append({
            "category": "Security Check",
            "severity": "medium",
            "title": "Extension / MIME Type Mismatch",
            "detail": f"Declared extension '{ext}' or MIME '{declared_mime}' does not match actual {detected_format} signature.",
        })
        checks.append({"name": "MIME & Extension Match", "status": "WARN", "detail": f"Mismatch with {detected_format}"})
    else:
        checks.append({"name": "MIME & Extension Match", "status": "PASS", "detail": "Consistent with file signature"})

    # Safe Image Decoding + Visual Analysis
    width, height = None, None
    thumbnail_b64 = None
    exif_summary = {"has_exif": False, "gps_present": False, "suspicious_tags": []}
    is_corrupted = False

    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
        with Image.open(io.BytesIO(data)) as img:
            img.load()
            width, height = img.size
            exif_summary = _extract_exif_summary(img)

            # Generate safe metadata-stripped thumbnail
            thumb = img.copy()
            thumb.thumbnail((160, 160))
            if thumb.mode not in ("RGB", "RGBA"):
                thumb = thumb.convert("RGB")
            buf = io.BytesIO()
            thumb.save(buf, format="PNG")
            thumbnail_b64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

        checks.append({"name": "Safe Image Decode", "status": "PASS", "detail": f"Decoded cleanly ({width}x{height})"})
    except Image.DecompressionBombError:
        is_corrupted = True
        score -= 35
        score_reasons.append("-35: Exceeded safe pixel limit (potential decompression bomb)")
        findings.append({
            "category": "Visual Analysis",
            "severity": "high",
            "title": "Decompression Bomb Risk",
            "detail": "Image pixel count exceeds 25,000,000 safe decoding threshold.",
        })
        checks.append({"name": "Safe Image Decode", "status": "FAIL", "detail": "Exceeded 25MP decompression limit"})
    except Exception as exc:
        is_corrupted = True
        score -= 35
        score_reasons.append("-35: Corrupted or malformed image structure")
        findings.append({
            "category": "File Integrity",
            "severity": "high",
            "title": "Corrupted / Malformed Image",
            "detail": f"Safe decoder rejected the file ({type(exc).__name__}).",
        })
        checks.append({"name": "Safe Image Decode", "status": "FAIL", "detail": "Image stream corrupted or invalid"})

    # Dimension bounds check
    if width and height and (width > MAX_DIMENSION_PX or height > MAX_DIMENSION_PX):
        score -= 10
        score_reasons.append(f"-10: Unusually large dimensions ({width}x{height} > {MAX_DIMENSION_PX}px)")
        findings.append({
            "category": "Visual Analysis",
            "severity": "low",
            "title": "Unusually Large Dimensions",
            "detail": f"Image dimensions {width}x{height}px exceed {MAX_DIMENSION_PX}px.",
        })
        checks.append({"name": "Dimension Bounds", "status": "WARN", "detail": f"{width}x{height}px exceeds {MAX_DIMENSION_PX}px"})
    elif width and height:
        checks.append({"name": "Dimension Bounds", "status": "PASS", "detail": f"{width}x{height}px within normal bounds"})

    # B. Metadata Analysis
    if exif_summary.get("gps_present"):
        score -= 10
        score_reasons.append("-10: Embedded GPS location metadata detected (privacy risk)")
        findings.append({
            "category": "Metadata Privacy",
            "severity": "medium",
            "title": "GPS Location Metadata Present",
            "detail": "EXIF GPS IFD detected. Coordinates are redacted from reports to protect privacy.",
        })
        checks.append({"name": "GPS Privacy Check", "status": "WARN", "detail": "GPS metadata present (redacted)"})
    else:
        checks.append({"name": "GPS Privacy Check", "status": "PASS", "detail": "No GPS coordinates found"})

    if exif_summary.get("suspicious_tags"):
        score -= 15
        score_reasons.append("-15: Suspicious or oversized EXIF/metadata tags detected")
        for tag_msg in exif_summary["suspicious_tags"]:
            findings.append({
                "category": "Metadata Security",
                "severity": "medium",
                "title": "Suspicious Metadata Tag",
                "detail": tag_msg,
            })
        checks.append({"name": "Metadata Integrity", "status": "WARN", "detail": "Suspicious metadata detected"})
    else:
        checks.append({"name": "Metadata Integrity", "status": "PASS", "detail": "No suspicious metadata tags"})

    # C. Trailing / Appended Data & Embedded Signatures
    has_trailing, trailing_bytes = _check_trailing_data(data, detected_format)
    if has_trailing:
        score -= 20
        score_reasons.append(f"-20: {trailing_bytes} bytes of appended data after image EOF marker")
        findings.append({
            "category": "Structure Inspection",
            "severity": "medium",
            "title": "Suspicious Appended Data",
            "detail": f"Detected {trailing_bytes} extra bytes after the {detected_format} end-of-file marker.",
        })
        checks.append({"name": "EOF / Trailing Data", "status": "WARN", "detail": f"{trailing_bytes} trailing bytes"})
    else:
        checks.append({"name": "EOF / Trailing Data", "status": "PASS", "detail": "No unexpected trailing data"})

    sig_hits = _scan_embedded_signatures(data)
    if sig_hits:
        score -= 25
        score_reasons.append(f"-25: Embedded script/polyglot signature(s) found ({len(sig_hits)})")
        for hit in sig_hits:
            findings.append({
                "category": "Static Threat Inspection",
                "severity": "high",
                "title": "Embedded Polyglot / Script Indicator",
                "detail": hit,
            })
        checks.append({"name": "Polyglot / Script Scan", "status": "WARN", "detail": f"{len(sig_hits)} indicator(s)"})
    else:
        checks.append({"name": "Polyglot / Script Scan", "status": "PASS", "detail": "No embedded script/archive signatures"})

    # E. Optional ClamAV engine
    clam_configured, clam_threat, clam_msg = _run_optional_clamav(temp_path)
    if clam_threat:
        confirmed_threat = True
        score = min(score, 10)
        score_reasons.append("-90: ClamAV engine detected a confirmed threat")
        findings.append({
            "category": "Malware Engine (ClamAV)",
            "severity": "critical",
            "title": "Confirmed Threat Detected",
            "detail": clam_threat,
        })
        checks.append({"name": "ClamAV Scan", "status": "FAIL", "detail": clam_threat})
    else:
        checks.append({
            "name": "ClamAV Scan",
            "status": "PASS" if clam_configured else "INFO",
            "detail": clam_msg,
        })

    score = max(0, min(100, score))
    if confirmed_threat:
        risk_category = "RED"
    elif score < 80 or len(findings) > 0:
        risk_category = "YELLOW"
    else:
        risk_category = "GREEN"
        score_reasons.append("No deductions: all static, integrity, and metadata checks passed")

    return {
        "sha256_hash": sha256_hash,
        "file_format": detected_format if detected_format != "UNKNOWN" else (ext.lstrip(".").upper() or "UNKNOWN"),
        "mime_type": actual_mime,
        "file_size": file_size,
        "width": width,
        "height": height,
        "thumbnail_b64": thumbnail_b64,
        "exif_json": exif_summary,
        "security_checks_json": checks,
        "findings_json": findings,
        "risk_score": score,
        "risk_category": risk_category,
        "score_reasons_json": score_reasons,
        "clamav_status": clam_msg,
    }


@router.post("/upload", response_model=ImageUploadResponse)
async def upload_image(
    request: Request,
    file: UploadFile = File(...),
):
    """Validate and stage an image in secure randomized temporary storage before scanning."""
    _check_rate_limit(request)
    _cleanup_stale_uploads()

    safe_name = _sanitize_filename(file.filename)
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(contents) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image exceeds 10 MB size limit")

    detected_format, actual_mime = _detect_magic_format(contents)
    ext = os.path.splitext(safe_name)[1].lower()
    if detected_format not in ALLOWED_FORMATS and ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Allowed formats: JPG, JPEG, PNG, WEBP, GIF.",
        )

    upload_id = uuid.uuid4().hex
    temp_path = os.path.join(TEMP_DIR, f"{upload_id}.bin")
    with open(temp_path, "wb") as f:
        f.write(contents)

    sha256_hash = hashlib.sha256(contents).hexdigest()
    _pending_uploads[upload_id] = {
        "path": temp_path,
        "filename": safe_name,
        "declared_mime": file.content_type,
        "detected_format": detected_format,
        "actual_mime": actual_mime,
        "file_size": len(contents),
        "sha256_hash": sha256_hash,
        "created_at": time.time(),
    }

    return ImageUploadResponse(
        upload_id=upload_id,
        filename=safe_name,
        file_size=len(contents),
        detected_format=detected_format,
        mime_type=actual_mime,
        sha256_hash=sha256_hash,
    )


@router.post("/scan", response_model=ImageScanResponse, status_code=201)
async def scan_image(
    request: Request,
    upload_id: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    """Run full image security analysis from a staged upload_id or direct file upload, then delete temp file."""
    _check_rate_limit(request)
    temp_path = None
    filename = "uploaded_image"
    declared_mime = None
    data = None

    try:
        if upload_id:
            meta = _pending_uploads.pop(upload_id, None)
            if not meta or not os.path.exists(meta["path"]):
                raise HTTPException(status_code=404, detail="Staged upload not found or expired")
            temp_path = meta["path"]
            filename = meta["filename"]
            declared_mime = meta["declared_mime"]
            with open(temp_path, "rb") as f:
                data = f.read()
        elif file is not None:
            filename = _sanitize_filename(file.filename)
            declared_mime = file.content_type
            data = await file.read()
            if not data:
                raise HTTPException(status_code=400, detail="Uploaded file is empty")
            if len(data) > MAX_IMAGE_BYTES:
                raise HTTPException(status_code=413, detail="Image exceeds 10 MB size limit")
            temp_path = os.path.join(TEMP_DIR, f"{uuid.uuid4().hex}.bin")
            with open(temp_path, "wb") as f:
                f.write(data)
        else:
            raise HTTPException(status_code=400, detail="Provide either upload_id or file")

        analysis = _analyze_image_bytes(data, filename, declared_mime, temp_path)

        scan_record = models.ImageScan(
            user_id=user.id if user else None,
            filename=filename,
            sha256_hash=analysis["sha256_hash"],
            file_format=analysis["file_format"],
            mime_type=analysis["mime_type"],
            file_size=analysis["file_size"],
            width=analysis["width"],
            height=analysis["height"],
            thumbnail_b64=analysis["thumbnail_b64"],
            exif_json=analysis["exif_json"],
            security_checks_json=analysis["security_checks_json"],
            findings_json=analysis["findings_json"],
            risk_score=analysis["risk_score"],
            risk_category=analysis["risk_category"],
            score_reasons_json=analysis["score_reasons_json"],
            scan_status="completed",
            clamav_status=analysis["clamav_status"],
        )
        db.add(scan_record)

        # Log activity & alert if YELLOW/RED
        level = "ALERT" if analysis["risk_category"] == "RED" else ("WARN" if analysis["risk_category"] == "YELLOW" else "SAFE")
        db.add(
            models.ActivityLog(
                user_id=user.id if user else None,
                level=level,
                message=f"Image Scan ({analysis['risk_category']}): {filename}",
                subtext=f"Score: {analysis['risk_score']}/100 | {analysis['file_format']} | SHA-256: {analysis['sha256_hash'][:12]}...",
                source="image_scanner",
            )
        )
        if analysis["risk_category"] in ("YELLOW", "RED"):
            db.add(
                models.ThreatAlert(
                    severity="critical" if analysis["risk_category"] == "RED" else "medium",
                    title=f"Image Security Finding: {filename}",
                    detail=f"Category: {analysis['risk_category']} | Score: {analysis['risk_score']}/100 | {len(analysis['findings_json'])} indicator(s)",
                    source="image_scanner",
                )
            )

        db.commit()
        db.refresh(scan_record)
        return ImageScanResponse.model_validate(scan_record)
    finally:
        # Always delete temporary uploaded image after processing
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.get("/history", response_model=list[ImageScanResponse])
def get_image_scan_history(
    search: Optional[str] = None,
    risk_category: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    query = db.query(models.ImageScan)
    if user:
        query = query.filter((models.ImageScan.user_id == user.id) | (models.ImageScan.user_id.is_(None)))
    else:
        query = query.filter(models.ImageScan.user_id.is_(None))

    if search:
        query = query.filter(
            models.ImageScan.filename.ilike(f"%{search}%")
            | models.ImageScan.sha256_hash.ilike(f"%{search}%")
        )
    if risk_category and risk_category in ("GREEN", "YELLOW", "RED"):
        query = query.filter(models.ImageScan.risk_category == risk_category)
    if date_from:
        try:
            dt_from = datetime.datetime.fromisoformat(date_from)
            query = query.filter(models.ImageScan.created_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.datetime.fromisoformat(date_to) + datetime.timedelta(days=1)
            query = query.filter(models.ImageScan.created_at < dt_to)
        except ValueError:
            pass

    rows = query.order_by(desc(models.ImageScan.created_at)).limit(limit).all()
    return [ImageScanResponse.model_validate(r) for r in rows]


def _get_authorized_scan(scan_id: int, db: Session, user: Optional[models.User]) -> models.ImageScan:
    scan = db.query(models.ImageScan).filter(models.ImageScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Image scan not found")
    if scan.user_id is not None and (user is None or scan.user_id != user.id):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan record")
    return scan


@router.get("/history/{scan_id}", response_model=ImageScanResponse)
def get_image_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    scan = _get_authorized_scan(scan_id, db, user)
    return ImageScanResponse.model_validate(scan)


@router.delete("/history/{scan_id}")
def delete_image_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    scan = _get_authorized_scan(scan_id, db, user)
    db.delete(scan)
    db.commit()
    return {"deleted": True, "id": scan_id}


@router.get("/report/{scan_id}")
def download_image_report_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    """Generate and stream a downloadable PDF security report for a scan."""
    scan = _get_authorized_scan(scan_id, db, user)

    pdf_buf = io.BytesIO()
    doc = SimpleDocTemplate(pdf_buf, pagesize=letter, rightMargin=48, leftMargin=48, topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("SecTitle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#1e3a8a"))
    h2_style = ParagraphStyle("SecH2", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#0f172a"), spaceBefore=10)
    body_style = ParagraphStyle("SecBody", parent=styles["Normal"], fontSize=9.5, leading=13)

    elements = [
        Paragraph("SecureX / RedactZero — Image Security Scan Report", title_style),
        Spacer(1, 6),
        Paragraph(f"Scan ID: #{scan.id} &nbsp;|&nbsp; Timestamp: {scan.created_at.isoformat()} UTC", body_style),
        Spacer(1, 12),
    ]

    # Summary Table
    summary_data = [
        ["Filename", scan.filename],
        ["SHA-256 Hash", scan.sha256_hash],
        ["Format / MIME", f"{scan.file_format} ({scan.mime_type or 'n/a'})"],
        ["File Size", f"{scan.file_size:,} bytes"],
        ["Dimensions", f"{scan.width} x {scan.height} px" if scan.width and scan.height else "N/A"],
        ["Risk Score", f"{scan.risk_score} / 100 ({scan.risk_category})"],
        ["ClamAV Engine", scan.clamav_status or "Not configured"],
    ]
    t = Table(summary_data, colWidths=[1.6 * inch, 5.1 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.extend([t, Spacer(1, 12)])

    # Score Reasons
    elements.append(Paragraph("Score Calculation Breakdown", h2_style))
    for reason in (scan.score_reasons_json or []):
        elements.append(Paragraph(f"• {xml_escape(str(reason))}", body_style))

    # Security Checks Table
    elements.append(Paragraph("Individual Security Checks", h2_style))
    check_rows = [["Check", "Status", "Details"]]
    for chk in (scan.security_checks_json or []):
        check_rows.append([chk.get("name", ""), chk.get("status", ""), chk.get("detail", "")])
    ct = Table(check_rows, colWidths=[1.9 * inch, 0.9 * inch, 3.9 * inch])
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.extend([ct, Spacer(1, 12)])

    # Findings
    elements.append(Paragraph("Security & Metadata Findings", h2_style))
    findings = scan.findings_json or []
    if not findings:
        elements.append(Paragraph("No suspicious indicators detected by static, integrity, or metadata checks.", body_style))
    else:
        for f in findings:
            sev = xml_escape(str(f.get("severity", "")).upper())
            title = xml_escape(str(f.get("title", "")))
            detail = xml_escape(str(f.get("detail", "")))
            elements.append(Paragraph(f"<b>[{sev}] {title}</b>: {detail}", body_style))

    elements.append(Spacer(1, 14))
    elements.append(Paragraph("Disclaimer", h2_style))
    elements.append(Paragraph(
        "This report reflects static file-header, structural, metadata, and safe decoding inspections. "
        "Unless an external antivirus engine (such as ClamAV) is installed and actively configured on the host, "
        "a GREEN result indicates that no suspicious structural or metadata indicators were found — it does not "
        "guarantee the absence of all zero-day or steganographic threats.",
        body_style,
    ))

    doc.build(elements)
    pdf_buf.seek(0)
    return StreamingResponse(
        pdf_buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="securex_image_report_{scan.id}.pdf"'},
    )
