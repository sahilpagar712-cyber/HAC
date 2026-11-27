"""Security scan endpoints: create scan record, list history, get by ID, file upload with static analysis."""

import hashlib
import math
import re
from collections import Counter
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
import models
from auth import get_current_user
from schemas import ScanCreateRequest, ScanResponse

router = APIRouter(prefix="/api/scans", tags=["Security Scans"])

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

# Safe static PII patterns for server-side file analysis
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _luhn_check(digits: str) -> bool:
    if len(digits) < 13 or len(digits) > 19 or not digits.isdigit():
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def _detect_file_signature(data: bytes, filename: str) -> str:
    if data.startswith(b"%PDF"):
        return "PDF Document"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG Image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG Image"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP / Office Archive"
    if data.startswith(b"MZ"):
        return "Windows PE Executable (MZ)"
    if data.startswith(b"\x7fELF"):
        return "ELF Executable"
    if filename.lower().endswith(".csv"):
        return "CSV Text"
    if filename.lower().endswith(".json"):
        return "JSON Text"
    try:
        data[:4096].decode("utf-8")
        return "UTF-8 Plain Text"
    except UnicodeDecodeError:
        return "Binary Data"


@router.post("/", response_model=ScanResponse, status_code=201)
def create_scan(
    req: ScanCreateRequest,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    scan = models.SecurityScan(
        user_id=user.id if user else None,
        filename=req.filename,
        file_hash_sha256=req.file_hash_sha256,
        file_size=req.file_size,
        scan_type=req.scan_type,
        status="completed",
        total_pii_found=req.total_pii_found,
        total_redacted=req.total_redacted,
        luhn_rejected=req.luhn_rejected,
        redaction_mode=req.redaction_mode,
        results_json=req.results_json,
    )
    db.add(scan)

    if req.results_json and isinstance(req.results_json, list):
        for item in req.results_json[:500]:
            sr = models.ScanResult(
                scan=scan,
                pii_type=item.get("type", "UNKNOWN"),
                matched_value=item.get("value", ""),
                start_offset=item.get("start"),
                end_offset=item.get("end"),
                validation_method=item.get("validationMethod", ""),
                is_valid=item.get("isValid", True),
            )
            db.add(sr)

    log = models.ActivityLog(
        user_id=user.id if user else None,
        level="SAFE",
        message=f"Scan completed: {req.total_pii_found} PII found",
        subtext=f"{req.filename or 'buffer'} | {req.total_redacted} redacted, {req.luhn_rejected} Luhn rejected",
        source="scanner",
    )
    db.add(log)
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.post("/upload", response_model=ScanResponse, status_code=201)
async def upload_and_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    """Accept a file upload, compute SHA-256 hash, perform safe static analysis, and store results."""
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 10 MB limit")

    sha256_hash = hashlib.sha256(contents).hexdigest()
    file_sig = _detect_file_signature(contents, file.filename or "")
    entropy = _shannon_entropy(contents)

    findings = []
    luhn_rejected = 0
    is_executable = file_sig.endswith("(MZ)") or file_sig == "ELF Executable"

    # Perform static text PII scan if UTF-8 decodable
    text_content = None
    try:
        text_content = contents.decode("utf-8")
    except UnicodeDecodeError:
        text_content = None

    if text_content is not None:
        for m in EMAIL_RE.finditer(text_content):
            findings.append({"type": "EMAIL", "start": m.start(), "end": m.end(), "validationMethod": "RFC Email Regex", "isValid": True})
        for m in IPV4_RE.finditer(text_content):
            findings.append({"type": "IP_ADDRESS", "start": m.start(), "end": m.end(), "validationMethod": "IPv4 Octet Bounds", "isValid": True})
        for m in PAN_RE.finditer(text_content):
            findings.append({"type": "PAN", "start": m.start(), "end": m.end(), "validationMethod": "PAN Format Regex", "isValid": True})
        for m in CC_CANDIDATE_RE.finditer(text_content):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19:
                if _luhn_check(digits):
                    findings.append({"type": "CREDIT_CARD", "start": m.start(), "end": m.end(), "validationMethod": "Luhn Mod-10", "isValid": True})
                else:
                    luhn_rejected += 1

    static_analysis = {
        "file_signature": file_sig,
        "shannon_entropy": entropy,
        "is_executable": is_executable,
        "line_count": len(text_content.splitlines()) if text_content is not None else 0,
        "findings_count": len(findings),
        "luhn_rejected": luhn_rejected,
        "findings_summary": {
            "EMAIL": sum(1 for f in findings if f["type"] == "EMAIL"),
            "IP_ADDRESS": sum(1 for f in findings if f["type"] == "IP_ADDRESS"),
            "PAN": sum(1 for f in findings if f["type"] == "PAN"),
            "CREDIT_CARD": sum(1 for f in findings if f["type"] == "CREDIT_CARD"),
        },
    }

    scan = models.SecurityScan(
        user_id=user.id if user else None,
        filename=file.filename,
        file_hash_sha256=sha256_hash,
        file_size=len(contents),
        scan_type="file_upload",
        status="completed",
        total_pii_found=len(findings),
        total_redacted=0,
        luhn_rejected=luhn_rejected,
        results_json=static_analysis,
    )
    db.add(scan)

    for f in findings[:200]:
        db.add(
            models.ScanResult(
                scan=scan,
                pii_type=f["type"],
                matched_value="[REDACTED_ON_SERVER]",
                start_offset=f["start"],
                end_offset=f["end"],
                validation_method=f["validationMethod"],
                is_valid=f["isValid"],
            )
        )

    if is_executable or len(findings) > 0:
        db.add(
            models.ThreatAlert(
                severity="high" if is_executable else "medium",
                title=f"Static Scan Alert: {file.filename}",
                detail=(
                    f"Executable binary detected ({file_sig})"
                    if is_executable
                    else f"{len(findings)} PII patterns detected in uploaded file ({file_sig})"
                ),
                source="file_scanner",
            )
        )

    log = models.ActivityLog(
        user_id=user.id if user else None,
        level="WARN" if (is_executable or len(findings) > 0) else "SAFE",
        message=f"Static file scan: {file.filename}",
        subtext=f"SHA-256: {sha256_hash[:16]}... | {file_sig} | {len(findings)} findings",
        source="scanner",
    )
    db.add(log)
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.get("/", response_model=list[ScanResponse])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user),
):
    query = db.query(models.SecurityScan)
    if user:
        query = query.filter(models.SecurityScan.user_id == user.id)
    return [
        ScanResponse.model_validate(s)
        for s in query.order_by(desc(models.SecurityScan.created_at)).offset(skip).limit(limit).all()
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.SecurityScan).filter(models.SecurityScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)
