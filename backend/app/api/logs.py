import json
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import Optional
from app.database.connection import get_db
from app.api.auth import get_current_user
from app.models.log_file import LogFile
from app.models.log_event import LogEvent
from app.schemas.log_file import LogFileResponse
from app.services.log_processor import LogProcessor
from app.config.settings import settings

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.post("/upload", response_model=LogFileResponse)
async def upload_log(
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    allowed_extensions = {".log", ".txt", ".csv"}
    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"File type '{ext}' not allowed. Use .log, .txt, or .csv")

    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")

    try:
        text_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text")

    log_file = LogFile(
        user_id=current_user.id,
        filename=file.filename,
        source_type=source_type,
        processing_status="processing",
    )
    db.add(log_file)
    db.commit()
    db.refresh(log_file)

    processor = LogProcessor(db)
    result = processor.process_upload(log_file, text_content, source_type)

    db.refresh(log_file)
    return LogFileResponse.model_validate(log_file)


@router.get("", response_model=list[LogFileResponse])
def list_logs(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    files = (
        db.query(LogFile)
        .filter(LogFile.user_id == current_user.id)
        .order_by(LogFile.uploaded_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [LogFileResponse.model_validate(f) for f in files]


@router.get("/{log_id}", response_model=LogFileResponse)
def get_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    log_file = (
        db.query(LogFile)
        .filter(LogFile.id == log_id, LogFile.user_id == current_user.id)
        .first()
    )
    if not log_file:
        raise HTTPException(status_code=404, detail="Log file not found")
    return LogFileResponse.model_validate(log_file)
