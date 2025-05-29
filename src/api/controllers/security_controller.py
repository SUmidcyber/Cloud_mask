from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from src.api.models.security import SecurityLog
from src.shared.database import get_db
from datetime import datetime
import uuid

router = APIRouter()

@router.post("/logs/")
async def create_log(
    source_ip: str,
    event_type: str,
    details: dict,
    severity: int,
    db: Session = Depends(get_db)
):
    db_log = SecurityLog(
        timestamp=datetime.utcnow(),
        source_ip=source_ip,
        event_type=event_type,
        details=details,
        severity=severity
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

@router.get("/logs/", response_model=List[dict])
async def read_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).offset(skip).limit(limit).all()
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp,
            "source_ip": log.source_ip,
            "event_type": log.event_type,
            "severity": log.severity
        }
        for log in logs
    ]