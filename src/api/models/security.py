from sqlalchemy import Column, Integer, String, DateTime, JSON
from src.shared.database import Base

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(50), nullable=False)
    event_type = Column(String(100), nullable=False)
    details = Column(JSON, nullable=False)
    severity = Column(Integer, nullable=False)