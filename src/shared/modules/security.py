from src.shared.database import db

class SecurityLog(db.Model):
    __tablename__ = "security_logs"
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    source_ip = db.Column(db.String(50), nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    details = db.Column(db.JSON, nullable=False)
    severity = db.Column(db.Integer, nullable=False)
    
    def __repr__(self):
        return f"<SecurityLog {self.id} {self.event_type}>"