from graphene import Field, List, ObjectType, String, Int
from graphene_sqlalchemy import SQLAlchemyObjectType
from src.api.models.security import LogEntry
from src.shared.database import db_session
from datetime import datetime

class LogEntryType(SQLAlchemyObjectType):
    class Meta:
        model = LogEntry
        interfaces = (ObjectType,)
        use_connection = True

class SecurityQuery(ObjectType):
    logs = List(LogEntryType, 
                limit=Int(default_value=100),
                start_date=String(),
                end_date=String())
    
    def resolve_logs(self, info, limit=None, start_date=None, end_date=None):
        query = LogEntryType.get_query(info)
        
        if start_date:
            start = datetime.fromisoformat(start_date)
            query = query.filter(LogEntry.timestamp >= start)
        
        if end_date:
            end = datetime.fromisoformat(end_date)
            query = query.filter(LogEntry.timestamp <= end)
            
        return query.limit(limit).all()

class SecurityMutation(ObjectType):
    # Örnek mutasyonlar buraya gelecek
    pass

schema = graphene.Schema(
    query=SecurityQuery,
    mutation=SecurityMutation,
    auto_camelcase=False
)