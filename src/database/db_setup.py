import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()

class IncidentReport(Base):
    __tablename__ = 'incident_reports'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    title = Column(String(256), nullable=False, default="Untitled Incident")
    severity = Column(String(50), nullable=True)
    risk_score = Column(Float, nullable=True)
    email_data = Column(Text, nullable=True)
    ip_data = Column(Text, nullable=True)
    log_data = Column(Text, nullable=True)
    final_analysis = Column(Text, nullable=False)
    ioc_count = Column(Integer, default=0)
    status = Column(String(50), default="Open")

db_path = os.getenv('DATABASE_URL', 'sqlite:///./cybersec_agents.db')
engine = create_engine(db_path, echo=False)
SessionLocal = sessionmaker(bind=engine)

def init_db():
    Base.metadata.create_all(engine)
