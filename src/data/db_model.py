from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime

Base = declarative_base()

class DeviceFeature(Base):
    __tablename__ = 'device_features'
    id = Column(Integer, primary_key=True)
    brand = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    mac_prefix = Column(String(20))
    web_header = Column(Text)
    snmp_identifier = Column(String(100))
    management_port = Column(Integer, default=80)
    default_username = Column(String(50))
    default_password = Column(String(50))
    supported = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class FirmwareCompatibility(Base):
    __tablename__ = 'firmware_compatibility'
    id = Column(Integer, primary_key=True)
    brand = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    firmware_type = Column(String(50))
    min_version = Column(String(20))
    max_version = Column(String(20))
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class BackupRecord(Base):
    __tablename__ = 'backup_records'
    id = Column(Integer, primary_key=True)
    device_brand = Column(String(50), nullable=False)
    device_model = Column(String(100), nullable=False)
    firmware_version = Column(String(50))
    backup_path = Column(String(255), nullable=False)
    backup_date = Column(DateTime, default=datetime.datetime.utcnow)
    md5_sum = Column(String(32))
    size = Column(Integer)
    notes = Column(Text)

class UserConfig(Base):
    __tablename__ = 'user_configs'
    id = Column(Integer, primary_key=True)
    key = Column(String(50), unique=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

def init_db():
    engine = create_engine('sqlite:///router_flasher.db')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()
