from sqlalchemy import Column, Integer, String, DateTime, LargeBinary, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()


class EmailParameters(Base):
    __tablename__ = "tbl_EMailParameters"

    id = Column(Integer, primary_key=True, autoincrement=True)
    SMTPServer = Column(String(255))
    SMTPPort = Column(Integer)
    SMTPAccountName = Column(String(255))
    SMTPPassword = Column(String(255))
    SMTPMailId = Column(String(255))
    ApplicationName = Column(String(255))
    SMTPSSLFlag = Column(String(1))
    ParamCode = Column(String(50))
    IsActive = Column(String(1), default="Y")


class DigitalEmailDetails(Base):
    __tablename__ = "Digital_Emaildetails"

    dd_srno = Column(Integer, primary_key=True, autoincrement=True)
    dd_document = Column(LargeBinary)
    dd_filename = Column(String(255))
    dd_toEmailid = Column(String(500), nullable=False)
    dd_ccEmailid = Column(String(500))
    dd_subject = Column(String(500), nullable=False)
    dd_bodyText = Column(Text, nullable=False)
    dd_SendFlag = Column(String(1), default="N")
    dd_EmailParamCode = Column(String(50))
    dd_RetryCount = Column(Integer, default=0)
    dd_SentDate = Column(DateTime)
    dd_BounceReason = Column(String(500))
    dd_LastRetryDate = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())