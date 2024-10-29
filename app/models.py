# app/models.py
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey,LargeBinary,JSON
from sqlalchemy.ext.declarative import declarative_base
import datetime
import json

Base = declarative_base()


class CookieCredential(Base):
    """
    用于保存用户输入的Cookie凭据。
    """
    __tablename__ = 'cookie_credentials'

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    credential = Column(Text, nullable=False)
    permission = Column(String(50), nullable=False)
    user = Column(String(50), nullable=False)




class ProcessedMatch(Base):
    __tablename__ = 'processed_matches'
    
    id = Column(Integer, primary_key=True, index=True)
    matched_data = Column(Text, unique=True, nullable=False)
    pattern_description = Column(Text, nullable=False)
    response = Column(Text, nullable=True)  # 保留原始响应字段
    user_cookie_id = Column(Integer, ForeignKey('cookie_credentials.id'), nullable=True)
    is_vulnerable = Column(Integer, nullable=True, default=None)
    vulnerability_reason = Column(Text, nullable=True)
    responses = relationship("ResponseHistory", back_populates="processed_match")

class ResponseHistory(Base):
    __tablename__ = 'response_history'
    
    id = Column(Integer, primary_key=True, index=True)
    processed_match_id = Column(Integer, ForeignKey('processed_matches.id'), nullable=False)
    response = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    cookie_credential_id = Column(Integer, ForeignKey('cookie_credentials.id'), nullable=True)

    # 外键关系
    processed_match = relationship("ProcessedMatch", back_populates="responses")
    cookie_credential = relationship("CookieCredential")

class Pattern(Base):
    __tablename__ = 'patterns'

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    pattern = Column(Text, nullable=False, unique=True)  # 正则表达式
    description = Column(Text, nullable=True)  # 描述
    created_at = Column(DateTime, default=datetime.datetime.now)  # 创建时间


class JSFile(Base):
    __tablename__ = 'js_files'

    id = Column(Integer, primary_key=True, index=True)
    host = Column(String, index=True)
    path = Column(String)
    content = Column(LargeBinary)
    timestamp = Column(DateTime, default=datetime.datetime.now)

    # 新增的关系，用于关联多个API请求
    api_requests = relationship("APIRequest", back_populates="js_file")



class APIRequest(Base):
    __tablename__ = 'api_requests'

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(50), nullable=False)  # API 请求类型 (fetch, axios, XMLHttpRequest 等)
    url = Column(Text, nullable=False)  # API 请求的 URL
    method = Column(String(10), nullable=False, default='GET')  # HTTP 方法
    headers = Column(JSON, nullable=True)  # 请求头部信息，使用 JSON 存储
    body = Column(Text, nullable=True)  # 请求体，可以为空
    location_start_line = Column(Integer, nullable=True)  # 源代码中 API 调用的起始行
    location_start_column = Column(Integer, nullable=True)  # 源代码中 API 调用的起始列
    location_end_line = Column(Integer, nullable=True)  # 源代码中 API 调用的结束行
    location_end_column = Column(Integer, nullable=True)  # 源代码中 API 调用的结束列

    # 外键，关联到 JSFile 表
    js_file_id = Column(Integer, ForeignKey('js_files.id'), nullable=False)
    js_file = relationship('JSFile', back_populates='api_requests')