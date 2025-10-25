from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, validator


class EventType(str, Enum):
    """보안 이벤트 타입"""
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    SUSPICIOUS_LOGIN = "suspicious_login"
    SQL_INJECTION = "sql_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FILE_ACCESS = "file_access"
    NETWORK_ANOMALY = "network_anomaly"
    BOTNET_ACTIVITY = "botnet_activity"
    MALWARE_DETECTED = "malware_detected"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """위협 심각도 레벨"""
    CRITICAL = "critical"  # 즉각 대응 필요
    HIGH = "high"          # 높은 우선순위
    MEDIUM = "medium"      # 중간 우선순위
    LOW = "low"           # 낮은 우선순위
    INFO = "info"         # 정보성


class LogEvent(BaseModel):
    """입력 로그 이벤트 모델"""
    event_type: str = Field(..., description="이벤트 타입")
    source_ip: Optional[str] = Field(None, description="출발지 IP")
    destination_ip: Optional[str] = Field(None, description="목적지 IP")
    username: Optional[str] = Field(None, description="사용자명")
    count: Optional[int] = Field(1, description="이벤트 발생 횟수", ge=1)
    description: Optional[str] = Field(None, description="이벤트 설명")
    raw_log: Optional[str] = Field(None, description="원본 로그 데이터")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="추가 메타데이터")

    class Config:
        json_schema_extra = {
            "example": {
                "event_type": "login_failed",
                "source_ip": "192.168.1.100",
                "username": "admin",
                "count": 5,
                "description": "Multiple failed login attempts"
            }
        }


class NormalizedLog(BaseModel):
    """정규화된 로그 데이터 모델"""
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="이벤트 발생 시각")
    event_type: EventType = Field(..., description="정규화된 이벤트 타입")
    severity: SeverityLevel = Field(default=SeverityLevel.INFO, description="심각도")
    source_ip: Optional[str] = Field(None, description="출발지 IP 주소")
    destination_ip: Optional[str] = Field(None, description="목적지 IP 주소")
    username: Optional[str] = Field(None, description="관련 사용자명")
    count: int = Field(1, description="이벤트 발생 횟수", ge=1)
    description: str = Field(..., description="이벤트 설명")
    raw_log: Optional[str] = Field(None, description="원본 로그 데이터")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="추가 메타데이터")
    is_threat: bool = Field(False, description="위협 여부")
    threat_details: Optional[str] = Field(None, description="위협 상세 정보")

    @validator('event_type', pre=True)
    def normalize_event_type(cls, v):
        """이벤트 타입 정규화"""
        if isinstance(v, str):
            # 문자열을 EventType Enum으로 변환
            try:
                return EventType(v.lower())
            except ValueError:
                return EventType.UNKNOWN
        return v

    @validator('severity', pre=True)
    def ensure_severity(cls, v):
        """심각도 검증"""
        if isinstance(v, str):
            try:
                return SeverityLevel(v.lower())
            except ValueError:
                return SeverityLevel.INFO
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2025-10-25T10:30:00Z",
                "event_type": "login_failed",
                "severity": "medium",
                "source_ip": "192.168.1.100",
                "username": "admin",
                "count": 5,
                "description": "Multiple failed login attempts detected",
                "is_threat": True,
                "threat_details": "Brute force attack suspected"
            }
        }


class IncidentStatus(str, Enum):
    """인시던트 상태"""
    DETECTED = "detected"       # 탐지됨
    ANALYZING = "analyzing"     # 분석 중
    IN_PROGRESS = "in_progress" # 처리 중
    RESOLVED = "resolved"       # 해결됨
    FALSE_POSITIVE = "false_positive"  # 오탐


class Incident(BaseModel):
    """보안 인시던트 모델"""
    id: str = Field(..., description="인시던트 ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="발생 시각")
    event_type: EventType = Field(..., description="이벤트 타입")
    severity: SeverityLevel = Field(..., description="심각도")
    status: IncidentStatus = Field(default=IncidentStatus.DETECTED, description="처리 상태")
    title: str = Field(..., description="인시던트 제목")
    description: str = Field(..., description="상세 설명")
    source_ip: Optional[str] = Field(None, description="공격 출발지 IP")
    affected_user: Optional[str] = Field(None, description="영향받은 사용자")
    detection_count: int = Field(1, description="탐지 횟수")
    first_seen: datetime = Field(default_factory=datetime.utcnow, description="최초 탐지 시각")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="최근 탐지 시각")
    analyst_notes: Optional[str] = Field(None, description="분석가 메모")
    resolution: Optional[str] = Field(None, description="해결 방법")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "INC-20251025-001",
                "event_type": "login_failed",
                "severity": "high",
                "status": "analyzing",
                "title": "Brute Force Attack from 192.168.1.100",
                "description": "Multiple failed login attempts detected",
                "source_ip": "192.168.1.100",
                "affected_user": "admin",
                "detection_count": 15
            }
        }


class DashboardStats(BaseModel):
    """대시보드 통계 모델"""
    total_events: int = Field(0, description="총 이벤트 수")
    total_threats: int = Field(0, description="총 위협 탐지 수")
    critical_incidents: int = Field(0, description="Critical 인시던트 수")
    high_incidents: int = Field(0, description="High 인시던트 수")
    medium_incidents: int = Field(0, description="Medium 인시던트 수")
    low_incidents: int = Field(0, description="Low 인시던트 수")
    active_incidents: int = Field(0, description="처리 중인 인시던트 수")
    resolved_incidents: int = Field(0, description="해결된 인시던트 수")
    top_attack_ips: list[str] = Field(default_factory=list, description="상위 공격 IP 목록")
    top_event_types: Dict[str, int] = Field(default_factory=dict, description="이벤트 타입별 통계")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="통계 생성 시각")

    class Config:
        json_schema_extra = {
            "example": {
                "total_events": 1523,
                "total_threats": 47,
                "critical_incidents": 3,
                "high_incidents": 12,
                "medium_incidents": 25,
                "low_incidents": 7,
                "active_incidents": 8,
                "resolved_incidents": 39,
                "top_attack_ips": ["192.168.1.100", "10.0.0.50"],
                "top_event_types": {
                    "login_failed": 142,
                    "sql_injection": 23,
                    "privilege_escalation": 12
                }
            }
        }