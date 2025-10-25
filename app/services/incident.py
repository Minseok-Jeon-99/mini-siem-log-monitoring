from datetime import datetime
from typing import Dict, List, Optional
from app.models.log import Incident, IncidentStatus, NormalizedLog, EventType, SeverityLevel


class IncidentManager:
    """보안 인시던트 관리 시스템"""

    def __init__(self):
        # 메모리 기반 인시던트 저장소 (실제로는 DB 사용 권장)
        self.incidents: Dict[str, Incident] = {}
        self.incident_counter = 0

    def _generate_incident_id(self) -> str:
        """인시던트 ID 생성"""
        self.incident_counter += 1
        today = datetime.utcnow().strftime("%Y%m%d")
        return f"INC-{today}-{self.incident_counter:04d}"

    def create_incident(self, log: NormalizedLog) -> Optional[Incident]:
        """
        위협 로그로부터 인시던트 생성

        Args:
            log: 위협이 탐지된 로그

        Returns:
            생성된 인시던트 또는 None
        """
        if not log.is_threat:
            return None

        # 인시던트 제목 생성
        title = self._generate_title(log)

        incident = Incident(
            id=self._generate_incident_id(),
            timestamp=log.timestamp,
            event_type=log.event_type,
            severity=log.severity,
            status=IncidentStatus.DETECTED,
            title=title,
            description=log.threat_details or log.description,
            source_ip=log.source_ip,
            affected_user=log.username,
            detection_count=log.count,
            first_seen=log.timestamp,
            last_seen=log.timestamp,
        )

        self.incidents[incident.id] = incident
        return incident

    def _generate_title(self, log: NormalizedLog) -> str:
        """인시던트 제목 자동 생성"""
        event_titles = {
            EventType.LOGIN_FAILED: f"Brute Force Attack from {log.source_ip}",
            EventType.SQL_INJECTION: f"SQL Injection Attempt from {log.source_ip}",
            EventType.PRIVILEGE_ESCALATION: f"Privilege Escalation by {log.username or 'unknown'}",
            EventType.BOTNET_ACTIVITY: f"Botnet Activity Detected: {log.source_ip}",
            EventType.SUSPICIOUS_LOGIN: f"Suspicious Login from {log.source_ip}",
            EventType.NETWORK_ANOMALY: f"Network Anomaly: {log.source_ip}",
            EventType.MALWARE_DETECTED: f"Malware Detected on {log.source_ip}",
            EventType.FILE_ACCESS: f"Unauthorized File Access by {log.username or 'unknown'}",
        }

        return event_titles.get(log.event_type, f"Security Event: {log.event_type.value}")

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """인시던트 조회"""
        return self.incidents.get(incident_id)

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[SeverityLevel] = None,
        limit: int = 50
    ) -> List[Incident]:
        """
        인시던트 목록 조회

        Args:
            status: 상태 필터
            severity: 심각도 필터
            limit: 최대 결과 수

        Returns:
            인시던트 목록
        """
        incidents = list(self.incidents.values())

        # 필터링
        if status:
            incidents = [inc for inc in incidents if inc.status == status]
        if severity:
            incidents = [inc for inc in incidents if inc.severity == severity]

        # 최신순 정렬
        incidents.sort(key=lambda x: x.timestamp, reverse=True)

        return incidents[:limit]

    def update_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        analyst_notes: Optional[str] = None,
        resolution: Optional[str] = None
    ) -> Optional[Incident]:
        """
        인시던트 상태 업데이트

        Args:
            incident_id: 인시던트 ID
            new_status: 새로운 상태
            analyst_notes: 분석가 메모
            resolution: 해결 방법

        Returns:
            업데이트된 인시던트 또는 None
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        incident.status = new_status

        if analyst_notes:
            incident.analyst_notes = analyst_notes

        if resolution:
            incident.resolution = resolution

        return incident

    def get_active_incidents(self) -> List[Incident]:
        """활성 인시던트 목록 (DETECTED, ANALYZING, IN_PROGRESS)"""
        return [
            inc for inc in self.incidents.values()
            if inc.status in [IncidentStatus.DETECTED, IncidentStatus.ANALYZING, IncidentStatus.IN_PROGRESS]
        ]

    def get_critical_incidents(self) -> List[Incident]:
        """Critical 심각도 인시던트 목록"""
        critical = [
            inc for inc in self.incidents.values()
            if inc.severity == SeverityLevel.CRITICAL and inc.status != IncidentStatus.RESOLVED
        ]
        return sorted(critical, key=lambda x: x.timestamp, reverse=True)

    def get_statistics(self) -> Dict:
        """인시던트 통계"""
        all_incidents = list(self.incidents.values())

        return {
            "total_incidents": len(all_incidents),
            "by_status": {
                "detected": len([i for i in all_incidents if i.status == IncidentStatus.DETECTED]),
                "analyzing": len([i for i in all_incidents if i.status == IncidentStatus.ANALYZING]),
                "in_progress": len([i for i in all_incidents if i.status == IncidentStatus.IN_PROGRESS]),
                "resolved": len([i for i in all_incidents if i.status == IncidentStatus.RESOLVED]),
                "false_positive": len([i for i in all_incidents if i.status == IncidentStatus.FALSE_POSITIVE]),
            },
            "by_severity": {
                "critical": len([i for i in all_incidents if i.severity == SeverityLevel.CRITICAL]),
                "high": len([i for i in all_incidents if i.severity == SeverityLevel.HIGH]),
                "medium": len([i for i in all_incidents if i.severity == SeverityLevel.MEDIUM]),
                "low": len([i for i in all_incidents if i.severity == SeverityLevel.LOW]),
            },
            "active_count": len(self.get_active_incidents()),
            "critical_unresolved": len(self.get_critical_incidents()),
        }


# 전역 인시던트 매니저 인스턴스
incident_manager = IncidentManager()
