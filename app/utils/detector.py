import re
from datetime import datetime, time
from typing import Tuple, Optional
from models.log import NormalizedLog, SeverityLevel, EventType


class ThreatDetector:
    """보안 위협 탐지 엔진"""

    # SQL Injection 패턴 (OWASP Top 10)
    SQL_INJECTION_PATTERNS = [
        r"(\bor\b\s+\d+\s*=\s*\d+)",
        r"(\bunion\b\s+\bselect\b)",
        r"(';?\s*drop\s+table)",
        r"(';?\s*delete\s+from)",
        r"(\bexec\b\s*\()",
        r"(<script.*?>.*?</script>)",
        r"(--|#|/\*|\*/)",
    ]

    # 알려진 악성 IP 리스트 (예시)
    KNOWN_MALICIOUS_IPS = [
        "192.168.99.99",
        "10.0.0.666",
        "172.16.0.100",
    ]

    # 비정상 접속 시간대 (새벽 2시 ~ 5시)
    SUSPICIOUS_HOURS = (2, 5)

    @staticmethod
    def detect_brute_force(log: NormalizedLog) -> Tuple[bool, Optional[str]]:
        """
        Brute Force 공격 탐지
        - 로그인 실패 5회 이상
        """
        if log.event_type == EventType.LOGIN_FAILED and log.count >= 5:
            return True, f"Brute force attack detected: {log.count} failed login attempts from {log.source_ip}"
        return False, None

    @staticmethod
    def detect_suspicious_time_access(log: NormalizedLog) -> Tuple[bool, Optional[str]]:
        """
        비정상 시간대 접속 탐지
        - 업무 외 시간(새벽 2-5시) 로그인 시도
        """
        if log.event_type in [EventType.LOGIN_SUCCESS, EventType.LOGIN_FAILED]:
            current_hour = log.timestamp.hour
            start_hour, end_hour = ThreatDetector.SUSPICIOUS_HOURS

            if start_hour <= current_hour < end_hour:
                return True, f"Suspicious login attempt at {log.timestamp.strftime('%H:%M')} (off-hours) from {log.source_ip}"
        return False, None

    @staticmethod
    def detect_sql_injection(log: NormalizedLog) -> Tuple[bool, Optional[str]]:
        """
        SQL Injection 공격 탐지
        - 쿼리 패턴 분석
        """
        if log.event_type == EventType.SQL_INJECTION or log.raw_log:
            content = log.raw_log or log.description or ""

            for pattern in ThreatDetector.SQL_INJECTION_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    return True, f"SQL Injection attempt detected from {log.source_ip}: {pattern}"
        return False, None

    @staticmethod
    def detect_privilege_escalation(log: NormalizedLog) -> Tuple[bool, Optional[str]]:
        """
        권한 상승 시도 탐지
        - sudo, admin, root 권한 요청
        """
        if log.event_type == EventType.PRIVILEGE_ESCALATION:
            return True, f"Privilege escalation attempt by {log.username} from {log.source_ip}"

        # 일반 로그에서 권한 상승 키워드 탐지
        keywords = ["sudo", "admin", "root", "privilege", "escalate"]
        content = (log.raw_log or log.description or "").lower()

        for keyword in keywords:
            if keyword in content:
                return True, f"Potential privilege escalation: '{keyword}' detected in event from {log.source_ip}"
        return False, None

    @staticmethod
    def detect_botnet_activity(log: NormalizedLog) -> Tuple[bool, Optional[str]]:
        """
        봇넷 활동 탐지
        - 다수의 연결 시도 (count > 10)
        """
        if log.event_type == EventType.NETWORK_ANOMALY and log.count > 10:
            return True, f"Potential botnet activity: {log.count} connection attempts from {log.source_ip}"

        # 짧은 시간 내 다수 IP 접속 (메타데이터 활용)
        if log.metadata.get("unique_ips_count", 0) > 20:
            return True, f"Botnet-like behavior detected: {log.metadata['unique_ips_count']} unique IPs in short time"
        return False, None

    @staticmethod
    def detect_malicious_ip(log: NormalizedLog) -> Tuple[bool, Optional[str]]:
        """
        알려진 악성 IP 탐지
        - 위협 인텔리전스 기반 (간단한 예시)
        """
        if log.source_ip in ThreatDetector.KNOWN_MALICIOUS_IPS:
            return True, f"Known malicious IP detected: {log.source_ip}"
        return False, None

    @staticmethod
    def detect_file_access_anomaly(log: NormalizedLog) -> Tuple[bool, Optional[str]]:
        """
        비정상 파일 접근 탐지
        - 민감한 파일에 대한 접근
        """
        if log.event_type == EventType.FILE_ACCESS:
            sensitive_paths = ["/etc/passwd", "/etc/shadow", "config.php", ".env", "database.yml"]
            content = log.raw_log or log.description or ""

            for path in sensitive_paths:
                if path in content:
                    return True, f"Suspicious file access attempt: {path} by {log.username or 'unknown'}"
        return False, None

    @staticmethod
    def assign_severity(log: NormalizedLog, is_threat: bool, threat_details: Optional[str]) -> SeverityLevel:
        """
        위협 심각도 자동 할당

        Args:
            log: 정규화된 로그
            is_threat: 위협 여부
            threat_details: 위협 상세 정보

        Returns:
            심각도 레벨
        """
        if not is_threat:
            return SeverityLevel.INFO

        # Critical: 알려진 악성 IP, SQL Injection
        if log.event_type in [EventType.SQL_INJECTION, EventType.MALWARE_DETECTED]:
            return SeverityLevel.CRITICAL
        if log.source_ip in ThreatDetector.KNOWN_MALICIOUS_IPS:
            return SeverityLevel.CRITICAL

        # High: 권한 상승, Brute Force (count >= 10)
        if log.event_type == EventType.PRIVILEGE_ESCALATION:
            return SeverityLevel.HIGH
        if log.event_type == EventType.LOGIN_FAILED and log.count >= 10:
            return SeverityLevel.HIGH

        # Medium: Brute Force (count 5-9), 봇넷 활동, 비정상 시간 접속
        if log.event_type == EventType.LOGIN_FAILED and 5 <= log.count < 10:
            return SeverityLevel.MEDIUM
        if log.event_type in [EventType.BOTNET_ACTIVITY, EventType.NETWORK_ANOMALY]:
            return SeverityLevel.MEDIUM
        if "off-hours" in (threat_details or ""):
            return SeverityLevel.MEDIUM

        # Low: 기타 의심스러운 활동
        return SeverityLevel.LOW

    @classmethod
    def analyze(cls, log: NormalizedLog) -> NormalizedLog:
        """
        로그를 분석하고 위협 탐지 수행

        Args:
            log: 분석할 정규화된 로그

        Returns:
            위협 분석이 추가된 로그
        """
        threats = []

        # 모든 탐지 룰 실행
        detectors = [
            cls.detect_brute_force,
            cls.detect_suspicious_time_access,
            cls.detect_sql_injection,
            cls.detect_privilege_escalation,
            cls.detect_botnet_activity,
            cls.detect_malicious_ip,
            cls.detect_file_access_anomaly,
        ]

        for detector in detectors:
            is_threat, details = detector(log)
            if is_threat and details:
                threats.append(details)

        # 위협이 탐지된 경우
        if threats:
            log.is_threat = True
            log.threat_details = " | ".join(threats)
            log.severity = cls.assign_severity(log, True, log.threat_details)
        else:
            log.is_threat = False
            log.severity = SeverityLevel.INFO

        return log