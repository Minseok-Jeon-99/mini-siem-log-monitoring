from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict, Counter
from models.log import NormalizedLog, DashboardStats, SeverityLevel


class StatisticsService:
    """통계 및 리포트 생성 서비스"""

    def __init__(self):
        # 메모리 기반 로그 저장소 (실제로는 DB 사용 권장)
        self.logs: List[NormalizedLog] = []
        self.threat_logs: List[NormalizedLog] = []

    def add_log(self, log: NormalizedLog):
        """로그 추가"""
        self.logs.append(log)
        if log.is_threat:
            self.threat_logs.append(log)

    def get_dashboard_stats(self) -> DashboardStats:
        """실시간 대시보드 통계 생성"""
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # 오늘 로그 필터링
        today_logs = [log for log in self.logs if log.timestamp >= today_start]
        today_threats = [log for log in self.threat_logs if log.timestamp >= today_start]

        # 심각도별 통계
        severity_counts = Counter([log.severity for log in today_threats])

        # 상위 공격 IP
        ip_counter = Counter([log.source_ip for log in today_threats if log.source_ip])
        top_attack_ips = [ip for ip, _ in ip_counter.most_common(10)]

        # 이벤트 타입별 통계
        event_type_counts = Counter([log.event_type.value for log in today_threats])

        return DashboardStats(
            total_events=len(today_logs),
            total_threats=len(today_threats),
            critical_incidents=severity_counts.get(SeverityLevel.CRITICAL, 0),
            high_incidents=severity_counts.get(SeverityLevel.HIGH, 0),
            medium_incidents=severity_counts.get(SeverityLevel.MEDIUM, 0),
            low_incidents=severity_counts.get(SeverityLevel.LOW, 0),
            active_incidents=len([log for log in today_threats if log.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]),
            resolved_incidents=0,  # TODO: 인시던트 관리 시스템 연동
            top_attack_ips=top_attack_ips,
            top_event_types=dict(event_type_counts),
            timestamp=now
        )

    def get_daily_report(self) -> Dict:
        """일일 보안 리포트 생성"""
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        today_logs = [log for log in self.logs if log.timestamp >= today_start]
        today_threats = [log for log in self.threat_logs if log.timestamp >= today_start]

        # 시간대별 통계
        hourly_stats = defaultdict(int)
        for log in today_threats:
            hour = log.timestamp.hour
            hourly_stats[hour] += 1

        # 사용자별 통계
        user_stats = Counter([log.username for log in today_threats if log.username])

        # 상위 위협
        top_threats = sorted(
            today_threats,
            key=lambda x: (x.severity.value, x.count),
            reverse=True
        )[:10]

        return {
            "report_date": today_start.strftime("%Y-%m-%d"),
            "generated_at": now.isoformat(),
            "summary": {
                "total_events": len(today_logs),
                "total_threats": len(today_threats),
                "threat_rate": f"{(len(today_threats) / len(today_logs) * 100):.2f}%" if today_logs else "0%",
            },
            "severity_breakdown": {
                "critical": len([l for l in today_threats if l.severity == SeverityLevel.CRITICAL]),
                "high": len([l for l in today_threats if l.severity == SeverityLevel.HIGH]),
                "medium": len([l for l in today_threats if l.severity == SeverityLevel.MEDIUM]),
                "low": len([l for l in today_threats if l.severity == SeverityLevel.LOW]),
            },
            "hourly_distribution": dict(hourly_stats),
            "top_targeted_users": dict(user_stats.most_common(10)),
            "top_threats": [
                {
                    "timestamp": threat.timestamp.isoformat(),
                    "event_type": threat.event_type.value,
                    "severity": threat.severity.value,
                    "source_ip": threat.source_ip,
                    "description": threat.description,
                    "threat_details": threat.threat_details,
                }
                for threat in top_threats
            ],
        }

    def get_weekly_report(self) -> Dict:
        """주간 보안 리포트 생성"""
        now = datetime.utcnow()
        week_start = now - timedelta(days=7)

        week_logs = [log for log in self.logs if log.timestamp >= week_start]
        week_threats = [log for log in self.threat_logs if log.timestamp >= week_start]

        # 일별 통계
        daily_stats = defaultdict(lambda: {"total": 0, "threats": 0})
        for log in week_logs:
            day = log.timestamp.strftime("%Y-%m-%d")
            daily_stats[day]["total"] += 1

        for log in week_threats:
            day = log.timestamp.strftime("%Y-%m-%d")
            daily_stats[day]["threats"] += 1

        # 이벤트 타입별 추세
        event_trends = Counter([log.event_type.value for log in week_threats])

        # 상위 공격 소스
        ip_counter = Counter([log.source_ip for log in week_threats if log.source_ip])

        return {
            "report_period": f"{week_start.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
            "generated_at": now.isoformat(),
            "summary": {
                "total_events": len(week_logs),
                "total_threats": len(week_threats),
                "avg_daily_events": len(week_logs) // 7,
                "avg_daily_threats": len(week_threats) // 7,
            },
            "daily_breakdown": dict(daily_stats),
            "threat_types": dict(event_trends),
            "top_attack_sources": dict(ip_counter.most_common(20)),
            "severity_summary": {
                "critical": len([l for l in week_threats if l.severity == SeverityLevel.CRITICAL]),
                "high": len([l for l in week_threats if l.severity == SeverityLevel.HIGH]),
                "medium": len([l for l in week_threats if l.severity == SeverityLevel.MEDIUM]),
                "low": len([l for l in week_threats if l.severity == SeverityLevel.LOW]),
            },
        }

    def get_threat_timeline(self, hours: int = 24) -> List[Dict]:
        """위협 타임라인 조회"""
        now = datetime.utcnow()
        start_time = now - timedelta(hours=hours)

        recent_threats = [log for log in self.threat_logs if log.timestamp >= start_time]

        return [
            {
                "timestamp": threat.timestamp.isoformat(),
                "event_type": threat.event_type.value,
                "severity": threat.severity.value,
                "source_ip": threat.source_ip,
                "username": threat.username,
                "description": threat.description,
                "threat_details": threat.threat_details,
            }
            for threat in sorted(recent_threats, key=lambda x: x.timestamp, reverse=True)
        ]


# 전역 통계 서비스 인스턴스
stats_service = StatisticsService()
