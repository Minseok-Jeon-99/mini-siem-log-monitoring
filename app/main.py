from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
import logging
import os
from datetime import datetime
from typing import Optional

# 로컬 임포트
from models.log import LogEvent, NormalizedLog, EventType, IncidentStatus
from utils.alert import send_slack_alert
from utils.auth import verify_api_key
from utils.detector import ThreatDetector
from services.statistics import stats_service
from services.incident import incident_manager

# === 로그 디렉토리 설정 ===
LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE_PATH = os.path.join(LOG_DIR, "app.log")

# === 로깅 설정 ===
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler()  # 콘솔에도 출력
    ]
)

logger = logging.getLogger(__name__)

# === FastAPI 앱 초기화 ===
app = FastAPI(
    title="Security Log Monitoring System (Mini-SIEM)",
    description="실시간 보안 이벤트 수집, 분석 및 위협 탐지 시스템",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


@app.get("/")
def home():
    """Health Check 엔드포인트"""
    logger.info("✅ Mini-SIEM FastAPI 서버 정상 작동 중")
    return {
        "message": "Mini-SIEM FastAPI Server is running.",
        "version": "2.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/log")
async def receive_log(log_event: LogEvent, api_key: str = Depends(verify_api_key)):
    """
    보안 이벤트 로그 수신 및 분석

    - **API Key 인증 필수**: X-API-Key 헤더 필요
    - 로그 정규화 및 위협 탐지 수행
    - 위협 발견 시 Slack 알림 전송
    - 인시던트 자동 생성
    """
    try:
        # 1. 로그 정규화
        normalized_log = NormalizedLog(
            timestamp=datetime.utcnow(),
            event_type=log_event.event_type,
            source_ip=log_event.source_ip,
            destination_ip=log_event.destination_ip,
            username=log_event.username,
            count=log_event.count,
            description=log_event.description or f"{log_event.event_type} event detected",
            raw_log=log_event.raw_log,
            metadata=log_event.metadata
        )

        # 2. 위협 탐지 분석
        analyzed_log = ThreatDetector.analyze(normalized_log)

        # 3. 통계에 추가
        stats_service.add_log(analyzed_log)

        # 4. 로그 파일에 기록
        logger.info(
            f"[EVENT] {analyzed_log.event_type.value} | "
            f"IP={analyzed_log.source_ip} | "
            f"Severity={analyzed_log.severity.value} | "
            f"Threat={analyzed_log.is_threat}"
        )

        # 5. 위협이 탐지된 경우
        if analyzed_log.is_threat:
            # 인시던트 생성
            incident = incident_manager.create_incident(analyzed_log)

            # Slack 알림 전송
            alert_message = (
                f"🚨 *[{analyzed_log.severity.value.upper()}]* Security Threat Detected\n"
                f"• *Type*: {analyzed_log.event_type.value}\n"
                f"• *Source IP*: {analyzed_log.source_ip}\n"
                f"• *Details*: {analyzed_log.threat_details}\n"
                f"• *Incident ID*: {incident.id if incident else 'N/A'}"
            )
            send_slack_alert(alert_message)
            logger.warning(f"⚠️ THREAT DETECTED: {analyzed_log.threat_details}")

            return {
                "status": "threat_detected",
                "log": analyzed_log.dict(),
                "incident_id": incident.id if incident else None,
                "alert_sent": True
            }

        # 6. 정상 로그
        return {
            "status": "ok",
            "log": analyzed_log.dict(),
            "alert_sent": False
        }

    except Exception as e:
        logger.error(f"Error processing log: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Log processing failed: {str(e)}")


@app.get("/dashboard")
def get_dashboard():
    """실시간 대시보드 통계 조회"""
    try:
        stats = stats_service.get_dashboard_stats()
        return stats.dict()
    except Exception as e:
        logger.error(f"Error generating dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report/daily")
def get_daily_report():
    """일일 보안 리포트 생성"""
    try:
        report = stats_service.get_daily_report()
        return report
    except Exception as e:
        logger.error(f"Error generating daily report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report/weekly")
def get_weekly_report():
    """주간 보안 리포트 생성"""
    try:
        report = stats_service.get_weekly_report()
        return report
    except Exception as e:
        logger.error(f"Error generating weekly report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threats/timeline")
def get_threat_timeline(hours: int = 24):
    """
    위협 타임라인 조회

    - **hours**: 조회할 시간 범위 (기본값: 24시간)
    """
    try:
        timeline = stats_service.get_threat_timeline(hours=hours)
        return {"timeline": timeline, "count": len(timeline)}
    except Exception as e:
        logger.error(f"Error generating threat timeline: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents")
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50
):
    """
    인시던트 목록 조회

    - **status**: 상태 필터 (detected, analyzing, in_progress, resolved, false_positive)
    - **severity**: 심각도 필터 (critical, high, medium, low, info)
    - **limit**: 최대 결과 수 (기본값: 50)
    """
    try:
        status_filter = IncidentStatus(status) if status else None
        severity_filter = None
        if severity:
            from models.log import SeverityLevel
            severity_filter = SeverityLevel(severity)

        incidents = incident_manager.list_incidents(
            status=status_filter,
            severity=severity_filter,
            limit=limit
        )

        return {
            "count": len(incidents),
            "incidents": [inc.dict() for inc in incidents]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid filter value: {str(e)}")
    except Exception as e:
        logger.error(f"Error listing incidents: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """특정 인시던트 상세 조회"""
    incident = incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident.dict()


@app.post("/incidents/{incident_id}/status", dependencies=[Depends(verify_api_key)])
def update_incident_status(
    incident_id: str,
    status: str,
    analyst_notes: Optional[str] = None,
    resolution: Optional[str] = None
):
    """
    인시던트 상태 업데이트

    - **API Key 인증 필수**
    - **status**: 새로운 상태 (detected, analyzing, in_progress, resolved, false_positive)
    - **analyst_notes**: 분석가 메모 (선택)
    - **resolution**: 해결 방법 (선택)
    """
    try:
        new_status = IncidentStatus(status)
        incident = incident_manager.update_status(
            incident_id=incident_id,
            new_status=new_status,
            analyst_notes=analyst_notes,
            resolution=resolution
        )

        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

        logger.info(f"Incident {incident_id} status updated to {status}")
        return {"status": "updated", "incident": incident.dict()}

    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status value: {status}")
    except Exception as e:
        logger.error(f"Error updating incident: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/stats")
def get_incident_statistics():
    """인시던트 통계 조회"""
    try:
        stats = incident_manager.get_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting incident statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("startup")
async def startup_event():
    """애플리케이션 시작 시 실행"""
    logger.info("🚀 Mini-SIEM Application Started")
    logger.info(f"📁 Log directory: {LOG_DIR}")
    logger.info(f"📄 Log file: {LOG_FILE_PATH}")
    logger.info("🔐 API authentication enabled")


@app.on_event("shutdown")
async def shutdown_event():
    """애플리케이션 종료 시 실행"""
    logger.info("🛑 Mini-SIEM Application Shutting Down")
    logger.info(f"📊 Total incidents created: {len(incident_manager.incidents)}")
    logger.info(f"📊 Total logs processed: {len(stats_service.logs)}")
