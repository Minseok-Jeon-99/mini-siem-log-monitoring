# Mini-SIEM 사용법 가이드

## 목차
1. [빠른 시작](#빠른-시작)
2. [로그 이벤트 전송](#로그-이벤트-전송)
3. [대시보드 및 통계 조회](#대시보드-및-통계-조회)
4. [인시던트 관리](#인시던트-관리)
5. [리포트 생성](#리포트-생성)
6. [실전 시나리오](#실전-시나리오)

---

## 빠른 시작

### 1. 환경 설정

```bash
# 프로젝트 디렉토리로 이동
cd Security_Log_Monitoring_System

# .env 파일 생성 및 편집
cp .env.example .env
nano .env
```

**.env 파일 필수 설정:**
```env
ELASTIC_PASSWORD=your_password
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
API_KEY=your_secure_api_key
```

### 2. 시스템 시작

```bash
# Docker Compose로 전체 시스템 시작
docker-compose up -d

# 로그 확인
docker-compose logs -f fastapi_app

# 서비스 상태 확인
docker-compose ps
```

### 3. 접속 확인

```bash
# API 서버 확인
curl http://localhost:8000/

# 서비스 접속 URL
# - API 문서: http://localhost:8000/docs
# - Kibana: http://localhost:5601
```

---

## 로그 이벤트 전송

### 이벤트 타입 목록

| 이벤트 타입 | 설명 | 심각도 |
|------------|------|--------|
| `login_failed` | 로그인 실패 (Brute Force) | Medium/High |
| `login_success` | 정상 로그인 | Info |
| `suspicious_login` | 의심스러운 로그인 | Medium |
| `sql_injection` | SQL Injection 시도 | Critical |
| `privilege_escalation` | 권한 상승 시도 | High |
| `network_anomaly` | 네트워크 이상 행위 | Medium |
| `botnet_activity` | 봇넷 활동 | Medium |
| `file_access` | 민감한 파일 접근 | Low/Medium |
| `malware_detected` | 악성코드 탐지 | Critical |

### 예제 1: Brute Force 공격

```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "login_failed",
    "source_ip": "192.168.1.100",
    "username": "admin",
    "count": 8,
    "description": "Multiple failed login attempts"
  }'
```

**응답:**
```json
{
  "status": "threat_detected",
  "log": {
    "timestamp": "2025-10-25T10:30:00.123Z",
    "event_type": "login_failed",
    "severity": "medium",
    "is_threat": true,
    "threat_details": "Brute force attack detected: 8 failed login attempts from 192.168.1.100"
  },
  "incident_id": "INC-20251025-0001",
  "alert_sent": true
}
```

### 예제 2: SQL Injection

```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "sql_injection",
    "source_ip": "172.16.0.200",
    "username": "attacker",
    "count": 1,
    "raw_log": "SELECT * FROM users WHERE id = 1 OR 1=1; DROP TABLE users;--",
    "description": "SQL Injection attempt detected in login form"
  }'
```

### 예제 3: 권한 상승 시도

```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "privilege_escalation",
    "source_ip": "192.168.10.50",
    "username": "user123",
    "count": 1,
    "description": "Unauthorized sudo access attempt",
    "raw_log": "user123 attempted: sudo -i"
  }'
```

### 예제 4: 봇넷 활동

```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "network_anomaly",
    "source_ip": "203.0.113.45",
    "count": 25,
    "description": "Suspicious network activity detected",
    "metadata": {
      "unique_ips_count": 30,
      "connection_rate": "500/min"
    }
  }'
```

### 예제 5: 정상 로그인 (위협 아님)

```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "login_success",
    "source_ip": "192.168.1.10",
    "username": "john.doe",
    "count": 1,
    "description": "Successful login from office network"
  }'
```

---

## 대시보드 및 통계 조회

### 실시간 대시보드

```bash
curl http://localhost:8000/dashboard
```

**응답 예시:**
```json
{
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
  },
  "timestamp": "2025-10-25T10:30:00.123Z"
}
```

### 위협 타임라인

```bash
# 최근 24시간
curl http://localhost:8000/threats/timeline?hours=24

# 최근 1시간
curl http://localhost:8000/threats/timeline?hours=1
```

---

## 인시던트 관리

### 1. 인시던트 목록 조회

```bash
# 전체 인시던트 목록
curl http://localhost:8000/incidents

# Critical 인시던트만
curl http://localhost:8000/incidents?severity=critical

# 처리 중인 인시던트만
curl http://localhost:8000/incidents?status=in_progress

# 조합 필터
curl "http://localhost:8000/incidents?severity=high&limit=10"
```

**응답 예시:**
```json
{
  "count": 15,
  "incidents": [
    {
      "id": "INC-20251025-0001",
      "timestamp": "2025-10-25T10:30:00.123Z",
      "event_type": "login_failed",
      "severity": "high",
      "status": "detected",
      "title": "Brute Force Attack from 192.168.1.100",
      "description": "Brute force attack detected: 8 failed login attempts...",
      "source_ip": "192.168.1.100",
      "affected_user": "admin",
      "detection_count": 8,
      "first_seen": "2025-10-25T10:30:00.123Z",
      "last_seen": "2025-10-25T10:30:00.123Z"
    }
  ]
}
```

### 2. 특정 인시던트 상세 조회

```bash
curl http://localhost:8000/incidents/INC-20251025-0001
```

### 3. 인시던트 상태 업데이트

```bash
# 분석 시작
curl -X POST "http://localhost:8000/incidents/INC-20251025-0001/status?status=analyzing" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_notes": "Started investigation. Checking firewall logs.",
    "resolution": null
  }'

# 처리 중으로 변경
curl -X POST "http://localhost:8000/incidents/INC-20251025-0001/status?status=in_progress" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_notes": "Blocking source IP in firewall.",
    "resolution": null
  }'

# 해결 완료
curl -X POST "http://localhost:8000/incidents/INC-20251025-0001/status?status=resolved" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_notes": "IP blocked. User password reset.",
    "resolution": "Blocked IP 192.168.1.100 in firewall. Reset admin password. No system compromise detected."
  }'
```

**상태 값:**
- `detected` - 탐지됨 (초기 상태)
- `analyzing` - 분석 중
- `in_progress` - 처리 중
- `resolved` - 해결됨
- `false_positive` - 오탐

### 4. 인시던트 통계

```bash
curl http://localhost:8000/incidents/stats
```

**응답 예시:**
```json
{
  "total_incidents": 47,
  "by_status": {
    "detected": 12,
    "analyzing": 5,
    "in_progress": 3,
    "resolved": 25,
    "false_positive": 2
  },
  "by_severity": {
    "critical": 3,
    "high": 12,
    "medium": 25,
    "low": 7
  },
  "active_count": 20,
  "critical_unresolved": 2
}
```

---

## 리포트 생성

### 일일 보안 리포트

```bash
curl http://localhost:8000/report/daily
```

**응답 예시:**
```json
{
  "report_date": "2025-10-25",
  "generated_at": "2025-10-25T23:59:00.000Z",
  "summary": {
    "total_events": 1523,
    "total_threats": 47,
    "threat_rate": "3.09%"
  },
  "severity_breakdown": {
    "critical": 3,
    "high": 12,
    "medium": 25,
    "low": 7
  },
  "hourly_distribution": {
    "0": 5,
    "1": 3,
    "2": 8,
    "10": 15,
    "14": 12
  },
  "top_targeted_users": {
    "admin": 25,
    "root": 12,
    "user123": 5
  },
  "top_threats": [
    {
      "timestamp": "2025-10-25T10:30:00.123Z",
      "event_type": "sql_injection",
      "severity": "critical",
      "source_ip": "172.16.0.200",
      "description": "SQL Injection attempt detected",
      "threat_details": "SQL Injection attempt detected from 172.16.0.200: (\\bor\\b\\s+\\d+\\s*=\\s*\\d+)"
    }
  ]
}
```

### 주간 보안 리포트

```bash
curl http://localhost:8000/report/weekly
```

**응답 예시:**
```json
{
  "report_period": "2025-10-18 to 2025-10-25",
  "generated_at": "2025-10-25T23:59:00.000Z",
  "summary": {
    "total_events": 10567,
    "total_threats": 324,
    "avg_daily_events": 1509,
    "avg_daily_threats": 46
  },
  "daily_breakdown": {
    "2025-10-25": {
      "total": 1523,
      "threats": 47
    },
    "2025-10-24": {
      "total": 1450,
      "threats": 52
    }
  },
  "threat_types": {
    "login_failed": 142,
    "sql_injection": 23,
    "privilege_escalation": 12
  },
  "top_attack_sources": {
    "192.168.1.100": 45,
    "172.16.0.200": 32,
    "10.0.0.50": 18
  }
}
```

---

## 실전 시나리오

### 시나리오 1: Brute Force 공격 대응

```bash
# 1. 공격 이벤트 발생 (자동 탐지)
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "login_failed",
    "source_ip": "192.168.1.100",
    "username": "admin",
    "count": 10
  }'

# ✅ Slack 알림 자동 전송
# ✅ 인시던트 자동 생성 (INC-20251025-0001)

# 2. 인시던트 확인
curl http://localhost:8000/incidents/INC-20251025-0001

# 3. 분석 시작
curl -X POST "http://localhost:8000/incidents/INC-20251025-0001/status?status=analyzing" \
  -H "X-API-Key: your_api_key"

# 4. 방화벽에서 IP 차단 (수동 작업)
# ... 실제 방화벽 작업 수행 ...

# 5. 처리 완료 기록
curl -X POST "http://localhost:8000/incidents/INC-20251025-0001/status?status=resolved" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "analyst_notes": "Confirmed brute force attack. IP blocked in firewall.",
    "resolution": "Blocked IP 192.168.1.100. Password reset for admin account."
  }'

# 6. 일일 리포트 확인
curl http://localhost:8000/report/daily
```

### 시나리오 2: SQL Injection 공격 모니터링

```bash
# 1. 여러 SQL Injection 시도 전송
for i in {1..5}; do
  curl -X POST http://localhost:8000/log \
    -H "Content-Type: application/json" \
    -H "X-API-Key: your_api_key" \
    -d "{
      \"event_type\": \"sql_injection\",
      \"source_ip\": \"172.16.0.200\",
      \"username\": \"attacker$i\",
      \"raw_log\": \"SELECT * FROM users WHERE id = 1 OR 1=1--\"
    }"
  sleep 1
done

# 2. Critical 인시던트 목록 확인
curl http://localhost:8000/incidents?severity=critical

# 3. 위협 타임라인 확인
curl http://localhost:8000/threats/timeline?hours=1

# 4. 대시보드 통계 확인
curl http://localhost:8000/dashboard
```

### 시나리오 3: 자동 테스트 스크립트 실행

```bash
# Python 테스트 스크립트 실행
cd examples
python3 test_events.py

# 실행 결과:
# - 7가지 다양한 보안 이벤트 전송
# - 위협 탐지 및 인시던트 생성
# - Slack 알림 전송
# - 대시보드 통계 출력
# - 인시던트 목록 출력
```

---

## API 인증

모든 **POST** 요청에는 API 키가 필요합니다:

```bash
# ✅ 올바른 예시
curl -X POST http://localhost:8000/log \
  -H "X-API-Key: your_api_key" \
  -d '{...}'

# ❌ 인증 없이 요청 시
curl -X POST http://localhost:8000/log \
  -d '{...}'
# 응답: 401 Unauthorized
```

**GET** 요청은 인증이 필요하지 않습니다 (대시보드, 리포트, 인시던트 조회 등).

---

## 트러블슈팅

### 1. API 키 오류

```bash
# 오류: 401 Unauthorized
# 해결: .env 파일의 API_KEY 확인
cat .env | grep API_KEY

# 테스트 스크립트의 API_KEY도 동일하게 설정
```

### 2. Slack 알림이 오지 않음

```bash
# .env 파일의 SLACK_WEBHOOK_URL 확인
cat .env | grep SLACK_WEBHOOK_URL

# Slack Webhook 테스트
curl -X POST YOUR_SLACK_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{"text":"Test message from Mini-SIEM"}'
```

### 3. Elasticsearch 연결 실패

```bash
# Elasticsearch 상태 확인
curl -u elastic:your_password http://localhost:9200/_cluster/health

# 컨테이너 재시작
docker-compose restart elasticsearch
docker-compose restart fastapi_app
```

### 4. 로그 확인

```bash
# FastAPI 앱 로그
docker-compose logs -f fastapi_app

# Filebeat 로그
docker-compose logs filebeat

# 전체 로그
docker-compose logs
```

---

## 시스템 종료

```bash
# 전체 시스템 중지
docker-compose down

# 데이터까지 삭제 (주의!)
docker-compose down -v
```

---

## 다음 단계

1. **Kibana 대시보드 설정**
   - http://localhost:5601 접속
   - Index pattern 생성
   - 시각화 대시보드 구성

2. **실제 로그 소스 연동**
   - 웹 서버 로그
   - 방화벽 로그
   - IDS/IPS 로그

3. **알림 채널 추가**
   - 이메일 알림
   - SMS 알림
   - PagerDuty 연동

---

## 참고 자료

- **API 문서**: http://localhost:8000/docs
- **프로젝트 README**: README.md
- **테스트 스크립트**: examples/test_events.py
- **curl 예제**: examples/curl_examples.sh