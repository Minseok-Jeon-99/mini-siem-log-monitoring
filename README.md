# Security Log Monitoring System (Mini-SIEM)

보안 이벤트를 실시간으로 수집, 분석, 저장하고 위협 발견 시 즉시 알림을 전송하는 미니 SIEM 시스템입니다.

## 프로젝트 개요

이 프로젝트는 보안 관제 업무에서 필수적인 로그 모니터링 및 위협 탐지 기능을 구현한 경량 SIEM(Security Information and Event Management) 시스템입니다.

### 주요 기능

- 실시간 보안 이벤트 수집 및 처리
- 다양한 위협 탐지 룰 기반 자동 분석
- Slack을 통한 즉각적인 알림
- Elasticsearch 기반 로그 저장 및 검색
- Kibana를 통한 시각화 대시보드
- RESTful API 제공

## 시스템 아키텍처

```
┌─────────────────┐
│  외부 시스템     │ (로그 소스)
└────────┬────────┘
         │ HTTP POST
         ▼
┌─────────────────────────────────────┐
│     FastAPI Application             │
│  ┌──────────────────────────────┐   │
│  │ /log - 로그 수신              │   │
│  │ /dashboard - 실시간 통계      │   │
│  │ /report - 리포트 생성         │   │
│  └──────────────────────────────┘   │
│          │                           │
│          ▼                           │
│  ┌──────────────────────────────┐   │
│  │  위협 탐지 엔진               │   │
│  │  - 로그인 실패 감지           │   │
│  │  - 비정상 시간대 접속         │   │
│  │  │  - SQL Injection 패턴      │   │
│  └──┬───────────────────────────┘   │
│     │                               │
│     ├─────────────┬─────────────┐   │
│     ▼             ▼             ▼   │
│  [로그 저장]  [Slack 알림]  [통계]  │
└─────┬───────────────────────────────┘
      │
      ▼
┌─────────────┐      ┌──────────────┐
│  Filebeat   │─────▶│Elasticsearch │
└─────────────┘      └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │    Kibana    │
                     └──────────────┘
```

## 기술 스택

- **Backend**: Python 3.10 + FastAPI
- **Log Storage**: Elasticsearch 8.15.0
- **Log Shipper**: Filebeat 8.15.0
- **Visualization**: Kibana 8.15.0
- **Alert**: Slack Webhook
- **Container**: Docker & Docker Compose

## 설치 및 실행

### 1. 사전 요구사항

- Docker & Docker Compose
- Python 3.10 이상 (로컬 개발 시)
- Slack Webhook URL (알림 기능 사용 시)

### 2. 환경 설정

`.env.example` 파일을 복사하여 `.env` 파일 생성:

```bash
cp .env.example .env
```

`.env` 파일 수정:

```env
ELASTIC_PASSWORD=your_password_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
API_KEY=your_api_key_here
```

### 3. Docker Compose로 실행

```bash
# 모든 서비스 시작
docker-compose up -d

# 로그 확인
docker-compose logs -f fastapi_app

# 서비스 중지
docker-compose down
```

### 4. 서비스 접속

- **FastAPI**: http://localhost:8000
- **API 문서**: http://localhost:8000/docs
- **Kibana**: http://localhost:5601
- **Elasticsearch**: http://localhost:9200

## 사용 방법

### 1. 로그 전송

```bash
# 로그인 실패 이벤트 전송
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "event_type": "login_failed",
    "source_ip": "192.168.1.100",
    "username": "admin",
    "count": 5
  }'
```

### 2. 대시보드 조회

```bash
# 실시간 통계 조회
curl http://localhost:8000/dashboard
```

### 3. 리포트 생성

```bash
# 일일 보안 리포트
curl http://localhost:8000/report/daily
```

## 위협 탐지 룰

현재 시스템에서 탐지하는 보안 위협:

1. **로그인 실패 5회 이상**: Brute Force 공격 의심
2. **비정상 시간대 접속**: 업무 외 시간(새벽 2-5시) 로그인
3. **SQL Injection 시도**: 쿼리 패턴 기반 탐지
4. **권한 상승 시도**: sudo, admin 권한 요청
5. **다수 IP 동시 접속**: 봇넷 공격 의심

## API 엔드포인트

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/` | Health Check | No |
| POST | `/log` | 로그 이벤트 수신 | Yes (API Key) |
| GET | `/dashboard` | 실시간 통계 | No |
| GET | `/report/daily` | 일일 리포트 | No |
| GET | `/report/weekly` | 주간 리포트 | No |
| GET | `/incidents` | 인시던트 목록 | No |
| POST | `/incidents/{id}/status` | 인시던트 상태 변경 | Yes |

## 디렉토리 구조

```
Security_Log_Monitoring_System/
├── app/
│   ├── main.py              # FastAPI 메인 애플리케이션
│   ├── models/              # Pydantic 데이터 모델
│   │   └── log.py
│   ├── utils/               # 유틸리티 함수
│   │   ├── alert.py         # Slack 알림
│   │   ├── detector.py      # 위협 탐지 로직
│   │   └── auth.py          # API 인증
│   ├── services/            # 비즈니스 로직
│   │   ├── incident.py      # 인시던트 관리
│   │   └── statistics.py    # 통계 처리
│   └── logs/                # 로그 파일 저장
├── filebeat/
│   └── filebeat.yml         # Filebeat 설정
├── docker-compose.yml       # Docker Compose 설정
├── Dockerfile              # FastAPI 앱 컨테이너 이미지
├── requirements.txt        # Python 의존성
├── .env.example           # 환경 변수 템플릿
└── README.md              # 프로젝트 문서
```

## 로그 데이터 스키마

```json
{
  "timestamp": "2025-10-25T10:30:00Z",
  "event_type": "login_failed",
  "severity": "medium",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "username": "admin",
  "description": "Multiple failed login attempts detected",
  "count": 5,
  "raw_log": "원본 로그 데이터"
}
```

## 보안 고려사항

- API 키 기반 인증 사용
- `.env` 파일은 Git에 커밋하지 않음 (`.gitignore` 포함)
- Elasticsearch 비밀번호 설정 필수
- 프로덕션 환경에서는 HTTPS 사용 권장
- Rate Limiting 적용 (추후 구현 예정)

## 확장 계획

- [ ] IP 화이트리스트/블랙리스트 관리
- [ ] 자동 차단 기능 (iptables 연동)
- [ ] 이메일 알림 추가
- [ ] 위협 인텔리전스 연동 (AbuseIPDB 등)
- [ ] 머신러닝 기반 이상 탐지
- [ ] 웹 UI 대시보드

## 트러블슈팅

### Elasticsearch 연결 실패

```bash
# Elasticsearch 상태 확인
curl -u elastic:your_password http://localhost:9200/_cluster/health
```

### Filebeat가 로그를 전송하지 않는 경우

```bash
# Filebeat 로그 확인
docker-compose logs filebeat
```

### Slack 알림이 오지 않는 경우

- `.env` 파일의 `SLACK_WEBHOOK_URL` 확인
- Webhook URL 유효성 테스트

## 라이선스

MIT License

## 작성자

Jesper - 보안 관제 직무 지원용 포트폴리오 프로젝트

## 참고 자료

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Elasticsearch Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)