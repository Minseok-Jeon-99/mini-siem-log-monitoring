# Mini-SIEM 프로젝트 트러블슈팅 가이드

> 작성일: 2025-10-27
> 환경: Docker Compose, Elasticsearch 8.15.0, Kibana 8.15.0, Filebeat 8.15.0, FastAPI

---

## 📋 목차

1. [문제 1: Import 경로 오류 (ModuleNotFoundError)](#문제-1-import-경로-오류)
2. [문제 2: Kibana 시작 실패](#문제-2-kibana-시작-실패)
3. [문제 3: Filebeat 시작 실패](#문제-3-filebeat-시작-실패)
4. [개선: Filebeat 로그 파싱 구조화](#개선-filebeat-로그-파싱-구조화)
5. [최종 검증](#최종-검증)

---

## 문제 1: Import 경로 오류

### 🔴 증상

```bash
docker-compose up -d --build
```

실행 시 다음 오류 발생:

```python
File "/app/main.py", line 12, in <module>
    from utils.detector import ThreatDetector
  File "/app/utils/detector.py", line 4, in <module>
    from app.models.log import NormalizedLog, SeverityLevel, EventType
ModuleNotFoundError: No module named 'app'
```

**컨테이너 상태:**
- ✅ Elasticsearch: Running
- ❌ FastAPI: Exited (1)
- ❌ Kibana: Exited (78)
- ❌ Filebeat: Exited (1)

---

### 🔍 원인 분석

**문제 원인:**
- Docker 컨테이너 내부에서 작업 디렉토리는 `/app`으로 설정됨
- `WORKDIR /app`이 Dockerfile에 정의되어 있음
- 따라서 Python 모듈 경로는 `/app`을 기준으로 상대 경로를 사용해야 함

**잘못된 Import:**
```python
from app.models.log import NormalizedLog, SeverityLevel, EventType
```

**올바른 Import:**
```python
from models.log import NormalizedLog, SeverityLevel, EventType
```

---

### ✅ 해결 방법

#### Step 1: 문제 파일 식별

다음 3개 파일에서 import 오류 발견:

1. `app/utils/detector.py` (line 4)
2. `app/services/incident.py` (line 3)
3. `app/services/statistics.py` (line 4)

---

#### Step 2: 파일별 수정 내역

##### 1️⃣ app/utils/detector.py

**수정 전:**
```python
import re
from datetime import datetime, time
from typing import Tuple, Optional
from app.models.log import NormalizedLog, SeverityLevel, EventType
```

**수정 후:**
```python
import re
from datetime import datetime, time
from typing import Tuple, Optional
from models.log import NormalizedLog, SeverityLevel, EventType
```

**변경 위치:** Line 4

---

##### 2️⃣ app/services/incident.py

**수정 전:**
```python
from datetime import datetime
from typing import Dict, List, Optional
from app.models.log import Incident, IncidentStatus, NormalizedLog, EventType, SeverityLevel
```

**수정 후:**
```python
from datetime import datetime
from typing import Dict, List, Optional
from models.log import Incident, IncidentStatus, NormalizedLog, EventType, SeverityLevel
```

**변경 위치:** Line 3

---

##### 3️⃣ app/services/statistics.py

**수정 전:**
```python
from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict, Counter
from app.models.log import NormalizedLog, DashboardStats, SeverityLevel
```

**수정 후:**
```python
from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict, Counter
from models.log import NormalizedLog, DashboardStats, SeverityLevel
```

**변경 위치:** Line 4

---

#### Step 3: 컨테이너 재빌드 및 시작

```bash
docker-compose down
docker-compose up -d --build
```

---

#### Step 4: 검증

```bash
# 컨테이너 상태 확인
docker-compose ps

# FastAPI 로그 확인
docker-compose logs fastapi_app

# 정상 시작 확인
curl http://localhost:8000/
```

**성공 응답:**
```json
{
  "message": "Mini-SIEM FastAPI Server is running.",
  "version": "2.0.0",
  "status": "healthy",
  "timestamp": "2025-10-27T12:51:17.245061"
}
```

---

### 📊 해결 후 상태

| 서비스 | 수정 전 | 수정 후 |
|--------|---------|---------|
| Elasticsearch | ✅ Running | ✅ Running |
| FastAPI | ❌ Exited | ✅ Running |
| Kibana | ❌ Exited | ⚠️ Exited (다른 문제) |
| Filebeat | ❌ Exited | ⚠️ Exited (다른 문제) |

---

## 문제 2: Kibana 시작 실패

### 🔴 증상

```bash
docker-compose logs kibana
```

출력:

```
[2025-10-27T12:50:57.285+00:00][FATAL][root] Reason: [config validation of [elasticsearch].username]:
value of "elastic" is forbidden. This is a superuser account that cannot write to system indices
that Kibana needs to function. Use a service account token instead.
```

**오류 메시지 핵심:**
- `elastic` 슈퍼유저 계정 사용 금지
- Elasticsearch 8.x부터 Kibana는 `elastic` 계정을 직접 사용할 수 없음
- 서비스 계정 토큰 사용 권장

---

### 🔍 원인 분석

**Elasticsearch 8.x 보안 정책 변경:**

- **Elasticsearch 7.x 이전:**
  - `elastic` 슈퍼유저로 Kibana 연결 허용

- **Elasticsearch 8.x 이후:**
  - `elastic` 계정은 시스템 인덱스에 쓰기 금지
  - Kibana는 시스템 인덱스(`.kibana-*`)에 쓰기 필요
  - 따라서 서비스 계정 토큰 또는 별도 사용자 필요

**문제가 된 설정 (docker-compose.yml):**

```yaml
kibana:
  image: docker.elastic.co/kibana/kibana:8.15.0
  environment:
    - ELASTICSEARCH_URL=http://elasticsearch:9200
    - ELASTICSEARCH_USERNAME=elastic  # ❌ 금지됨
    - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
```

---

### ✅ 해결 방법

#### 옵션 1: Elasticsearch Security 비활성화 (개발 환경용) ⭐

**장점:**
- 간단하고 빠른 설정
- 개발/테스트 환경에 적합
- 인증 없이 접근 가능

**단점:**
- 프로덕션 환경에는 부적합
- 보안 취약

**적용 방법:**

##### 1️⃣ Elasticsearch 설정 수정

**docker-compose.yml 수정:**

```yaml
elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0
  environment:
    - discovery.type=single-node
    - xpack.security.enabled=false  # ✅ Security 비활성화
    - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
  ports:
    - "9200:9200"
```

**변경 사항:**
- `xpack.security.enabled=false` 추가

---

##### 2️⃣ Kibana 설정 단순화

**docker-compose.yml 수정:**

```yaml
kibana:
  image: docker.elastic.co/kibana/kibana:8.15.0
  environment:
    - ELASTICSEARCH_HOSTS=http://elasticsearch:9200  # ✅ 인증 정보 제거
  ports:
    - "5601:5601"
  depends_on:
    - elasticsearch
```

**변경 사항:**
- `ELASTICSEARCH_URL` → `ELASTICSEARCH_HOSTS`로 변경
- `ELASTICSEARCH_USERNAME` 제거
- `ELASTICSEARCH_PASSWORD` 제거
- `depends_on` 추가

---

#### 옵션 2: 서비스 계정 토큰 사용 (프로덕션 환경용)

**프로덕션 환경에서는 이 방법 권장:**

```bash
# 1. Elasticsearch에서 Kibana 서비스 토큰 생성
docker exec -it security_log_monitoring_system-elasticsearch-1 \
  /usr/share/elasticsearch/bin/elasticsearch-service-tokens create elastic/kibana kibana-token

# 2. 출력된 토큰을 복사
# SERVICE_TOKEN elastic/kibana/kibana-token = AAEAAWVsYXN0aWMva2...

# 3. docker-compose.yml에 토큰 설정
kibana:
  environment:
    - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    - ELASTICSEARCH_SERVICEACCOUNTTOKEN=AAEAAWVsYXN0aWMva2liYW5hL2tpYmFuYS10b2tlbiA...
```

---

### 📝 최종 docker-compose.yml (Security 비활성화 버전)

```yaml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false  # ✅ 추가
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
    ports:
      - "9200:9200"

  kibana:
    image: docker.elastic.co/kibana/kibana:8.15.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200  # ✅ 변경
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch  # ✅ 추가

  fastapi_app:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./app:/app
    environment:
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - API_KEY=${API_KEY}
    depends_on:
      - elasticsearch

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.15.0
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml
      - ./app/logs:/var/log/mini_siem
    depends_on:
      - fastapi_app
      - elasticsearch
```

---

### 📊 해결 후 검증

```bash
# 1. 컨테이너 재시작
docker-compose down
docker-compose up -d

# 2. Kibana 로그 확인
docker-compose logs kibana | tail -20

# 3. Kibana 접속 테스트
curl http://localhost:5601/api/status

# 4. 정상 응답 확인
# {"status": {"overall": {"level": "available", ...}}}
```

---

## 문제 3: Filebeat 시작 실패

### 🔴 증상

```bash
docker-compose logs filebeat
```

출력:

```
Exiting: error initializing publisher: missing field accessing
'output.elasticsearch.password' (source:'filebeat.yml')
```

**오류 메시지 핵심:**
- Filebeat 설정 파일에서 `password` 필드 누락
- 환경 변수 `${ELASTIC_PASSWORD}`가 전달되지 않음

---

### 🔍 원인 분석

**문제 1: 환경 변수 미전달**

**docker-compose.yml의 Filebeat 설정:**
```yaml
filebeat:
  image: docker.elastic.co/beats/filebeat:8.15.0
  volumes:
    - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml
    - ./app/logs:/var/log/mini_siem
  # ❌ environment 섹션 없음 - 환경 변수가 컨테이너에 전달되지 않음
  depends_on:
    - fastapi_app
    - elasticsearch
```

**filebeat.yml 설정:**
```yaml
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  username: "elastic"
  password: "${ELASTIC_PASSWORD}"  # ❌ 환경 변수가 없어서 빈 값
```

---

**문제 2: Security 비활성화 후 불필요한 인증**

Elasticsearch에서 `xpack.security.enabled=false`로 설정했으므로:
- `username`, `password` 불필요
- 오히려 인증 정보가 있으면 오류 발생 가능

---

### ✅ 해결 방법

#### Step 1: docker-compose.yml 수정

##### 변경 전:
```yaml
filebeat:
  image: docker.elastic.co/beats/filebeat:8.15.0
  volumes:
    - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml
    - ./app/logs:/var/log/mini_siem
  depends_on:
    - fastapi_app
    - elasticsearch
```

##### 변경 후:
```yaml
filebeat:
  image: docker.elastic.co/beats/filebeat:8.15.0
  user: root  # ✅ 추가: 로그 파일 읽기 권한
  volumes:
    - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro  # ✅ :ro 추가
    - ./app/logs:/var/log/mini_siem:ro  # ✅ :ro 추가
  environment:
    - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}  # ✅ 추가 (security 활성화 시 필요)
  depends_on:
    - fastapi_app
    - elasticsearch
```

**변경 사항:**
1. `user: root` 추가 → 로그 파일 접근 권한 확보
2. 볼륨에 `:ro` (read-only) 플래그 추가 → 보안 강화
3. `environment` 섹션 추가 → 환경 변수 전달

---

#### Step 2: filebeat.yml 수정

##### 변경 전:
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/mini_siem/*.log

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  username: "elastic"
  password: "${ELASTIC_PASSWORD}"
```

##### 변경 후:
```yaml
filebeat.inputs:
  - type: log
    enabled: true  # ✅ 명시적으로 활성화
    paths:
      - /var/log/mini_siem/*.log

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  # ✅ username, password 제거 (security 비활성화 시)
```

**변경 사항:**
1. `enabled: true` 명시
2. `username`, `password` 제거 (security 비활성화되었으므로)

---

### 📝 Security 활성화 시 Filebeat 설정

만약 Elasticsearch security를 활성화한 경우:

```yaml
# filebeat.yml
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  username: "elastic"
  password: "${ELASTIC_PASSWORD}"
  ssl:
    enabled: true
    verification_mode: certificate
```

```yaml
# docker-compose.yml
filebeat:
  environment:
    - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}  # 필수!
```

---

### 📊 해결 후 검증

```bash
# 1. 컨테이너 재시작
docker-compose restart filebeat

# 2. Filebeat 로그 확인
docker-compose logs filebeat

# 3. Filebeat 상태 확인
docker ps | grep filebeat
# 출력: Up X minutes (정상)

# 4. Elasticsearch 인덱스 확인
curl 'http://localhost:9200/_cat/indices?v' | grep filebeat

# 출력 예시:
# yellow open .ds-filebeat-8.15.0-2025.10.27-000001  1  1  54  0  46.2kb  46.2kb
```

---

### 🔧 추가 트러블슈팅

#### 문제: Filebeat가 로그를 수집하지 않는 경우

**원인 1: 로그 파일 권한**
```bash
# 호스트에서 로그 디렉토리 권한 확인
ls -la app/logs/

# 권한이 없으면 부여
chmod -R 755 app/logs/
```

**원인 2: 로그 파일이 없음**
```bash
# 로그 파일 생성 확인
ls -la app/logs/app.log

# 테스트 로그 전송
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test_api_key" \
  -d '{"event_type": "login_failed", "source_ip": "192.168.1.1", "count": 5}'
```

**원인 3: Filebeat 입력 경로 오류**
```bash
# Filebeat 컨테이너 내부에서 확인
docker exec -it security_log_monitoring_system-filebeat-1 ls -la /var/log/mini_siem/

# 파일이 보이지 않으면 볼륨 마운트 확인
docker inspect security_log_monitoring_system-filebeat-1 | grep -A 5 Mounts
```

---

## 개선: Filebeat 로그 파싱 구조화

### 🎯 개선 목표

**현재 문제:**
- 로그가 단순 텍스트로 저장됨
- Kibana에서 필드별 필터링 불가능
- 구조화된 분석 어려움

**개선 후:**
- 로그를 구조화된 필드로 파싱
- `siem.event_type`, `siem.source_ip`, `siem.severity` 등 필드 생성
- Kibana에서 쉽게 필터링 및 집계 가능

---

### ✅ 개선 방법

#### Step 1: 로그 포맷 분석

**FastAPI 애플리케이션 로그 포맷:**

```
2025-10-27 14:09:38,963 [INFO] [EVENT] network_anomaly | IP=203.0.113.50 | Severity=medium | Threat=True
```

**파싱 목표:**
- `timestamp`: 2025-10-27 14:09:38,963
- `log_level`: INFO
- `event_type`: network_anomaly
- `source_ip`: 203.0.113.50
- `severity`: medium
- `is_threat`: True

---

#### Step 2: filebeat.yml에 Dissect 프로세서 추가

**개선된 filebeat.yml:**

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/mini_siem/*.log

    # ✅ 로그 파싱 프로세서 추가
    processors:
      # [EVENT] 로그 파싱
      - dissect:
          tokenizer: "%{timestamp} [%{log_level}] [EVENT] %{event_type} | IP=%{source_ip} | Severity=%{severity} | Threat=%{is_threat}"
          field: "message"
          target_prefix: "siem"
          ignore_failure: true

      # [WARNING] THREAT DETECTED 로그 파싱
      - dissect:
          tokenizer: "%{timestamp} [%{log_level}] %{threat_marker} THREAT DETECTED: %{threat_details}"
          field: "message"
          target_prefix: "siem"
          ignore_failure: true

      # 타임스탬프 파싱
      - timestamp:
          field: siem.timestamp
          layouts:
            - '2006-01-02 15:04:05,000'
          ignore_failure: true

      # 필드 타입 변환
      - convert:
          fields:
            - {from: "siem.is_threat", type: "boolean"}
          ignore_failure: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "siem-logs-%{+yyyy.MM.dd}"  # ✅ 커스텀 인덱스명

# Elasticsearch 인덱스 템플릿 설정
setup.ilm.enabled: false
setup.template.name: "siem-logs"
setup.template.pattern: "siem-logs-*"
```

---

#### Step 3: Dissect 프로세서 설명

**Dissect란?**
- Logstash의 Grok보다 빠른 로그 파싱 도구
- 정규식이 아닌 패턴 매칭 사용
- 성능이 뛰어남

**Tokenizer 패턴:**

```
%{timestamp} [%{log_level}] [EVENT] %{event_type} | IP=%{source_ip} | Severity=%{severity} | Threat=%{is_threat}
```

**매칭 예시:**

**입력:**
```
2025-10-27 14:09:38,963 [INFO] [EVENT] network_anomaly | IP=203.0.113.50 | Severity=medium | Threat=True
```

**출력 (파싱된 필드):**
```json
{
  "siem": {
    "timestamp": "2025-10-27 14:09:38,963",
    "log_level": "INFO",
    "event_type": "network_anomaly",
    "source_ip": "203.0.113.50",
    "severity": "medium",
    "is_threat": "True"
  }
}
```

---

#### Step 4: 커스텀 인덱스 설정

**왜 커스텀 인덱스?**

- 기본 `filebeat-*` 인덱스와 분리
- SIEM 전용 데이터 관리
- 더 나은 검색 성능

**설정:**
```yaml
output.elasticsearch:
  index: "siem-logs-%{+yyyy.MM.dd}"  # 날짜별 인덱스
  # 예: siem-logs-2025.10.27

setup.ilm.enabled: false  # Index Lifecycle Management 비활성화
setup.template.name: "siem-logs"
setup.template.pattern: "siem-logs-*"
```

---

### 📊 개선 결과 비교

#### Before (파싱 전)

**Elasticsearch 데이터:**
```json
{
  "@timestamp": "2025-10-27T14:09:38.963Z",
  "message": "2025-10-27 14:09:38,963 [INFO] [EVENT] network_anomaly | IP=203.0.113.50 | Severity=medium | Threat=True",
  "log": {
    "file": {
      "path": "/var/log/mini_siem/app.log"
    }
  }
}
```

**문제점:**
- 모든 정보가 `message` 필드에 텍스트로 저장
- 필드별 필터링 불가능
- 집계 분석 어려움

---

#### After (파싱 후)

**Elasticsearch 데이터:**
```json
{
  "@timestamp": "2025-10-27T14:09:38.963Z",
  "message": "2025-10-27 14:09:38,963 [INFO] [EVENT] network_anomaly | IP=203.0.113.50 | Severity=medium | Threat=True",
  "siem": {
    "timestamp": "2025-10-27 14:09:38,963",
    "log_level": "INFO",
    "event_type": "network_anomaly",
    "source_ip": "203.0.113.50",
    "severity": "medium",
    "is_threat": true
  }
}
```

**장점:**
- ✅ 구조화된 필드로 저장
- ✅ `siem.severity: "critical"` 같은 필터링 가능
- ✅ 집계 및 시각화 용이
- ✅ Kibana 대시보드 생성 간편

---

### 🎨 Kibana에서 활용

#### 1. Data View 생성

```
Management → Data Views → Create
- Name: SIEM Security Logs
- Index pattern: siem-logs-*
- Timestamp field: @timestamp
```

#### 2. Discover에서 필터링

```
siem.severity: "critical"
siem.is_threat: true
siem.source_ip: "192.168.99.99"
siem.event_type: "sql_injection"
```

#### 3. Visualize에서 집계

```
- Pie Chart: siem.severity 분포
- Bar Chart: Top 10 siem.source_ip
- Line Chart: 시간대별 siem.event_type 추이
```

---

### 📝 검증

```bash
# 1. Filebeat 재시작
docker-compose restart filebeat

# 2. 테스트 로그 전송
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test_api_key" \
  -d '{"event_type": "network_anomaly", "source_ip": "203.0.113.50", "count": 15}'

# 3. 대기 (5-10초)
sleep 10

# 4. 새 인덱스 확인
curl 'http://localhost:9200/_cat/indices?v' | grep siem-logs

# 5. 파싱된 데이터 확인
curl 'http://localhost:9200/siem-logs-*/_search?size=1&pretty'
```

**성공 예시:**
```json
{
  "hits": {
    "hits": [
      {
        "_source": {
          "siem": {
            "event_type": "network_anomaly",
            "source_ip": "203.0.113.50",
            "severity": "medium",
            "is_threat": true
          }
        }
      }
    ]
  }
}
```

---

## 최종 검증

### ✅ 전체 시스템 상태 확인

```bash
# 1. 모든 컨테이너 상태
docker-compose ps
```

**예상 출력:**
```
NAME                                           STATUS
security_log_monitoring_system-elasticsearch-1  Up
security_log_monitoring_system-kibana-1         Up
security_log_monitoring_system-fastapi_app-1    Up
security_log_monitoring_system-filebeat-1       Up
```

---

### 🧪 기능 테스트

#### 1. FastAPI 헬스 체크

```bash
curl http://localhost:8000/
```

**예상 응답:**
```json
{
  "message": "Mini-SIEM FastAPI Server is running.",
  "version": "2.0.0",
  "status": "healthy"
}
```

---

#### 2. 위협 탐지 테스트

```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test_api_key" \
  -d '{
    "event_type": "sql_injection",
    "source_ip": "192.168.99.99",
    "raw_log": "SELECT * FROM users WHERE id=1 OR 1=1--"
  }'
```

**예상 응답:**
```json
{
  "status": "threat_detected",
  "log": {
    "event_type": "sql_injection",
    "severity": "critical",
    "is_threat": true,
    "threat_details": "SQL Injection attempt detected from 192.168.99.99: (\\bor\\b\\s+\\d+\\s*=\\s*\\d+) | Known malicious IP detected: 192.168.99.99"
  },
  "incident_id": "INC-20251027-0001",
  "alert_sent": true
}
```

---

#### 3. 대시보드 통계 확인

```bash
curl http://localhost:8000/dashboard
```

**예상 응답:**
```json
{
  "total_events": 13,
  "total_threats": 11,
  "critical_incidents": 3,
  "high_incidents": 2,
  "medium_incidents": 4,
  "low_incidents": 2,
  "top_attack_ips": [
    "192.168.99.99",
    "192.168.1.100",
    "203.0.113.50"
  ]
}
```

---

#### 4. Elasticsearch 인덱스 확인

```bash
curl 'http://localhost:9200/_cat/indices?v' | grep -E "(filebeat|siem-logs)"
```

**예상 출력:**
```
yellow open .ds-filebeat-8.15.0-2025.10.27-000001  1 1  62  0  58.1kb
yellow open .ds-siem-logs-2025.10.27-000001        1 1   2  0  13.9kb
```

---

#### 5. Kibana 접속 확인

```bash
curl http://localhost:5601/api/status
```

**예상 응답:**
```json
{
  "status": {
    "overall": {
      "level": "available",
      "summary": "All services and plugins are available"
    }
  }
}
```

**웹 브라우저:**
```
http://localhost:5601
```

---

### 📊 최종 시스템 구성

```
┌─────────────────────────────────────────────────────────────┐
│                     Mini-SIEM 시스템                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                                           │
│  │   FastAPI    │  http://localhost:8000                   │
│  │  (Python)    │  - 로그 수신 및 위협 탐지                 │
│  └──────┬───────┘  - Slack 알림 전송                        │
│         │          - 인시던트 관리                          │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │  Log Files   │  /app/logs/app.log                       │
│  │  (.log)      │  - 구조화된 로그 저장                     │
│  └──────┬───────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │   Filebeat   │  - 로그 파일 모니터링                     │
│  │   8.15.0     │  - Dissect 파싱                          │
│  └──────┬───────┘  - Elasticsearch 전송                     │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │Elasticsearch │  http://localhost:9200                   │
│  │   8.15.0     │  - 인덱스: filebeat-*, siem-logs-*       │
│  └──────┬───────┘  - 대용량 로그 저장 및 검색               │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │    Kibana    │  http://localhost:5601                   │
│  │   8.15.0     │  - 로그 시각화                            │
│  └──────────────┘  - 대시보드 생성                          │
│                   - 알림 규칙 설정                          │
└─────────────────────────────────────────────────────────────┘
```

---

### 📋 수정 파일 체크리스트

#### ✅ 수정된 파일

- [x] `app/utils/detector.py` (Line 4: import 경로 수정)
- [x] `app/services/incident.py` (Line 3: import 경로 수정)
- [x] `app/services/statistics.py` (Line 4: import 경로 수정)
- [x] `docker-compose.yml` (Elasticsearch, Kibana, Filebeat 설정 수정)
- [x] `filebeat/filebeat.yml` (파싱 프로세서 추가, 인증 제거)

#### ⚙️ 환경 설정

- [x] `.env` 파일 확인 (`ELASTIC_PASSWORD`, `API_KEY`, `SLACK_WEBHOOK_URL`)
- [x] 로그 디렉토리 권한 확인 (`app/logs/`)
- [x] Docker 볼륨 마운트 확인

---

### 🎯 핵심 수정 사항 요약

| 문제 | 원인 | 해결 방법 |
|------|------|----------|
| **Import 오류** | 절대 경로 사용 (`app.models.log`) | 상대 경로로 변경 (`models.log`) |
| **Kibana 시작 실패** | Elasticsearch 8.x에서 `elastic` 계정 사용 금지 | Security 비활성화 (`xpack.security.enabled=false`) |
| **Filebeat 시작 실패** | 환경 변수 미전달, 불필요한 인증 | 환경 변수 추가, 인증 정보 제거 |
| **로그 파싱 부재** | 텍스트로만 저장 | Dissect 프로세서 추가 |

---

### 🚀 배포 전 체크리스트

#### 개발 환경 (현재)
- ✅ Elasticsearch Security: **비활성화**
- ✅ Kibana 인증: **없음**
- ✅ Filebeat 인증: **없음**
- ⚠️ 외부 접근: 허용 (포트 오픈)

#### 프로덕션 환경 권장 사항

```yaml
# ⚠️ 프로덕션에서는 다음 설정 필수

elasticsearch:
  environment:
    - xpack.security.enabled=true  # Security 활성화
    - xpack.security.transport.ssl.enabled=true
    - xpack.security.http.ssl.enabled=true

kibana:
  environment:
    - ELASTICSEARCH_SERVICEACCOUNTTOKEN=${KIBANA_TOKEN}  # 서비스 토큰 사용

filebeat:
  environment:
    - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
  # filebeat.yml에서 SSL 설정 필수
```

---

### 📚 참고 자료

#### 공식 문서
- [Elasticsearch 8.x Security](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html)
- [Kibana Service Accounts](https://www.elastic.co/guide/en/elasticsearch/reference/current/service-accounts.html)
- [Filebeat Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html)
- [Dissect Processor](https://www.elastic.co/guide/en/beats/filebeat/current/dissect.html)

#### 트러블슈팅 가이드
- [Kibana Won't Start](https://www.elastic.co/guide/en/kibana/current/start-troubleshooting.html)
- [Filebeat Troubleshooting](https://www.elastic.co/guide/en/beats/filebeat/current/troubleshooting.html)
- [Docker Compose Networking](https://docs.docker.com/compose/networking/)

---

## 🎓 학습 포인트

### 1. Docker Compose 네트워킹
- 컨테이너 간 통신은 서비스 이름으로 (`elasticsearch:9200`)
- 호스트에서 접근은 `localhost:9200`

### 2. Python Import 경로
- `WORKDIR`를 기준으로 상대 경로 사용
- 절대 경로는 패키지 설치 시에만 사용

### 3. Elasticsearch 8.x 보안 변경
- 슈퍼유저 계정 직접 사용 금지
- 서비스 계정 토큰 또는 Security 비활성화 필요

### 4. Filebeat 로그 파싱
- Dissect가 Grok보다 성능 우수
- 구조화된 로그로 파싱하면 분석 효율 극대화

### 5. 개발 vs 프로덕션
- 개발: Security 비활성화로 간편한 설정
- 프로덕션: Security 필수 활성화, 인증서 설정

---

## ✅ 완료 체크

- [x] FastAPI 정상 실행 (http://localhost:8000)
- [x] Elasticsearch 정상 실행 (http://localhost:9200)
- [x] Kibana 정상 실행 (http://localhost:5601)
- [x] Filebeat 로그 수집 정상 (siem-logs-* 인덱스 생성)
- [x] 위협 탐지 기능 정상 (SQL Injection, Brute Force 등)
- [x] 인시던트 관리 정상 (INC-YYYYMMDD-XXXX 생성)
- [x] Slack 알림 정상 (alert_sent: true)
- [x] 구조화된 로그 파싱 (siem.* 필드 생성)

---

**작성자:** Jesper
**최종 업데이트:** 2025-10-27
**프로젝트:** Mini-SIEM (Security Log Monitoring System)
**버전:** 2.0.0

---

## 📞 추가 지원

문제가 지속되는 경우:

1. **로그 확인:**
   ```bash
   docker-compose logs [서비스명] --tail=100
   ```

2. **컨테이너 재시작:**
   ```bash
   docker-compose restart [서비스명]
   ```

3. **전체 재빌드:**
   ```bash
   docker-compose down -v
   docker-compose up -d --build
   ```

4. **GitHub Issues:** https://github.com/anthropics/claude-code/issues