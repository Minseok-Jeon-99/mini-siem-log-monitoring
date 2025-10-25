#!/bin/bash
# Mini-SIEM API 사용 예제 (curl)

API_URL="http://localhost:8000"
API_KEY="your_api_key_here"  # .env 파일의 API_KEY와 동일하게 설정

echo "======================================"
echo "Mini-SIEM API Usage Examples (curl)"
echo "======================================"
echo ""

# 1. Health Check
echo "1️⃣  Health Check"
curl -X GET "$API_URL/" | jq
echo -e "\n"

# 2. Brute Force Attack 이벤트 전송
echo "2️⃣  Sending Brute Force Attack Event"
curl -X POST "$API_URL/log" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "event_type": "login_failed",
    "source_ip": "192.168.1.100",
    "username": "admin",
    "count": 7,
    "description": "Multiple failed login attempts"
  }' | jq
echo -e "\n"

# 3. SQL Injection 이벤트 전송
echo "3️⃣  Sending SQL Injection Event"
curl -X POST "$API_URL/log" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "event_type": "sql_injection",
    "source_ip": "172.16.0.200",
    "username": "attacker",
    "count": 1,
    "raw_log": "SELECT * FROM users WHERE id = 1 OR 1=1--"
  }' | jq
echo -e "\n"

# 4. 권한 상승 시도
echo "4️⃣  Sending Privilege Escalation Event"
curl -X POST "$API_URL/log" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "event_type": "privilege_escalation",
    "source_ip": "192.168.10.50",
    "username": "user123",
    "count": 1,
    "description": "Unauthorized sudo access attempt"
  }' | jq
echo -e "\n"

# 5. 대시보드 통계 조회
echo "5️⃣  Getting Dashboard Statistics"
curl -X GET "$API_URL/dashboard" | jq
echo -e "\n"

# 6. 인시던트 목록 조회
echo "6️⃣  Listing All Incidents"
curl -X GET "$API_URL/incidents" | jq
echo -e "\n"

# 7. Critical 인시던트만 조회
echo "7️⃣  Listing Critical Incidents Only"
curl -X GET "$API_URL/incidents?severity=critical" | jq
echo -e "\n"

# 8. 일일 리포트 조회
echo "8️⃣  Getting Daily Report"
curl -X GET "$API_URL/report/daily" | jq
echo -e "\n"

# 9. 주간 리포트 조회
echo "9️⃣  Getting Weekly Report"
curl -X GET "$API_URL/report/weekly" | jq
echo -e "\n"

# 10. 위협 타임라인 조회 (최근 24시간)
echo "🔟  Getting Threat Timeline (Last 24 hours)"
curl -X GET "$API_URL/threats/timeline?hours=24" | jq
echo -e "\n"

# 11. 인시던트 상태 업데이트
echo "1️⃣1️⃣  Updating Incident Status (requires incident_id)"
# 먼저 인시던트 ID를 가져옴
INCIDENT_ID=$(curl -s "$API_URL/incidents" | jq -r '.incidents[0].id')

if [ "$INCIDENT_ID" != "null" ] && [ -n "$INCIDENT_ID" ]; then
  echo "Updating incident: $INCIDENT_ID"
  curl -X POST "$API_URL/incidents/$INCIDENT_ID/status?status=analyzing&analyst_notes=Investigation%20started" \
    -H "X-API-Key: $API_KEY" | jq
else
  echo "No incidents found to update"
fi
echo -e "\n"

# 12. API 문서 접속 안내
echo "1️⃣2️⃣  API Documentation"
echo "   Swagger UI: $API_URL/docs"
echo "   ReDoc: $API_URL/redoc"
echo ""

echo "======================================"
echo "✅ All examples completed!"
echo "======================================"