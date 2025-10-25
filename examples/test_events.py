#!/usr/bin/env python3
"""
보안 이벤트 테스트 스크립트
다양한 보안 이벤트를 Mini-SIEM 시스템에 전송하여 위협 탐지를 테스트합니다.
"""

import requests
import time
import json
from datetime import datetime

# API 설정
API_URL = "http://localhost:8000"
API_KEY = "your_api_key_here"  # .env 파일의 API_KEY와 동일하게 설정

HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY
}


def send_event(event_data):
    """이벤트 전송"""
    try:
        response = requests.post(f"{API_URL}/log", json=event_data, headers=HEADERS)
        print(f"✅ Event sent: {event_data['event_type']}")
        print(f"   Response: {response.json()}")
        print()
        return response.json()
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def test_brute_force_attack():
    """Brute Force 공격 테스트 (로그인 실패 5회 이상)"""
    print("=" * 60)
    print("🧪 TEST 1: Brute Force Attack (Multiple Failed Logins)")
    print("=" * 60)

    event = {
        "event_type": "login_failed",
        "source_ip": "192.168.1.100",
        "username": "admin",
        "count": 8,
        "description": "Multiple failed login attempts",
        "raw_log": "2025-10-25 10:30:00 - Failed login attempt for user 'admin' from 192.168.1.100"
    }
    send_event(event)
    time.sleep(1)


def test_suspicious_time_login():
    """비정상 시간대 로그인 테스트 (새벽 3시)"""
    print("=" * 60)
    print("🧪 TEST 2: Suspicious Time Login (Off-hours Access)")
    print("=" * 60)

    # 시스템 시간이 새벽 시간대가 아니더라도 이벤트 타입으로 테스트 가능
    event = {
        "event_type": "suspicious_login",
        "source_ip": "10.0.0.50",
        "username": "developer",
        "count": 1,
        "description": "Login attempt at 03:00 AM",
        "metadata": {"login_time": "03:00:00"}
    }
    send_event(event)
    time.sleep(1)


def test_sql_injection():
    """SQL Injection 공격 테스트"""
    print("=" * 60)
    print("🧪 TEST 3: SQL Injection Attack")
    print("=" * 60)

    event = {
        "event_type": "sql_injection",
        "source_ip": "172.16.0.200",
        "username": "attacker",
        "count": 1,
        "description": "SQL Injection attempt detected",
        "raw_log": "SELECT * FROM users WHERE id = 1 OR 1=1; DROP TABLE users;--"
    }
    send_event(event)
    time.sleep(1)


def test_privilege_escalation():
    """권한 상승 시도 테스트"""
    print("=" * 60)
    print("🧪 TEST 4: Privilege Escalation Attempt")
    print("=" * 60)

    event = {
        "event_type": "privilege_escalation",
        "source_ip": "192.168.10.50",
        "username": "user123",
        "count": 1,
        "description": "Unauthorized sudo access attempt",
        "raw_log": "user123 attempted: sudo -i"
    }
    send_event(event)
    time.sleep(1)


def test_botnet_activity():
    """봇넷 활동 테스트"""
    print("=" * 60)
    print("🧪 TEST 5: Botnet Activity (Multiple Connections)")
    print("=" * 60)

    event = {
        "event_type": "network_anomaly",
        "source_ip": "203.0.113.45",
        "count": 25,
        "description": "Suspicious network activity detected",
        "metadata": {"unique_ips_count": 30, "connection_rate": "500/min"}
    }
    send_event(event)
    time.sleep(1)


def test_normal_login():
    """정상 로그인 테스트 (위협 아님)"""
    print("=" * 60)
    print("🧪 TEST 6: Normal Login (No Threat)")
    print("=" * 60)

    event = {
        "event_type": "login_success",
        "source_ip": "192.168.1.10",
        "username": "john.doe",
        "count": 1,
        "description": "Successful login"
    }
    send_event(event)
    time.sleep(1)


def test_file_access():
    """의심스러운 파일 접근 테스트"""
    print("=" * 60)
    print("🧪 TEST 7: Suspicious File Access")
    print("=" * 60)

    event = {
        "event_type": "file_access",
        "source_ip": "192.168.5.100",
        "username": "hacker",
        "count": 1,
        "description": "Attempted access to sensitive file",
        "raw_log": "Access attempt: /etc/shadow by user 'hacker'"
    }
    send_event(event)
    time.sleep(1)


def check_dashboard():
    """대시보드 통계 확인"""
    print("=" * 60)
    print("📊 Checking Dashboard Statistics")
    print("=" * 60)

    try:
        response = requests.get(f"{API_URL}/dashboard")
        stats = response.json()
        print(json.dumps(stats, indent=2))
    except Exception as e:
        print(f"❌ Error: {e}")


def check_incidents():
    """인시던트 목록 확인"""
    print("=" * 60)
    print("🚨 Checking Active Incidents")
    print("=" * 60)

    try:
        response = requests.get(f"{API_URL}/incidents")
        incidents = response.json()
        print(f"Total Incidents: {incidents['count']}")
        for inc in incidents['incidents'][:5]:  # 최근 5개만 출력
            print(f"\n  ID: {inc['id']}")
            print(f"  Title: {inc['title']}")
            print(f"  Severity: {inc['severity']}")
            print(f"  Status: {inc['status']}")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    """메인 테스트 함수"""
    print("\n" + "=" * 60)
    print("🔐 Mini-SIEM Security Event Testing Suite")
    print("=" * 60 + "\n")

    # Health Check
    try:
        response = requests.get(f"{API_URL}/")
        print(f"✅ Server Status: {response.json()['status']}")
        print(f"   Version: {response.json()['version']}\n")
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("Please make sure the server is running (docker-compose up)")
        return

    # 테스트 실행
    test_brute_force_attack()
    test_suspicious_time_login()
    test_sql_injection()
    test_privilege_escalation()
    test_botnet_activity()
    test_normal_login()
    test_file_access()

    # 결과 확인
    time.sleep(2)
    check_dashboard()
    print()
    check_incidents()

    print("\n" + "=" * 60)
    print("✅ Test Suite Completed!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
