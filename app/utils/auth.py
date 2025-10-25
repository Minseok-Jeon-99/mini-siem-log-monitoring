import os
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv

load_dotenv()

# API 키 헤더 정의
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# 환경 변수에서 API 키 로드
API_KEY = os.getenv("API_KEY", "test_api_key")


def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    API 키 검증 함수

    Args:
        api_key: 요청 헤더에서 전달된 API 키

    Returns:
        검증된 API 키

    Raises:
        HTTPException: API 키가 없거나 유효하지 않은 경우
    """
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key is missing. Please provide 'X-API-Key' header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key. Access denied.",
        )

    return api_key


def get_api_key_optional(api_key: str = Security(api_key_header)) -> str:
    """
    선택적 API 키 검증 (개발/테스트용)

    Args:
        api_key: 요청 헤더에서 전달된 API 키

    Returns:
        API 키 또는 None
    """
    return api_key
