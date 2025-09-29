from pydantic import BaseModel
from typing import Optional, Dict, Any


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[Dict[str, Any]] = None


class TokenVerifyResponse(BaseModel):
    success: bool
    user: Optional[Dict[str, Any]] = None
    message: Optional[str] = None