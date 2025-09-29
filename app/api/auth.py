from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime

from app.core.security import SecurityManager
from app.models.auth import LoginRequest, LoginResponse, TokenVerifyResponse

router = APIRouter()
security = HTTPBearer()
security_manager = SecurityManager()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to get current authenticated user"""
    try:
        payload = security_manager.verify_token(credentials.credentials)
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/authenticate", response_model=LoginResponse)
async def authenticate(request: LoginRequest):
    """Authenticate user and return JWT token"""
    try:
        # Load stored email configuration to get credentials
        config_data = security_manager.load_encrypted_config("email")

        if not config_data:
            # Default credentials if no config exists
            if request.username == "admin" and request.password == "admin":
                valid_credentials = True
            else:
                valid_credentials = False
        else:
            # Check against stored credentials
            valid_credentials = (request.username == config_data.get("username") and
                               request.password == config_data.get("password"))

        if valid_credentials:
            # Generate JWT token
            token_data = {
                "username": request.username,
                "timestamp": datetime.now().timestamp()
            }
            token = security_manager.create_access_token(token_data)

            return LoginResponse(
                success=True,
                message="Authentication successful",
                token=token,
                user={"username": request.username}
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}"
        )


@router.get("/authenticate", response_model=TokenVerifyResponse)
async def verify_token(current_user: dict = Depends(get_current_user)):
    """Verify JWT token"""
    return TokenVerifyResponse(
        success=True,
        user={"username": current_user.get("username")},
        message="Token is valid"
    )