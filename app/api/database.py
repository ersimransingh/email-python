from fastapi import APIRouter, HTTPException, Depends, status
from typing import Dict, Any
from datetime import datetime

from app.core.config import DatabaseConfig
from app.services.database_manager import db_manager
from app.api.auth import get_current_user

router = APIRouter()


@router.post("/save-config")
async def save_database_config(
    config: DatabaseConfig,
    current_user: dict = Depends(get_current_user)
):
    """Save database configuration"""
    try:
        # Test the connection first
        success, message, response_time = await db_manager.test_connection(config)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Database connection failed: {message}"
            )

        # Save the configuration
        db_manager.save_config(config)

        # Initialize the connection with the new config
        await db_manager.initialize_connection(config)

        return {
            "success": True,
            "message": "Configuration saved successfully",
            "connection_test": {
                "success": success,
                "message": message,
                "response_time": response_time
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving configuration: {str(e)}"
        )


@router.get("/get-current-config")
async def get_current_config(current_user: dict = Depends(get_current_user)):
    """Get current database and email configuration"""
    try:
        # Get database configuration
        db_config = await db_manager.load_config()
        db_exists = db_manager.config_exists()

        # Get email configuration
        from app.services.email_worker import email_worker
        email_config = await email_worker.load_email_config()
        email_exists = email_worker.config_exists()

        config_data = {
            "database": {
                "exists": db_exists,
                "config": db_config.model_dump() if db_config else None
            },
            "email": {
                "exists": email_exists,
                "config": email_config.model_dump() if email_config else None
            }
        }

        # Remove sensitive information
        if config_data["database"]["config"]:
            config_data["database"]["config"]["password"] = "***"

        if config_data["email"]["config"]:
            config_data["email"]["config"]["password"] = "***"

        return {
            "success": True,
            "config": config_data
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting configuration: {str(e)}"
        )


@router.get("/check-db-config")
async def check_db_config(current_user: dict = Depends(get_current_user)):
    """Check if database configuration exists"""
    try:
        exists = db_manager.config_exists()
        return {"exists": exists}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking configuration: {str(e)}"
        )


@router.post("/test-connection")
async def test_database_connection(
    config: DatabaseConfig,
    current_user: dict = Depends(get_current_user)
):
    """Test database connection with provided configuration"""
    try:
        success, message, response_time = await db_manager.test_connection(config)

        return {
            "success": success,
            "message": message,
            "response_time": response_time,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error testing connection: {str(e)}"
        )


@router.post("/test-db-status")
async def test_current_db_status(current_user: dict = Depends(get_current_user)):
    """Test current database connection status"""
    try:
        status_info = await db_manager.check_database_status()
        return {
            "success": True,
            **status_info
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking database status: {str(e)}"
        )