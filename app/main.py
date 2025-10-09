import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import auth, database, email, service
from app.core.config import settings
from app.services.database_manager import db_manager
from app.services.email_worker import email_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    print("Starting Email Service API...")

    # Initialize database connection if configuration exists
    try:
        if db_manager.config_exists():
            config = await db_manager.load_config()
            if config:
                await db_manager.initialize_connection(config)
                print("Database connection initialized")
    except Exception as e:
        print(f"Warning: Could not initialize database connection: {e}")

    # Auto-start email worker if configuration exists
    try:
        if email_worker.config_exists():
            await email_worker.start()
            print("Email worker started automatically")
    except Exception as e:
        print(f"Warning: Could not start email worker: {e}")

    yield

    # Cleanup
    print("Shutting down Email Service API...")
    try:
        await email_worker.stop()
        await db_manager.close_connection()
    except Exception as e:
        print(f"Warning: Error during cleanup: {e}")


app = FastAPI(
    title="Email Service API",
    description="""
    # Email Processing Service with Queue Management

    A comprehensive email service API that provides:
    - **Authentication**: JWT-based secure authentication
    - **Database Configuration**: SQL Server connection management
    - **Email Processing**: Queue-based email processing with attachments
    - **Scheduling**: Configurable email processing schedules
    - **Monitoring**: Real-time dashboard and service status

    ## Features
    - 🔐 Secure JWT authentication
    - 📊 SQL Server integration
    - 📧 SMTP email processing with attachments
    - ⏰ Scheduled background processing
    - 📈 Dashboard monitoring
    - 🛠️ Service control (start/stop)
    """,
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Internal server error",
            "detail": str(exc) if app.debug else "An unexpected error occurred"
        }
    )


# Include routers
app.include_router(auth.router, prefix="/api", tags=["Authentication"])
app.include_router(database.router, prefix="/api", tags=["Database Configuration"])
app.include_router(email.router, prefix="/api", tags=["Email Processing"])
app.include_router(service.router, prefix="/api", tags=["Service Control"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint - API information"""
    return {
        "message": "Email Service API is running",
        "version": "1.0.0",
        "status": "healthy",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }


@app.get("/health", tags=["Health Check"])
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        db_status = "unknown"
        if db_manager.config_exists():
            db_info = await db_manager.check_database_status()
            db_status = "connected" if db_info.get("connected") else "disconnected"

        # Check email worker status
        worker_status_info = await email_worker.get_status()
        worker_status = worker_status_info.status

        return {
            "status": "healthy",
            "service": "email-service",
            "timestamp": "2024-01-01T00:00:00Z",
            "components": {
                "api": "healthy",
                "database": db_status,
                "email_worker": worker_status
            }
        }
    except Exception as e:
        return {
            "status": "degraded",
            "service": "email-service",
            "error": str(e),
            "components": {
                "api": "healthy",
                "database": "error",
                "email_worker": "error"
            }
        }


@app.get("/api/info", tags=["Information"])
async def api_info():
    """Get API information and available endpoints"""
    return {
        "name": "Email Service API",
        "version": "1.0.0",
        "description": "RESTful API service with background email processing",
        "endpoints": {
            "authentication": [
                "POST /api/authenticate - Login and get JWT token",
                "GET /api/authenticate - Verify JWT token"
            ],
            "database": [
                "POST /api/save-config - Save database configuration",
                "GET /api/get-current-config - Get current configuration",
                "GET /api/check-db-config - Check if database config exists",
                "POST /api/test-connection - Test database connection",
                "POST /api/test-db-status - Test current database status"
            ],
            "email": [
                "POST /api/save-email-config - Save email service configuration",
                "GET /api/check-email-config - Check if email config exists",
                "GET /api/certificate-status - Check USB certificate availability",
                "GET /api/certificates - List all certificates on the computer",
                "POST /api/email-test - Send test email",
                "POST /api/email-force-process - Force process email queue",
                "GET /api/dashboard - Get dashboard data"
            ],
            "service": [
                "POST /api/service-control - Start/stop email service",
                "GET /api/service-status - Get service status"
            ]
        },
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_json": "/openapi.json"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )