@echo off
echo Email Service API - Windows Batch Starter
echo ==========================================

cd /d "%~dp0"

echo Installing dependencies...
pip install fastapi uvicorn pydantic python-jose passlib email-validator sqlalchemy apscheduler aiosmtplib

echo.
echo Starting Email Service API...
echo Documentation available at: http://localhost:8000/docs
echo.

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

pause