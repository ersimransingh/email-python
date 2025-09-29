#!/usr/bin/env python3
"""
Simple starter script for the Email Service API
"""

import subprocess
import sys
import os

def install_dependencies():
    """Install core dependencies"""
    deps = [
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "pydantic>=2.5.0",
        "python-jose>=3.3.0",
        "passlib[bcrypt]>=1.7.4",
        "email-validator>=2.0.0",
        "sqlalchemy>=2.0.0",
        "apscheduler>=3.10.0",
        "aiosmtplib>=3.0.0"
    ]

    print("Installing dependencies...")
    for dep in deps:
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", dep],
                          capture_output=True, check=False)
        except:
            pass

    print("Dependencies installed!")

def main():
    """Main function"""
    print("Email Service API - Starting...")
    print("=" * 50)

    # Install dependencies
    install_dependencies()

    print("\nStarting server...")
    print("Documentation: http://localhost:8000/docs")
    print("Health check: http://localhost:8000/health")
    print("Press Ctrl+C to stop")
    print("-" * 50)

    # Start server
    try:
        import uvicorn
        uvicorn.run(
            "app.main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except ImportError:
        print("Installing uvicorn...")
        subprocess.run([sys.executable, "-m", "pip", "install", "uvicorn"])
        import uvicorn
        uvicorn.run(
            "app.main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\nServer stopped.")

if __name__ == "__main__":
    main()