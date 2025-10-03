#!/usr/bin/env python3
"""
Enhanced Email Service API Starter
Automatically sets up Python 3.11 environment and installs all dependencies
"""

import subprocess
import sys
import os
import venv
import platform
from pathlib import Path

# Configuration
REQUIRED_PYTHON_VERSION = (3, 11)
PROJECT_NAME = "email-service-python"
VENV_NAME = f"{PROJECT_NAME}-venv"

def check_python_version():
    """Check if Python version meets requirements"""
    current_version = sys.version_info[:2]
    print(f"Current Python version: {'.'.join(map(str, sys.version_info[:3]))}")

    if current_version >= REQUIRED_PYTHON_VERSION:
        print(f"✓ Python version meets requirements (>= {'.'.join(map(str, REQUIRED_PYTHON_VERSION))})")
        return True
    else:
        print(f"✗ Python {'.'.join(map(str, REQUIRED_PYTHON_VERSION))} or higher required")
        return False

def find_python311():
    """Find Python 3.11 executable"""
    possible_commands = [
        "python3.11",
        "python311",
        "py -3.11",
        "python",
        "python3"
    ]

    for cmd in possible_commands:
        try:
            result = subprocess.run(
                cmd.split() + ["--version"],
                capture_output=True,
                text=True,
                check=True
            )
            version_str = result.stdout.strip()
            if "3.11" in version_str:
                print(f"✓ Found Python 3.11: {cmd}")
                return cmd.split()[0]  # Return just the command without flags
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    return None

def create_virtual_environment(python_cmd):
    """Create virtual environment using Python 3.11"""
    venv_path = Path.cwd() / VENV_NAME

    if venv_path.exists():
        print(f"✓ Virtual environment already exists: {venv_path}")
        return venv_path

    print(f"Creating virtual environment: {venv_path}")
    try:
        subprocess.run([python_cmd, "-m", "venv", str(venv_path)], check=True)
        print("✓ Virtual environment created successfully")
        return venv_path
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to create virtual environment: {e}")
        return None

def get_venv_python(venv_path):
    """Get Python executable from virtual environment"""
    if platform.system() == "Windows":
        return venv_path / "Scripts" / "python.exe"
    else:
        return venv_path / "bin" / "python"

def install_dependencies(python_exe):
    """Install all project dependencies"""
    requirements_file = Path.cwd() / "requirements.txt"

    if not requirements_file.exists():
        print("✗ requirements.txt not found")
        return False

    print("Installing dependencies from requirements.txt...")
    try:
        # Upgrade pip first
        subprocess.run([str(python_exe), "-m", "pip", "install", "--upgrade", "pip"],
                      check=True, capture_output=True)
        print("✓ pip upgraded")

        # Install requirements
        subprocess.run([str(python_exe), "-m", "pip", "install", "-r", "requirements.txt"],
                      check=True)
        print("✓ All dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install dependencies: {e}")

        # Try installing core dependencies individually
        print("Attempting to install core dependencies individually...")
        core_deps = [
            "fastapi>=0.104.0",
            "uvicorn[standard]>=0.24.0",
            "sqlalchemy>=2.0.0",
            "pyodbc>=5.0.0",
            "aiosmtplib>=3.0.0",
            "python-jose[cryptography]>=3.3.0",
            "pydantic>=2.5.0",
            "apscheduler>=3.10.0",
            "pypdf>=4.0.0",
            "endesive>=2.19.0",
            "PyKCS11>=1.5.18",
            "reportlab>=4.0.0"
        ]

        failed_deps = []
        for dep in core_deps:
            try:
                subprocess.run([str(python_exe), "-m", "pip", "install", dep],
                             check=True, capture_output=True)
                print(f"  ✓ {dep}")
            except subprocess.CalledProcessError:
                print(f"  ✗ {dep}")
                failed_deps.append(dep)

        if failed_deps:
            print(f"Failed to install: {', '.join(failed_deps)}")
            print("The application may still work with core functionality")

        return len(failed_deps) == 0

def start_server(python_exe):
    """Start the FastAPI server"""
    print("\n" + "="*50)
    print("🚀 STARTING EMAIL SERVICE API")
    print("="*50)
    print("📖 Swagger UI: http://localhost:8000/docs")
    print("🔍 Health Check: http://localhost:8000/health")
    print("⚡ Admin Panel: http://localhost:8000/admin")
    print("📧 Email APIs: http://localhost:8000/api/")
    print("="*50)
    print("Press Ctrl+C to stop the server")
    print("-"*50)

    try:
        # Import and start uvicorn
        import uvicorn
        subprocess.run([
            str(python_exe), "-m", "uvicorn",
            "app.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload",
            "--log-level", "info"
        ], check=True)
    except ImportError:
        print("Installing uvicorn...")
        subprocess.run([str(python_exe), "-m", "pip", "install", "uvicorn[standard]"])
        subprocess.run([
            str(python_exe), "-m", "uvicorn",
            "app.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload",
            "--log-level", "info"
        ], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to start server: {e}")

def main():
    """Main setup and startup function"""
    print("🐍 EMAIL SERVICE PYTHON SETUP")
    print("="*50)

    # Step 1: Check current Python or find Python 3.11
    if not check_python_version():
        print("Searching for Python 3.11...")
        python_cmd = find_python311()
        if not python_cmd:
            print("✗ Python 3.11 not found. Please install Python 3.11 first.")
            print("Download from: https://www.python.org/downloads/")
            sys.exit(1)
    else:
        python_cmd = sys.executable

    # Step 2: Create or use virtual environment
    venv_path = create_virtual_environment(python_cmd)
    if not venv_path:
        print("✗ Failed to create virtual environment")
        sys.exit(1)

    # Step 3: Get virtual environment Python
    venv_python = get_venv_python(venv_path)
    if not venv_python.exists():
        print(f"✗ Virtual environment Python not found: {venv_python}")
        sys.exit(1)

    print(f"✓ Using Python: {venv_python}")

    # Step 4: Install dependencies
    if not install_dependencies(venv_python):
        print("⚠️  Some dependencies failed to install, but attempting to start...")

    # Step 5: Start the server
    try:
        start_server(venv_python)
    except Exception as e:
        print(f"✗ Error starting server: {e}")
        print("\nTroubleshooting:")
        print("1. Check if all dependencies are installed")
        print("2. Verify database configuration in .env file")
        print("3. Ensure no other service is running on port 8000")

def print_environment_info():
    """Print environment information for debugging"""
    print("\n📋 ENVIRONMENT INFO")
    print("-"*30)
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    print(f"Working Directory: {os.getcwd()}")
    print(f"Virtual Env: {VENV_NAME}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Setup interrupted by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        print_environment_info()
        sys.exit(1)