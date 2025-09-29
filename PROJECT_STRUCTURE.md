# Email Service Project Structure

## Clean Production Structure

```
email-service-python/
├── app/                          # Main application directory
│   ├── api/                      # FastAPI endpoints
│   │   ├── auth.py              # Authentication endpoints
│   │   ├── database.py          # Database configuration endpoints
│   │   ├── email.py             # Email processing endpoints
│   │   └── service.py           # Service control endpoints
│   ├── core/                     # Core application modules
│   │   ├── config.py            # Application configuration and models
│   │   └── security.py          # JWT and security utilities
│   ├── models/                   # Data models
│   │   ├── auth.py              # Authentication models
│   │   ├── database.py          # Database models
│   │   └── email.py             # Email models
│   ├── services/                 # Business logic services
│   │   ├── database_manager.py  # Database connection manager
│   │   ├── email_service.py     # Main email service (PDF protection + signing)
│   │   └── email_worker.py      # Background email worker
│   ├── utils/                    # Utility modules
│   │   ├── pdf_utils.py         # PDF password protection utilities
│   │   └── pdf_signing.py       # PDF digital signing utilities
│   └── main.py                  # FastAPI application entry point
├── .env                         # Environment configuration (excluded from git)
├── .env.sample                  # Sample environment configuration
├── .gitignore                   # Git ignore file
├── requirements.txt             # Python dependencies
├── docker-compose.yml          # Docker composition
├── Dockerfile                  # Docker container configuration
├── start.py                    # Application startup script
└── README.md                   # Project documentation
```

## Key Features

### ✅ **Email Processing**
- Password protection for PDF attachments
- Digital signing of PDFs
- SMTP connection pooling
- Background queue processing
- CC email support

### ✅ **API Endpoints**
- JWT authentication
- Database configuration
- Service control
- Email queue management

### ✅ **Database Integration**
- SQL Server support
- Email queue management
- SMTP configuration storage
- PDF metadata tracking

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   cp .env.sample .env
   # Edit .env with your database and SMTP settings
   ```

3. **Run the service:**
   ```bash
   python start.py
   ```

4. **Access Swagger UI:**
   ```
   http://localhost:8000/docs
   ```

## Removed Files

**Test Files** (removed for production):
- All `test_*.py` files
- Debug and diagnostic scripts
- Setup utility scripts

**Unused Configs**:
- `config/` directory (database config now handled via API)
- `logs/` directory (empty)
- Unused security modules

**Documentation**:
- Duplicate documentation files
- Quick start guides (consolidated into README)