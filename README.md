# Python Email Service API

A comprehensive RESTful API service for email processing with queue management, built with FastAPI and SQL Server.

## 🚀 Features

- **Authentication**: JWT-based secure authentication
- **Database Integration**: SQL Server connection with connection pooling
- **Email Processing**: Queue-based email processing with PDF attachments
- **Scheduling**: Configurable background processing with APScheduler
- **Monitoring**: Real-time dashboard and service status
- **Security**: Encrypted configuration storage
- **API Documentation**: Auto-generated Swagger/OpenAPI documentation

## 📋 Requirements

- Python 3.11+
- SQL Server (with ODBC Driver 17)
- Redis (optional, for advanced features)

## 🛠️ Installation & Running

### 🚀 Quick Start (Recommended)

**Option 1: Using the run script (Python)**
```bash
python run.py
```

**Option 2: Using the batch file (Windows)**
```bash
run.bat
```

**Option 3: Manual installation**
```bash
# 1. Install core dependencies
pip install fastapi uvicorn pydantic python-jose passlib email-validator sqlalchemy apscheduler aiosmtplib

# 2. Start the server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 🐳 Docker Installation
```bash
# Using Docker Compose (Recommended)
docker-compose up -d

# View logs
docker-compose logs -f email-service

# Stop services
docker-compose down
```

## 🐳 Docker Deployment

### Using Docker Compose
```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Using Docker only
```bash
# Build image
docker build -t email-service .

# Run container
docker run -d -p 8000:8000 --name email-service-container email-service
```

## 📚 API Documentation

Once the application is running, access the documentation at:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## 🔧 Configuration

### Database Setup
1. Create the required tables in your SQL Server database:

```sql
-- Email Configuration Table
CREATE TABLE tbl_EMailParameters (
    id INT IDENTITY(1,1) PRIMARY KEY,
    SMTPServer NVARCHAR(255),
    SMTPPort INT,
    SMTPAccountName NVARCHAR(255),
    SMTPPassword NVARCHAR(255),
    SMTPMailId NVARCHAR(255),
    ApplicationName NVARCHAR(255),
    SMTPSSLFlag NVARCHAR(1),
    ParamCode NVARCHAR(50),
    IsActive NVARCHAR(1) DEFAULT 'Y'
);

-- Email Queue Table
CREATE TABLE Digital_Emaildetails (
    dd_srno INT IDENTITY(1,1) PRIMARY KEY,
    dd_document VARBINARY(MAX),
    dd_filename NVARCHAR(255),
    dd_toEmailid NVARCHAR(500) NOT NULL,
    dd_ccEmailid NVARCHAR(500),
    dd_subject NVARCHAR(500) NOT NULL,
    dd_bodyText NTEXT NOT NULL,
    dd_SendFlag NVARCHAR(1) DEFAULT 'N',
    dd_EmailParamCode NVARCHAR(50),
    dd_RetryCount INT DEFAULT 0,
    dd_SentDate DATETIME,
    dd_BounceReason NVARCHAR(500),
    dd_LastRetryDate DATETIME,
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);
```

### Initial Configuration
1. **Authenticate**: POST `/api/authenticate`
   ```json
   {
     "username": "admin",
     "password": "admin"
   }
   ```

2. **Configure Database**: POST `/api/save-config`
   ```json
   {
     "server": "localhost",
     "port": 1433,
     "user": "sa",
     "password": "YourPassword123",
     "database": "EmailDB"
   }
   ```

3. **Configure Email Service**: POST `/api/save-email-config`
   ```json
   {
     "startTime": "09:00",
     "endTime": "18:00",
     "interval": 30,
     "intervalUnit": "minutes",
     "dbRequestTimeout": 30000,
     "dbConnectionTimeout": 30000,
     "username": "emailuser",
     "password": "emailpass"
   }
   ```

4. **Start Email Service**: POST `/api/service-control`
   ```json
   {
     "action": "start",
     "user": "admin"
   }
   ```

## 🧪 Testing

### Using curl
```bash
# Health check
curl http://localhost:8000/health

# Authenticate
curl -X POST "http://localhost:8000/api/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Test email
curl -X POST "http://localhost:8000/api/email-test" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

### Using Postman
Import the provided Postman collection for comprehensive API testing.

## 📁 Project Structure

```
email-service-python/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── api/                    # API endpoints
│   │   ├── auth.py            # Authentication
│   │   ├── database.py        # Database configuration
│   │   ├── email.py           # Email processing
│   │   └── service.py         # Service control
│   ├── core/                   # Core functionality
│   │   ├── config.py          # Configuration models
│   │   └── security.py        # Security & encryption
│   ├── models/                 # Data models
│   │   ├── auth.py            # Auth models
│   │   ├── database.py        # Database models
│   │   └── email.py           # Email models
│   └── services/               # Business logic
│       ├── database_manager.py # Database operations
│       ├── email_service.py    # Email functionality
│       └── email_worker.py     # Background processing
├── config/                     # Configuration files
├── temp/                       # Temporary files
├── logs/                       # Log files
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker configuration
├── docker-compose.yml          # Docker Compose setup
└── README.md                   # This file
```

## 🔐 Security Features

- JWT-based authentication with configurable expiration
- Encrypted storage for sensitive configuration data
- Password hashing using bcrypt
- SQL injection prevention with parameterized queries
- CORS configuration for cross-origin requests

## 📊 Monitoring & Logging

- Real-time dashboard with service statistics
- Health check endpoints
- Structured logging with configurable levels
- Email processing statistics and error tracking

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the GitHub repository
- Check the API documentation at `/docs`
- Review the health check endpoint at `/health`

## 🎯 Roadmap

- [ ] WebSocket support for real-time updates
- [ ] Email template management
- [ ] Advanced retry logic with exponential backoff
- [ ] Metrics export (Prometheus format)
- [ ] Multi-tenant support
- [ ] Email delivery tracking