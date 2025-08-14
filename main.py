# Vulnerable TodoList Backend
# Educational application with intentional security vulnerabilities

from fastapi import FastAPI, HTTPException, Depends, status, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from typing import Optional, List
from database import get_db_connection
from models import MessageResponse, UserCreate, UserLogin, UserResponse, Token, ErrorResponse, TaskCreate, TaskUpdate, TaskResponse
import os
import jwt
import traceback
import time
import logging
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging for detailed request tracking (vulnerable - too verbose)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Vulnerable JWT configuration (intentionally weak for educational purposes)
SECRET_KEY = "secret123"  # Vulnerable: weak secret key
ALGORITHM = "HS256"

app = FastAPI(
    title="Vulnerable TodoList API", 
    version="1.0.0",
    description="Educational API with intentional vulnerabilities"
)

# Security scheme for JWT
security = HTTPBearer()

# Configure CORS for GitHub Pages (still vulnerable but more specific)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://*.github.io",  # GitHub Pages domains
        "https://pages.github.com",
        "http://localhost:3000",  # Local development
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
        "*"  # Vulnerable: still allows all origins for educational purposes
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Vulnerable request logging middleware (exposes sensitive information)
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Detailed request logging middleware that exposes sensitive information
    This is intentionally vulnerable for educational purposes
    """
    start_time = time.time()
    
    # Log request details (vulnerable - logs sensitive data)
    request_body = None
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.body()
            if body:
                request_body = body.decode('utf-8')
        except Exception as e:
            request_body = f"Error reading body: {str(e)}"
    
    # Get headers (vulnerable - logs authorization headers)
    headers = dict(request.headers)
    
    # Log comprehensive request information
    logger.info(f"""
    === INCOMING REQUEST ===
    Method: {request.method}
    URL: {str(request.url)}
    Client IP: {request.client.host if request.client else 'unknown'}
    User Agent: {headers.get('user-agent', 'unknown')}
    Headers: {json.dumps(headers, indent=2)}
    Query Params: {dict(request.query_params)}
    Body: {request_body}
    Timestamp: {datetime.now().isoformat()}
    """)
    
    # Process the request
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Log response details (vulnerable - may expose sensitive data)
        logger.info(f"""
        === OUTGOING RESPONSE ===
        Status Code: {response.status_code}
        Process Time: {process_time:.4f}s
        Response Headers: {dict(response.headers)}
        """)
        
        # Add custom headers with potentially sensitive information
        response.headers["X-Process-Time"] = str(process_time)
        response.headers["X-Server-Info"] = "FastAPI/Vulnerable-TodoList-1.0"
        response.headers["X-Database-Host"] = os.getenv("DATABASE_HOST", "localhost")
        response.headers["X-Python-Version"] = "3.9+"
        
        return response
        
    except Exception as e:
        process_time = time.time() - start_time
        
        # Log detailed error information (vulnerable)
        logger.error(f"""
        === REQUEST ERROR ===
        Method: {request.method}
        URL: {str(request.url)}
        Error: {str(e)}
        Error Type: {type(e).__name__}
        Process Time: {process_time:.4f}s
        Stack Trace: {traceback.format_exc()}
        Request Body: {request_body}
        Headers: {json.dumps(headers, indent=2)}
        """)
        
        # Return detailed error response (vulnerable)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "message": str(e),
                "error_type": type(e).__name__,
                "timestamp": datetime.now().isoformat(),
                "request_method": request.method,
                "request_url": str(request.url),
                "process_time": process_time,
                "stack_trace": traceback.format_exc(),
                "server_info": {
                    "python_version": "3.9+",
                    "fastapi_version": "0.68+",
                    "database_host": os.getenv("DATABASE_HOST", "localhost"),
                    "environment": os.getenv("ENVIRONMENT", "development")
                }
            }
        )

# Global exception handler for unhandled exceptions (vulnerable)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler that exposes detailed error information
    This is intentionally vulnerable for educational purposes
    """
    logger.error(f"""
    === UNHANDLED EXCEPTION ===
    URL: {request.url}
    Method: {request.method}
    Exception: {str(exc)}
    Exception Type: {type(exc).__name__}
    Stack Trace: {traceback.format_exc()}
    """)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Unhandled Server Error",
            "message": str(exc),
            "exception_type": type(exc).__name__,
            "timestamp": datetime.now().isoformat(),
            "request_details": {
                "method": request.method,
                "url": str(request.url),
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", "unknown")
            },
            "stack_trace": traceback.format_exc(),
            "system_info": {
                "python_version": "3.9+",
                "server": "FastAPI Vulnerable TodoList",
                "database_type": "PostgreSQL",
                "environment_variables": {
                    "DATABASE_HOST": os.getenv("DATABASE_HOST", "not_set"),
                    "DATABASE_NAME": os.getenv("DATABASE_NAME", "not_set"),
                    "ENVIRONMENT": os.getenv("ENVIRONMENT", "development")
                }
            }
        }
    )

# Custom HTTP exception handler (vulnerable)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    HTTP exception handler that exposes additional system information
    This is intentionally vulnerable for educational purposes
    """
    logger.warning(f"""
    === HTTP EXCEPTION ===
    URL: {request.url}
    Method: {request.method}
    Status Code: {exc.status_code}
    Detail: {exc.detail}
    """)
    
    # Enhanced error response with system information
    error_response = {
        "error": "HTTP Exception",
        "status_code": exc.status_code,
        "detail": exc.detail,
        "timestamp": datetime.now().isoformat(),
        "request_info": {
            "method": request.method,
            "url": str(request.url),
            "client_ip": request.client.host if request.client else "unknown"
        }
    }
    
    # Add extra debugging information for certain error codes (vulnerable)
    if exc.status_code == 401:
        error_response["debug_info"] = {
            "jwt_secret_hint": "secret123",
            "algorithm": "HS256",
            "token_location": "Authorization header with Bearer prefix"
        }
    elif exc.status_code == 404:
        error_response["debug_info"] = {
            "available_endpoints": [
                "/auth/register", "/auth/login", "/auth/me",
                "/tasks", "/tasks/{id}", "/health"
            ],
            "database_tables": ["users", "tasks"]
        }
    elif exc.status_code == 500:
        error_response["debug_info"] = {
            "database_connection": "Check DATABASE_URL environment variable",
            "common_issues": [
                "Database connection failed",
                "SQL syntax error",
                "Missing environment variables"
            ]
        }
    
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response
    )

# Database connection on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database connection on startup"""
    try:
        db = get_db_connection()
        db.connect()
        print("Database connected successfully!")
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection on shutdown"""
    try:
        db = get_db_connection()
        db.disconnect()
        print("Database disconnected!")
    except Exception as e:
        print(f"Error disconnecting from database: {e}")

@app.get("/", response_model=MessageResponse)
async def root():
    return MessageResponse(message="Vulnerable TodoList API - Educational Use Only")

@app.get("/health")
async def health_check():
    """Health check endpoint with verbose system information"""
    try:
        db = get_db_connection()
        # Test database connection
        db.execute_query("SELECT 1")
        
        # Vulnerable: expose detailed system information
        system_info = {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now().isoformat(),
            "system_details": {
                "python_version": "3.9+",
                "fastapi_version": "0.68+",
                "server": "FastAPI Vulnerable TodoList",
                "environment": os.getenv("ENVIRONMENT", "development")
            },
            "database_info": {
                "type": "PostgreSQL",
                "host": os.getenv("DATABASE_HOST", "localhost"),
                "database": os.getenv("DATABASE_NAME", "todolist"),
                "user": os.getenv("DATABASE_USER", "postgres"),
                "connection_pool": "active"
            },
            "security_info": {
                "jwt_algorithm": ALGORITHM,
                "jwt_secret_hint": SECRET_KEY[:6] + "...",
                "cors_enabled": True,
                "authentication_required": True
            },
            "available_endpoints": [
                "GET /", "GET /health", "POST /auth/register", 
                "POST /auth/login", "GET /auth/me", "GET /tasks",
                "POST /tasks", "PUT /tasks/{id}", "DELETE /tasks/{id}",
                "GET /tasks/{id}"
            ]
        }
        
        logger.info(f"Health check performed: {json.dumps(system_info, indent=2)}")
        return system_info
        
    except Exception as e:
        error_details = {
            "status": "unhealthy",
            "error": str(e),
            "error_type": type(e).__name__,
            "timestamp": datetime.now().isoformat(),
            "stack_trace": traceback.format_exc(),
            "database_connection_details": {
                "host": os.getenv("DATABASE_HOST", "localhost"),
                "database": os.getenv("DATABASE_NAME", "todolist"),
                "user": os.getenv("DATABASE_USER", "postgres"),
                "port": os.getenv("DATABASE_PORT", "5432")
            },
            "troubleshooting": [
                "Check DATABASE_URL environment variable",
                "Verify PostgreSQL service is running",
                "Confirm database credentials are correct",
                "Check network connectivity to database host"
            ]
        }
        
        logger.error(f"Health check failed: {json.dumps(error_details, indent=2)}")
        
        raise HTTPException(
            status_code=503, 
            detail=error_details
        )

@app.get("/debug/system-info")
async def get_system_info():
    """
    Debug endpoint that exposes detailed system information
    This is intentionally vulnerable for educational purposes
    """
    logger.warning("System info endpoint accessed - this exposes sensitive information!")
    
    return {
        "system_information": {
            "server": "FastAPI Vulnerable TodoList API",
            "version": "1.0.0",
            "python_version": "3.9+",
            "fastapi_version": "0.68+",
            "timestamp": datetime.now().isoformat()
        },
        "environment_variables": {
            "DATABASE_HOST": os.getenv("DATABASE_HOST", "not_set"),
            "DATABASE_NAME": os.getenv("DATABASE_NAME", "not_set"),
            "DATABASE_USER": os.getenv("DATABASE_USER", "not_set"),
            "DATABASE_PORT": os.getenv("DATABASE_PORT", "5432"),
            "ENVIRONMENT": os.getenv("ENVIRONMENT", "development")
        },
        "security_configuration": {
            "jwt_secret_key": SECRET_KEY,  # Vulnerable: exposes secret key
            "jwt_algorithm": ALGORITHM,
            "cors_origins": ["*"],  # Shows CORS is wide open
            "authentication_required": True
        },
        "database_schema": {
            "tables": {
                "users": {
                    "columns": ["id", "username", "password", "email", "created_at"],
                    "vulnerabilities": ["passwords stored in plain text"]
                },
                "tasks": {
                    "columns": ["id", "title", "description", "completed", "user_id", "created_at", "updated_at"],
                    "vulnerabilities": ["no input sanitization", "IDOR in access control"]
                }
            }
        },
        "known_vulnerabilities": [
            "SQL Injection in task search",
            "XSS in task title/description",
            "Plain text password storage",
            "JWT without expiration",
            "IDOR in task operations",
            "Verbose error messages",
            "CORS misconfiguration",
            "Information disclosure"
        ],
        "exploitation_hints": {
            "sql_injection": "Try: '; DROP TABLE tasks; --",
            "xss": "Try: <script>alert('XSS')</script>",
            "idor": "Try accessing /tasks/{other_user_task_id}",
            "jwt": "Secret key is 'secret123'"
        }
    }

# Vulnerable Authentication Functions
def create_access_token(data: dict):
    """Create JWT token without expiration (vulnerable)"""
    to_encode = data.copy()
    # Intentionally no expiration for vulnerability demonstration
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token without expiration check (vulnerable)"""
    try:
        token = credentials.credentials
        # Vulnerable: no expiration verification
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"username": username, "user_id": user_id}
    except jwt.PyJWTError as e:
        # Vulnerable: expose detailed JWT error information
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"JWT Error: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(token_data: dict = Depends(verify_token)):
    """Get current user from token"""
    return token_data

# Authentication Endpoints
@app.post("/auth/register", response_model=dict)
async def register_user(user: UserCreate):
    """Register new user with vulnerable password storage"""
    try:
        db = get_db_connection()
        
        # Check if user already exists
        existing_user = db.execute_query(
            "SELECT id FROM users WHERE username = %s", 
            (user.username,)
        )
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Vulnerable: Store password in plain text
        result = db.execute_query(
            """INSERT INTO users (username, password, email) 
               VALUES (%s, %s, %s) RETURNING id""",
            (user.username, user.password, user.email)  # Plain text password!
        )
        
        user_id = result[0]['id'] if result else None
        
        return {
            "user_id": user_id,
            "message": "User registered successfully",
            "warning": "Password stored in plain text for educational purposes"
        }
        
    except Exception as e:
        # Vulnerable: expose extremely detailed error information
        error_details = {
            "error": "Registration failed",
            "message": str(e),
            "error_type": type(e).__name__,
            "timestamp": datetime.now().isoformat(),
            "stack_trace": traceback.format_exc(),
            "database_info": {
                "host": os.getenv("DATABASE_HOST", "localhost"),
                "database": os.getenv("DATABASE_NAME", "todolist"),
                "user": os.getenv("DATABASE_USER", "postgres")
            },
            "request_data": {
                "username": user.username,
                "email": user.email,
                "password_length": len(user.password)
            },
            "sql_query": f"INSERT INTO users (username, password, email) VALUES ('{user.username}', '{user.password}', '{user.email}')",
            "system_info": {
                "python_version": "3.9+",
                "fastapi_version": "0.68+",
                "environment": os.getenv("ENVIRONMENT", "development")
            }
        }
        
        logger.error(f"Registration failed for user {user.username}: {str(e)}")
        logger.error(f"Full error details: {json.dumps(error_details, indent=2)}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_details
        )

@app.post("/auth/login", response_model=Token)
async def login_user(user_credentials: UserLogin):
    """Login user with vulnerable authentication"""
    try:
        db = get_db_connection()
        
        # Vulnerable: Plain text password comparison
        user_data = db.execute_query(
            "SELECT id, username, password, email, created_at FROM users WHERE username = %s",
            (user_credentials.username,)
        )
        
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        user = user_data[0]
        
        # Vulnerable: Plain text password comparison
        if user['password'] != user_credentials.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Create JWT token without expiration
        access_token = create_access_token(
            data={"sub": user['username'], "user_id": user['id']}
        )
        
        user_response = UserResponse(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            created_at=user['created_at']
        )
        
        return Token(
            access_token=access_token,
            user_info=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Vulnerable: expose extremely detailed error information
        error_details = {
            "error": "Login failed",
            "message": str(e),
            "error_type": type(e).__name__,
            "timestamp": datetime.now().isoformat(),
            "stack_trace": traceback.format_exc(),
            "database_info": {
                "host": os.getenv("DATABASE_HOST", "localhost"),
                "database": os.getenv("DATABASE_NAME", "todolist"),
                "connection_status": "active"
            },
            "authentication_details": {
                "username_provided": user_credentials.username,
                "password_length": len(user_credentials.password),
                "jwt_secret": SECRET_KEY,
                "jwt_algorithm": ALGORITHM
            },
            "sql_query": f"SELECT id, username, password, email, created_at FROM users WHERE username = '{user_credentials.username}'",
            "debug_hints": [
                "Check if user exists in database",
                "Verify password matches (stored in plain text)",
                "Ensure database connection is active"
            ],
            "system_info": {
                "server_time": datetime.now().isoformat(),
                "environment": os.getenv("ENVIRONMENT", "development"),
                "database_type": "PostgreSQL"
            }
        }
        
        logger.error(f"Login failed for user {user_credentials.username}: {str(e)}")
        logger.error(f"Full error details: {json.dumps(error_details, indent=2)}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_details
        )

# Protected endpoint example
@app.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    try:
        db = get_db_connection()
        user_data = db.execute_query(
            "SELECT id, username, email, created_at FROM users WHERE id = %s",
            (current_user["user_id"],)
        )
        
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user = user_data[0]
        return UserResponse(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            created_at=user['created_at']
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get user info: {str(e)}"
        )

# CRUD Endpoints for Tasks (with vulnerabilities)

@app.get("/tasks", response_model=List[TaskResponse])
async def get_tasks(
    search: Optional[str] = Query(None, description="Search tasks by title"),
    current_user: dict = Depends(get_current_user)
):
    """Get user tasks with vulnerable SQL injection in search parameter"""
    try:
        db = get_db_connection()
        
        if search:
            # Vulnerable: Direct string concatenation allows SQL injection
            query = f"""
                SELECT id, title, description, completed, user_id, created_at, updated_at 
                FROM tasks 
                WHERE user_id = {current_user['user_id']} 
                AND title LIKE '%{search}%'
                ORDER BY created_at DESC
            """
            # Intentionally vulnerable - no parameterized query
            tasks_data = db.execute_query(query)
        else:
            # Safe query when no search parameter
            tasks_data = db.execute_query(
                """SELECT id, title, description, completed, user_id, created_at, updated_at 
                   FROM tasks WHERE user_id = %s ORDER BY created_at DESC""",
                (current_user['user_id'],)
            )
        
        tasks = []
        for task in tasks_data:
            tasks.append(TaskResponse(
                id=task['id'],
                title=task['title'],
                description=task['description'],
                completed=task['completed'],
                user_id=task['user_id'],
                created_at=task['created_at'],
                updated_at=task['updated_at']
            ))
        
        return tasks
        
    except Exception as e:
        # Vulnerable: expose extremely detailed error information including SQL injection details
        vulnerable_query = f"SELECT id, title, description, completed, user_id, created_at, updated_at FROM tasks WHERE user_id = {current_user['user_id']} AND title LIKE '%{search if search else ''}%' ORDER BY created_at DESC"
        
        error_details = {
            "error": "Failed to retrieve tasks",
            "message": str(e),
            "error_type": type(e).__name__,
            "timestamp": datetime.now().isoformat(),
            "stack_trace": traceback.format_exc(),
            "sql_injection_info": {
                "vulnerable_query": vulnerable_query,
                "search_parameter": search,
                "user_id": current_user['user_id'],
                "injection_point": "search parameter in LIKE clause",
                "example_payload": "'; DROP TABLE tasks; --"
            },
            "database_schema": {
                "table": "tasks",
                "columns": ["id", "title", "description", "completed", "user_id", "created_at", "updated_at"],
                "relationships": "user_id references users(id)"
            },
            "user_context": {
                "authenticated_user": current_user['username'],
                "user_id": current_user['user_id']
            },
            "debug_info": {
                "database_host": os.getenv("DATABASE_HOST", "localhost"),
                "environment": os.getenv("ENVIRONMENT", "development"),
                "query_execution_time": "N/A due to error"
            }
        }
        
        logger.error(f"Task retrieval failed for user {current_user['username']}: {str(e)}")
        logger.error(f"Vulnerable SQL query: {vulnerable_query}")
        logger.error(f"Full error details: {json.dumps(error_details, indent=2)}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_details
        )

@app.post("/tasks", response_model=TaskResponse)
async def create_task(
    task: TaskCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create new task without input validation (vulnerable to XSS)"""
    try:
        db = get_db_connection()
        
        # Vulnerable: No input sanitization - allows XSS stored attacks
        # Title and description are stored as-is without escaping HTML/JS
        result = db.execute_query(
            """INSERT INTO tasks (title, description, completed, user_id) 
               VALUES (%s, %s, %s, %s) 
               RETURNING id, title, description, completed, user_id, created_at, updated_at""",
            (task.title, task.description, task.completed, current_user['user_id'])
        )
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create task"
            )
        
        task_data = result[0]
        return TaskResponse(
            id=task_data['id'],
            title=task_data['title'],
            description=task_data['description'],
            completed=task_data['completed'],
            user_id=task_data['user_id'],
            created_at=task_data['created_at'],
            updated_at=task_data['updated_at']
        )
        
    except Exception as e:
        # Vulnerable: expose detailed error information
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse(
                error="Failed to create task",
                details=str(e),
                query=f"INSERT INTO tasks (title, description, completed, user_id) VALUES ('{task.title}', '{task.description}', {task.completed}, {current_user['user_id']})",
                stack_trace=traceback.format_exc()
            ).dict()
        )

@app.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(
    task_id: int,
    task_update: TaskUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update task without ownership verification (vulnerable to privilege escalation)"""
    try:
        db = get_db_connection()
        
        # Vulnerable: No ownership verification - users can modify any task by ID
        # Should check if task belongs to current user, but doesn't
        
        # Build dynamic update query
        update_fields = []
        update_values = []
        
        if task_update.title is not None:
            update_fields.append("title = %s")
            update_values.append(task_update.title)
        
        if task_update.description is not None:
            update_fields.append("description = %s")
            update_values.append(task_update.description)
            
        if task_update.completed is not None:
            update_fields.append("completed = %s")
            update_values.append(task_update.completed)
        
        if not update_fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )
        
        # Add updated_at timestamp
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        update_values.append(task_id)
        
        query = f"""
            UPDATE tasks 
            SET {', '.join(update_fields)}
            WHERE id = %s
            RETURNING id, title, description, completed, user_id, created_at, updated_at
        """
        
        result = db.execute_query(query, update_values)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        task_data = result[0]
        return TaskResponse(
            id=task_data['id'],
            title=task_data['title'],
            description=task_data['description'],
            completed=task_data['completed'],
            user_id=task_data['user_id'],
            created_at=task_data['created_at'],
            updated_at=task_data['updated_at']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Vulnerable: expose detailed error information
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse(
                error="Failed to update task",
                details=str(e),
                query=f"UPDATE tasks SET ... WHERE id = {task_id}",
                stack_trace=traceback.format_exc()
            ).dict()
        )

@app.delete("/tasks/{task_id}")
async def delete_task(
    task_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Delete task vulnerable to IDOR (Insecure Direct Object Reference)"""
    try:
        db = get_db_connection()
        
        # Vulnerable: No ownership verification - IDOR vulnerability
        # Any authenticated user can delete any task by guessing the ID
        result = db.execute_query(
            "DELETE FROM tasks WHERE id = %s RETURNING id, title, user_id",
            (task_id,)
        )
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        deleted_task = result[0]
        
        return {
            "message": f"Task '{deleted_task['title']}' deleted successfully",
            "deleted_task_id": deleted_task['id'],
            "original_owner_id": deleted_task['user_id'],  # Vulnerable: exposes other user's ID
            "deleted_by_user_id": current_user['user_id']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        # Vulnerable: expose detailed error information
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse(
                error="Failed to delete task",
                details=str(e),
                query=f"DELETE FROM tasks WHERE id = {task_id}",
                stack_trace=traceback.format_exc()
            ).dict()
        )

@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task_by_id(
    task_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get specific task by ID (vulnerable to IDOR)"""
    try:
        db = get_db_connection()
        
        # Vulnerable: No ownership verification - users can access any task by ID
        task_data = db.execute_query(
            """SELECT id, title, description, completed, user_id, created_at, updated_at 
               FROM tasks WHERE id = %s""",
            (task_id,)
        )
        
        if not task_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        task = task_data[0]
        return TaskResponse(
            id=task['id'],
            title=task['title'],
            description=task['description'],
            completed=task['completed'],
            user_id=task['user_id'],
            created_at=task['created_at'],
            updated_at=task['updated_at']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Vulnerable: expose detailed error information
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse(
                error="Failed to retrieve task",
                details=str(e),
                query=f"SELECT * FROM tasks WHERE id = {task_id}",
                stack_trace=traceback.format_exc()
            ).dict()
        )