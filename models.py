# Pydantic models for data validation
# Vulnerable implementation for educational purposes

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# User Models
class UserBase(BaseModel):
    username: str
    email: Optional[str] = None

class UserCreate(UserBase):
    password: str
    
    # Intentionally minimal validation for educational purposes
    class Config:
        # Allow weak passwords for vulnerability demonstration
        min_anystr_length = 1

class UserResponse(UserBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    username: str
    password: str

# Task Models
class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    completed: bool = False

class TaskCreate(TaskBase):
    # Intentionally no input validation for XSS vulnerability
    pass

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None

class TaskResponse(TaskBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True

# Authentication Models
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_info: UserResponse

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None

# API Response Models
class MessageResponse(BaseModel):
    message: str

class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None
    # Intentionally expose sensitive information for educational purposes
    query: Optional[str] = None
    stack_trace: Optional[str] = None