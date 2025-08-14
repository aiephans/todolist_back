# Database initialization utility
# Vulnerable implementation for educational purposes

import os
from pathlib import Path
from .connection import get_db_connection

def init_database():
    """Initialize database with tables and sample data"""
    db = get_db_connection()
    
    # Read SQL initialization script
    sql_file = Path(__file__).parent / "init.sql"
    
    try:
        with open(sql_file, 'r') as file:
            sql_script = file.read()
        
        # Execute the initialization script
        db.connect()
        cursor = db.get_cursor()
        cursor.execute(sql_script)
        db.connection.commit()
        
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise
    finally:
        db.disconnect()

def create_sample_users():
    """Create sample users for testing vulnerabilities"""
    db = get_db_connection()
    
    sample_users = [
        ("admin", "admin123", "admin@example.com"),
        ("user1", "password", "user1@example.com"),
        ("testuser", "test", "test@example.com")
    ]
    
    try:
        db.connect()
        
        for username, password, email in sample_users:
            # Intentionally vulnerable: storing passwords in plain text
            query = """
                INSERT INTO users (username, password, email) 
                VALUES (%s, %s, %s) 
                ON CONFLICT (username) DO NOTHING
            """
            db.execute_query(query, (username, password, email))
        
        print("Sample users created successfully!")
        
    except Exception as e:
        print(f"Error creating sample users: {e}")
        raise
    finally:
        db.disconnect()

def create_sample_tasks():
    """Create sample tasks for testing"""
    db = get_db_connection()
    
    sample_tasks = [
        (1, "Complete project documentation", "Write comprehensive docs for the project", False),
        (1, "Review security vulnerabilities", "Check for common web vulnerabilities", True),
        (2, "Test XSS payload", "<script>alert('XSS')</script>", False),
        (2, "SQL injection test", "'; DROP TABLE users; --", False),
    ]
    
    try:
        db.connect()
        
        for user_id, title, description, completed in sample_tasks:
            query = """
                INSERT INTO tasks (user_id, title, description, completed) 
                VALUES (%s, %s, %s, %s)
            """
            db.execute_query(query, (user_id, title, description, completed))
        
        print("Sample tasks created successfully!")
        
    except Exception as e:
        print(f"Error creating sample tasks: {e}")
        raise
    finally:
        db.disconnect()

if __name__ == "__main__":
    print("Initializing vulnerable todolist database...")
    init_database()
    create_sample_users()
    create_sample_tasks()
    print("Database setup complete!")