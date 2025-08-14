# Database connection module
# Vulnerable implementation for educational purposes

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class DatabaseConnection:
    def __init__(self):
        self.database_url = os.getenv("DATABASE_URL")
        if not self.database_url:
            raise ValueError("DATABASE_URL environment variable is required")
        
        self.connection = None
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = psycopg2.connect(
                self.database_url,
                cursor_factory=RealDictCursor
            )
            return self.connection
        except psycopg2.Error as e:
            print(f"Database connection error: {e}")
            raise
    
    def disconnect(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def get_cursor(self):
        """Get database cursor"""
        if not self.connection:
            self.connect()
        return self.connection.cursor()
    
    def execute_query(self, query, params=None):
        """Execute a query and return results"""
        cursor = self.get_cursor()
        try:
            cursor.execute(query, params)
            if query.strip().upper().startswith('SELECT'):
                return cursor.fetchall()
            else:
                self.connection.commit()
                return cursor.rowcount
        except psycopg2.Error as e:
            self.connection.rollback()
            # Intentionally verbose error for educational purposes
            print(f"SQL Error: {e}")
            raise
        finally:
            cursor.close()

# Global database instance
db = DatabaseConnection()

def get_db_connection():
    """Get database connection instance"""
    return db