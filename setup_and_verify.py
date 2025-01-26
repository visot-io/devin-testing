import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import time
from flask import Flask
from iam_1 import app, get_db_connection

def setup_database():
    """Set up database schema with graceful error handling"""
    conn = None
    cur = None
    try:
        # Set environment variables for database connection
        os.environ['POSTGRES_PASSWORD'] = 'devin123'
        os.environ['POSTGRES_HOST'] = 'localhost'
        os.environ['POSTGRES_DB'] = 'aws_security'
        os.environ['POSTGRES_USER'] = 'postgres'
        os.environ['POSTGRES_PORT'] = '5432'
        
        conn = get_db_connection()
        if not conn:
            print("Skipping database setup - no connection available")
            return False
            
        cur = conn.cursor()
        
        # Create table if not exists
        cur.execute("""
            CREATE TABLE IF NOT EXISTS aws_project_status (
                id SERIAL PRIMARY KEY,
                description TEXT,
                resource TEXT,
                status VARCHAR(50),
                check_type VARCHAR(100)
            );
        """)
        
        conn.commit()
        print("Database schema setup complete")
        return True
        
    except Exception as e:
        print(f"Database setup error: {str(e)}")
        if conn:
            conn.rollback()
        return False
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

def verify_iam_checks(skip_db_checks=False):
    """Run and verify IAM checks with optional database verification"""
    start_time = time.time()
    
    # Set required environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = os.getenv('AWS_ACCESS_KEY_ID_AWS_ACCESS_KEY_ID')
    os.environ['AWS_SECRET_ACCESS_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY_AWS_SECRET_ACCESS_KEY')
    os.environ['AWS_DEFAULT_REGION'] = os.getenv('AWS_DEFAULT_REGION_AWS_DEFAULT_REGION', 'us-east-1')
    os.environ['AWS_ACCOUNT_ID'] = '123456789012'  # Test account ID
    
    # Set database environment variables for testing
    os.environ['POSTGRES_HOST'] = 'localhost'
    os.environ['POSTGRES_DB'] = 'aws_security'
    os.environ['POSTGRES_USER'] = 'postgres'
    os.environ['POSTGRES_PASSWORD'] = 'postgres'
    os.environ['POSTGRES_PORT'] = '5432'
    
    with app.test_client() as client:
        response = client.get('/check-iam_1')
        execution_time = time.time() - start_time
        
        print(f'\nResponse time: {execution_time} seconds')
        print(f'Status code: {response.status_code}')
        
        try:
            response_data = json.loads(response.data)
            print('\nResponse body:')
            print(json.dumps(response_data, indent=2))
            
            if response.status_code != 200:
                print('\nError details:')
                if 'body' in response_data and 'error' in response_data['body']:
                    print(f"Error: {response_data['body']['error']}")
                    print(f"Message: {response_data['body'].get('message', 'No message provided')}")
            
            # Verify database records if successful
            if response.status_code == 200:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute("SELECT * FROM aws_project_status ORDER BY id DESC LIMIT 5")
                records = cur.fetchall()
                print("\nLatest database records:")
                for record in records:
                    print(json.dumps(record, indent=2))
                cur.close()
                conn.close()
                
        except Exception as e:
            print(f'\nError during verification: {str(e)}')
            print(f'Raw response data: {response.data}')

if __name__ == '__main__':
    print("Setting up database schema...")
    db_available = setup_database()
    
    print("\nRunning IAM checks verification...")
    verify_iam_checks(skip_db_checks=not db_available)
    
    print("\nVerification complete. Check the output above for:"
          "\n1. Response time (target: < 4 minutes)"
          "\n2. All security checks executed"
          "\n3. Check_type column population"
          "\n4. Error handling")
