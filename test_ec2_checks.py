import time
import requests
import json

def test_ec2_checks():
    print("Starting EC2 security checks test...")
    
    # Record start time
    start_time = time.time()
    
    # Make request to the endpoint
    try:
        response = requests.get('http://localhost:5004/check-ec2-3')
        response.raise_for_status()
        
        # Calculate execution time
        execution_time = time.time() - start_time
        print(f"Execution completed in {execution_time:.2f} seconds")
        
        # Parse and validate results
        results = response.json()
        print(f"Number of results: {len(results)}")
        
        # Check result structure
        if results:
            sample_result = results[0]
            print("\nSample result structure:")
            print(json.dumps(sample_result, indent=2))
            
        return execution_time, len(results)
        
    except Exception as e:
        print(f"Error during test: {e}")
        return None, 0

if __name__ == '__main__':
    test_ec2_checks()
