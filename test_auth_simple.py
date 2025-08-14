#!/usr/bin/env python3
"""
Simple test script for authentication vulnerabilities
Tests core functionality without complex dependencies
"""

import os
import jwt

# Set environment variable
os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"

from main import SECRET_KEY, create_access_token

def test_vulnerabilities():
    """Test all authentication vulnerabilities"""
    print("Testing Authentication Vulnerabilities")
    print("=" * 50)
    
    # Test 1: Weak Secret Key
    print("\n1. Testing Weak Secret Key:")
    print(f"   Secret Key: {SECRET_KEY}")
    assert SECRET_KEY == "secret123", "Expected weak secret key"
    print("   ✅ VULNERABLE: Using weak secret key 'secret123'")
    
    # Test 2: No Token Expiration
    print("\n2. Testing Token Without Expiration:")
    test_data = {"sub": "testuser", "user_id": 1}
    token = create_access_token(test_data)
    decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    print(f"   Token payload: {decoded}")
    assert "exp" not in decoded, "Token should not have expiration"
    print("   ✅ VULNERABLE: Token has no expiration field")
    
    # Test 3: Token Manipulation
    print("\n3. Testing Token Manipulation:")
    malicious_payload = {
        "sub": "admin",
        "user_id": 999,
        "role": "superuser"
    }
    malicious_token = jwt.encode(malicious_payload, SECRET_KEY, algorithm="HS256")
    decoded_malicious = jwt.decode(malicious_token, SECRET_KEY, algorithms=["HS256"])
    print(f"   Malicious token created: {malicious_token[:50]}...")
    print(f"   Decoded payload: {decoded_malicious}")
    assert decoded_malicious["sub"] == "admin"
    print("   ✅ VULNERABLE: Can create malicious tokens with known secret")
    
    # Test 4: Algorithm Manipulation
    print("\n4. Testing Algorithm Manipulation:")
    try:
        # Try to create a token with 'none' algorithm
        none_token = jwt.encode({"sub": "hacker", "user_id": 666}, "", algorithm="none")
        print(f"   'None' algorithm token: {none_token}")
        print("   ✅ VULNERABLE: Can create tokens with 'none' algorithm")
    except Exception as e:
        print(f"   'None' algorithm blocked: {e}")
    
    print("\n" + "=" * 50)
    print("✅ All vulnerability tests completed successfully!")
    print("This authentication system demonstrates multiple security flaws:")
    print("- Weak secret key that can be easily guessed")
    print("- No token expiration (tokens valid forever)")
    print("- Token manipulation possible due to known secret")
    print("- Verbose error messages (implemented in endpoints)")
    print("- Plain text password storage (implemented in endpoints)")

if __name__ == "__main__":
    test_vulnerabilities()