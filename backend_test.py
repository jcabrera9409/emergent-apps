#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for Credential Management System
Tests all authentication, namespace, credential, and statistics endpoints
"""

import requests
import json
import base64
import time
from datetime import datetime

# Configuration
BASE_URL = "https://0456bc3d-f1c7-48a3-9db6-0930350177d6.preview.emergentagent.com/api"
TEST_USER_DATA = {
    "username": "john_developer",
    "email": "john.dev@techcorp.com",
    "password": "SecurePass123!",
    "full_name": "John Developer"
}

class CredentialManagerTester:
    def __init__(self):
        self.base_url = BASE_URL
        self.auth_token = None
        self.user_data = None
        self.test_namespace_id = None
        self.test_credentials = []
        self.test_results = []
        
    def log_test(self, test_name, success, message="", details=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status}: {test_name}")
        if message:
            print(f"    {message}")
        if details and not success:
            print(f"    Details: {details}")
        print()

    def test_health_check(self):
        """Test health check endpoint"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "status" in data and data["status"] == "healthy":
                    self.log_test("Health Check", True, "API is healthy and responding")
                    return True
                else:
                    self.log_test("Health Check", False, "Invalid health response format", data)
                    return False
            else:
                self.log_test("Health Check", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Health Check", False, "Connection failed", str(e))
            return False

    def test_user_registration(self):
        """Test user registration endpoint"""
        try:
            response = requests.post(
                f"{self.base_url}/auth/register",
                json=TEST_USER_DATA,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.auth_token = data["access_token"]
                    self.user_data = data["user"]
                    self.log_test("User Registration", True, f"User registered successfully: {data['user']['username']}")
                    return True
                else:
                    self.log_test("User Registration", False, "Invalid registration response format", data)
                    return False
            elif response.status_code == 400:
                # User might already exist, try to login instead
                self.log_test("User Registration", True, "User already exists (expected for repeated tests)")
                return self.test_user_login()
            else:
                self.log_test("User Registration", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("User Registration", False, "Request failed", str(e))
            return False

    def test_user_login(self):
        """Test user login endpoint"""
        try:
            login_data = {
                "username": TEST_USER_DATA["username"],
                "password": TEST_USER_DATA["password"]
            }
            
            response = requests.post(
                f"{self.base_url}/auth/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.auth_token = data["access_token"]
                    self.user_data = data["user"]
                    self.log_test("User Login", True, f"Login successful for user: {data['user']['username']}")
                    return True
                else:
                    self.log_test("User Login", False, "Invalid login response format", data)
                    return False
            else:
                self.log_test("User Login", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("User Login", False, "Request failed", str(e))
            return False

    def test_get_current_user(self):
        """Test get current user info endpoint"""
        if not self.auth_token:
            self.log_test("Get Current User", False, "No auth token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(f"{self.base_url}/auth/me", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "username" in data and data["username"] == TEST_USER_DATA["username"]:
                    self.log_test("Get Current User", True, f"User info retrieved: {data['username']}")
                    return True
                else:
                    self.log_test("Get Current User", False, "Invalid user info response", data)
                    return False
            else:
                self.log_test("Get Current User", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Get Current User", False, "Request failed", str(e))
            return False

    def test_create_namespace(self):
        """Test namespace creation"""
        if not self.auth_token:
            self.log_test("Create Namespace", False, "No auth token available")
            return False
            
        try:
            namespace_data = {
                "name": "Development Environment",
                "description": "Credentials for development servers and services"
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.post(
                f"{self.base_url}/namespaces",
                json=namespace_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data and "name" in data:
                    self.test_namespace_id = data["id"]
                    self.log_test("Create Namespace", True, f"Namespace created: {data['name']} (ID: {data['id']})")
                    return True
                else:
                    self.log_test("Create Namespace", False, "Invalid namespace creation response", data)
                    return False
            else:
                self.log_test("Create Namespace", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Create Namespace", False, "Request failed", str(e))
            return False

    def test_list_namespaces(self):
        """Test listing namespaces"""
        if not self.auth_token:
            self.log_test("List Namespaces", False, "No auth token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(f"{self.base_url}/namespaces", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    namespace_found = any(ns.get("id") == self.test_namespace_id for ns in data)
                    if namespace_found:
                        self.log_test("List Namespaces", True, f"Found {len(data)} namespaces including test namespace")
                        return True
                    else:
                        self.log_test("List Namespaces", False, "Test namespace not found in list", data)
                        return False
                else:
                    self.log_test("List Namespaces", False, "Invalid namespaces list response", data)
                    return False
            else:
                self.log_test("List Namespaces", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("List Namespaces", False, "Request failed", str(e))
            return False

    def test_create_credentials(self):
        """Test creating different types of credentials"""
        if not self.auth_token or not self.test_namespace_id:
            self.log_test("Create Credentials", False, "Missing auth token or namespace ID")
            return False

        credentials_to_test = [
            {
                "title": "Database Admin",
                "credential_type": "username_password",
                "username": "db_admin",
                "password": "SuperSecretDBPass123!",
                "notes": "Production database admin credentials"
            },
            {
                "title": "GitHub API",
                "credential_type": "api_key",
                "api_key": "ghp_1234567890abcdef1234567890abcdef12345678",
                "notes": "GitHub API key for CI/CD"
            },
            {
                "title": "JWT Service Token",
                "credential_type": "token",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "notes": "Service authentication token"
            },
            {
                "title": "SSL Certificate",
                "credential_type": "file",
                "file_name": "server.crt",
                "file_content": base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n-----END CERTIFICATE-----").decode(),
                "notes": "SSL certificate for production server"
            }
        ]

        success_count = 0
        for cred_data in credentials_to_test:
            try:
                cred_data["namespace_id"] = self.test_namespace_id
                headers = {"Authorization": f"Bearer {self.auth_token}"}
                
                response = requests.post(
                    f"{self.base_url}/credentials",
                    json=cred_data,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "id" in data:
                        self.test_credentials.append(data["id"])
                        success_count += 1
                        self.log_test(f"Create {cred_data['credential_type']} Credential", True, 
                                    f"Created: {cred_data['title']} (ID: {data['id']})")
                    else:
                        self.log_test(f"Create {cred_data['credential_type']} Credential", False, 
                                    "Invalid credential creation response", data)
                else:
                    self.log_test(f"Create {cred_data['credential_type']} Credential", False, 
                                f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Create {cred_data['credential_type']} Credential", False, 
                            "Request failed", str(e))

        overall_success = success_count == len(credentials_to_test)
        self.log_test("Create All Credentials", overall_success, 
                     f"Created {success_count}/{len(credentials_to_test)} credentials")
        return overall_success

    def test_get_credentials(self):
        """Test retrieving credentials and verify encryption/decryption"""
        if not self.auth_token or not self.test_namespace_id:
            self.log_test("Get Credentials", False, "Missing auth token or namespace ID")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(
                f"{self.base_url}/credentials/namespace/{self.test_namespace_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    # Verify that sensitive data is properly decrypted
                    decryption_verified = True
                    for cred in data:
                        if cred.get("credential_type") == "username_password":
                            if not cred.get("password") or cred.get("password") == "":
                                decryption_verified = False
                                break
                        elif cred.get("credential_type") == "api_key":
                            if not cred.get("api_key") or cred.get("api_key") == "":
                                decryption_verified = False
                                break
                        elif cred.get("credential_type") == "token":
                            if not cred.get("token") or cred.get("token") == "":
                                decryption_verified = False
                                break
                        elif cred.get("credential_type") == "file":
                            if not cred.get("file_content") or cred.get("file_content") == "":
                                decryption_verified = False
                                break
                    
                    if decryption_verified:
                        self.log_test("Get Credentials", True, 
                                    f"Retrieved {len(data)} credentials with proper decryption")
                        return True
                    else:
                        self.log_test("Get Credentials", False, 
                                    "Sensitive data not properly decrypted", data)
                        return False
                else:
                    self.log_test("Get Credentials", False, "No credentials found or invalid response", data)
                    return False
            else:
                self.log_test("Get Credentials", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Get Credentials", False, "Request failed", str(e))
            return False

    def test_statistics(self):
        """Test statistics endpoint"""
        if not self.auth_token:
            self.log_test("Statistics", False, "No auth token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(f"{self.base_url}/stats", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "total_namespaces" in data and "total_credentials" in data:
                    if data["total_namespaces"] >= 1 and data["total_credentials"] >= 1:
                        self.log_test("Statistics", True, 
                                    f"Stats: {data['total_namespaces']} namespaces, {data['total_credentials']} credentials")
                        return True
                    else:
                        self.log_test("Statistics", False, "Statistics don't reflect created data", data)
                        return False
                else:
                    self.log_test("Statistics", False, "Invalid statistics response format", data)
                    return False
            else:
                self.log_test("Statistics", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Statistics", False, "Request failed", str(e))
            return False

    def test_delete_credentials(self):
        """Test deleting credentials"""
        if not self.auth_token or not self.test_credentials:
            self.log_test("Delete Credentials", False, "Missing auth token or credential IDs")
            return False

        success_count = 0
        for cred_id in self.test_credentials:
            try:
                headers = {"Authorization": f"Bearer {self.auth_token}"}
                response = requests.delete(
                    f"{self.base_url}/credentials/{cred_id}",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    success_count += 1
                    self.log_test(f"Delete Credential {cred_id[:8]}...", True, "Credential deleted successfully")
                else:
                    self.log_test(f"Delete Credential {cred_id[:8]}...", False, 
                                f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Delete Credential {cred_id[:8]}...", False, "Request failed", str(e))

        overall_success = success_count == len(self.test_credentials)
        self.log_test("Delete All Credentials", overall_success, 
                     f"Deleted {success_count}/{len(self.test_credentials)} credentials")
        return overall_success

    def test_delete_namespace(self):
        """Test deleting namespace"""
        if not self.auth_token or not self.test_namespace_id:
            self.log_test("Delete Namespace", False, "Missing auth token or namespace ID")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.delete(
                f"{self.base_url}/namespaces/{self.test_namespace_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                self.log_test("Delete Namespace", True, "Namespace deleted successfully")
                return True
            else:
                self.log_test("Delete Namespace", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Delete Namespace", False, "Request failed", str(e))
            return False

    def test_error_cases(self):
        """Test error handling for unauthorized access and non-existent resources"""
        error_tests_passed = 0
        total_error_tests = 4

        # Test 1: Access without authentication
        try:
            response = requests.get(f"{self.base_url}/namespaces", timeout=10)
            if response.status_code == 401:
                self.log_test("Unauthorized Access Test", True, "Properly rejected unauthenticated request")
                error_tests_passed += 1
            else:
                self.log_test("Unauthorized Access Test", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Unauthorized Access Test", False, "Request failed", str(e))

        # Test 2: Access non-existent namespace
        if self.auth_token:
            try:
                headers = {"Authorization": f"Bearer {self.auth_token}"}
                fake_namespace_id = "non-existent-namespace-id"
                response = requests.get(
                    f"{self.base_url}/credentials/namespace/{fake_namespace_id}",
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 404:
                    self.log_test("Non-existent Namespace Test", True, "Properly rejected non-existent namespace")
                    error_tests_passed += 1
                else:
                    self.log_test("Non-existent Namespace Test", False, f"Expected 404, got {response.status_code}")
            except Exception as e:
                self.log_test("Non-existent Namespace Test", False, "Request failed", str(e))

        # Test 3: Delete non-existent credential
        if self.auth_token:
            try:
                headers = {"Authorization": f"Bearer {self.auth_token}"}
                fake_credential_id = "non-existent-credential-id"
                response = requests.delete(
                    f"{self.base_url}/credentials/{fake_credential_id}",
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 404:
                    self.log_test("Non-existent Credential Test", True, "Properly rejected non-existent credential")
                    error_tests_passed += 1
                else:
                    self.log_test("Non-existent Credential Test", False, f"Expected 404, got {response.status_code}")
            except Exception as e:
                self.log_test("Non-existent Credential Test", False, "Request failed", str(e))

        # Test 4: Invalid login credentials
        try:
            invalid_login = {
                "username": "nonexistent_user",
                "password": "wrong_password"
            }
            response = requests.post(f"{self.base_url}/auth/login", json=invalid_login, timeout=10)
            if response.status_code == 401:
                self.log_test("Invalid Login Test", True, "Properly rejected invalid credentials")
                error_tests_passed += 1
            else:
                self.log_test("Invalid Login Test", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid Login Test", False, "Request failed", str(e))

        overall_success = error_tests_passed == total_error_tests
        self.log_test("All Error Handling Tests", overall_success, 
                     f"Passed {error_tests_passed}/{total_error_tests} error handling tests")
        return overall_success

    def run_all_tests(self):
        """Run all tests in sequence"""
        print("=" * 80)
        print("CREDENTIAL MANAGEMENT API - COMPREHENSIVE BACKEND TESTING")
        print("=" * 80)
        print(f"Testing API at: {self.base_url}")
        print(f"Test started at: {datetime.now().isoformat()}")
        print()

        # Test sequence
        tests = [
            ("Health Check", self.test_health_check),
            ("User Registration", self.test_user_registration),
            ("User Login", self.test_user_login),
            ("Get Current User", self.test_get_current_user),
            ("Create Namespace", self.test_create_namespace),
            ("List Namespaces", self.test_list_namespaces),
            ("Create Credentials", self.test_create_credentials),
            ("Get Credentials", self.test_get_credentials),
            ("Statistics", self.test_statistics),
            ("Delete Credentials", self.test_delete_credentials),
            ("Delete Namespace", self.test_delete_namespace),
            ("Error Handling", self.test_error_cases)
        ]

        passed_tests = 0
        total_tests = len(tests)

        for test_name, test_func in tests:
            print(f"Running: {test_name}")
            print("-" * 40)
            if test_func():
                passed_tests += 1
            print()

        # Summary
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        print()

        if passed_tests == total_tests:
            print("🎉 ALL TESTS PASSED! The Credential Management API is working correctly.")
        else:
            print("⚠️  Some tests failed. Please review the detailed results above.")
            
        print()
        print("DETAILED TEST RESULTS:")
        print("-" * 40)
        for result in self.test_results:
            print(f"{result['status']}: {result['test']}")
            if result['message']:
                print(f"    {result['message']}")

        return passed_tests == total_tests

if __name__ == "__main__":
    tester = CredentialManagerTester()
    success = tester.run_all_tests()
    exit(0 if success else 1)