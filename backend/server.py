from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import os
import jwt
import bcrypt
import uuid
from datetime import datetime, timedelta
from pymongo import MongoClient
from cryptography.fernet import Fernet
import base64
import json

# Initialize FastAPI app
app = FastAPI(title="Credential Manager API", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
JWT_SECRET = os.environ.get("JWT_SECRET", "your-super-secret-jwt-key-change-in-production")

# Generate or get encryption key - ensure it's properly formatted
if "ENCRYPTION_KEY" in os.environ:
    ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"]
else:
    # Generate a new key for this session - this returns bytes, so we need to use it directly
    ENCRYPTION_KEY = Fernet.generate_key()

# MongoDB connection
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
client = MongoClient(MONGO_URL)
db = client.credential_manager

# Collections
users_collection = db.users
namespaces_collection = db.namespaces
credentials_collection = db.credentials

# Encryption setup
fernet = Fernet(ENCRYPTION_KEY)

# Pydantic models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')
    password: str = Field(..., min_length=6)
    full_name: str = Field(..., min_length=1, max_length=100)

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

class NamespaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

class NamespaceResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    credentials_count: int

class CredentialCreate(BaseModel):
    namespace_id: str
    title: str = Field(..., min_length=1, max_length=100)
    credential_type: str = Field(..., description="Type: username_password, api_key, token, file")
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None
    file_content: Optional[str] = None  # base64 encoded
    file_name: Optional[str] = None
    notes: Optional[str] = Field(None, max_length=1000)

class CredentialResponse(BaseModel):
    id: str
    namespace_id: str
    title: str
    credential_type: str
    username: Optional[str]
    password: Optional[str]  # Will be decrypted for display
    api_key: Optional[str]   # Will be decrypted for display
    token: Optional[str]     # Will be decrypted for display
    file_name: Optional[str]
    file_content: Optional[str]  # Will be decrypted for display
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime

# Utility functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = users_collection.find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data"""
    if not data:
        return data
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    if not encrypted_data:
        return encrypted_data
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except:
        return encrypted_data  # Return as-is if decryption fails

# Routes
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    """Register a new user"""
    # Check if user already exists
    if users_collection.find_one({"$or": [{"username": user_data.username}, {"email": user_data.email}]}):
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Create new user
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(user_data.password)
    
    user_doc = {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "password": hashed_password,
        "full_name": user_data.full_name,
        "created_at": datetime.utcnow(),
        "is_active": True
    }
    
    users_collection.insert_one(user_doc)
    
    # Create access token
    access_token = create_access_token(data={"sub": user_data.username})
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user_id,
            "username": user_data.username,
            "email": user_data.email,
            "full_name": user_data.full_name
        }
    )

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user_credentials: UserLogin):
    """Login user"""
    user = users_collection.find_one({"username": user_credentials.username})
    
    if not user or not verify_password(user_credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="User account is disabled")
    
    # Create access token
    access_token = create_access_token(data={"sub": user["username"]})
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"]
        }
    )

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"],
        "full_name": current_user["full_name"]
    }

@app.post("/api/namespaces", response_model=dict)
async def create_namespace(namespace_data: NamespaceCreate, current_user: dict = Depends(get_current_user)):
    """Create a new namespace"""
    # Check if namespace already exists for this user
    existing = namespaces_collection.find_one({
        "name": namespace_data.name,
        "user_id": current_user["id"]
    })
    
    if existing:
        raise HTTPException(status_code=400, detail="Namespace with this name already exists")
    
    namespace_id = str(uuid.uuid4())
    namespace_doc = {
        "id": namespace_id,
        "name": namespace_data.name,
        "description": namespace_data.description,
        "user_id": current_user["id"],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    namespaces_collection.insert_one(namespace_doc)
    
    return {
        "id": namespace_id,
        "name": namespace_data.name,
        "description": namespace_data.description,
        "created_at": namespace_doc["created_at"],
        "credentials_count": 0
    }

@app.get("/api/namespaces", response_model=List[NamespaceResponse])
async def get_namespaces(current_user: dict = Depends(get_current_user)):
    """Get all namespaces for the current user"""
    namespaces = list(namespaces_collection.find({"user_id": current_user["id"]}))
    
    result = []
    for ns in namespaces:
        # Count credentials for this namespace
        cred_count = credentials_collection.count_documents({"namespace_id": ns["id"]})
        
        result.append(NamespaceResponse(
            id=ns["id"],
            name=ns["name"],
            description=ns.get("description"),
            created_at=ns["created_at"],
            credentials_count=cred_count
        ))
    
    return result

@app.delete("/api/namespaces/{namespace_id}")
async def delete_namespace(namespace_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a namespace and all its credentials"""
    # Check if namespace exists and belongs to user
    namespace = namespaces_collection.find_one({"id": namespace_id, "user_id": current_user["id"]})
    if not namespace:
        raise HTTPException(status_code=404, detail="Namespace not found")
    
    # Delete all credentials in this namespace
    credentials_collection.delete_many({"namespace_id": namespace_id})
    
    # Delete the namespace
    namespaces_collection.delete_one({"id": namespace_id})
    
    return {"message": "Namespace deleted successfully"}

@app.post("/api/credentials", response_model=dict)
async def create_credential(credential_data: CredentialCreate, current_user: dict = Depends(get_current_user)):
    """Create a new credential"""
    # Verify namespace exists and belongs to user
    namespace = namespaces_collection.find_one({
        "id": credential_data.namespace_id,
        "user_id": current_user["id"]
    })
    
    if not namespace:
        raise HTTPException(status_code=404, detail="Namespace not found")
    
    credential_id = str(uuid.uuid4())
    
    # Encrypt sensitive data
    encrypted_data = {}
    if credential_data.password:
        encrypted_data["password"] = encrypt_data(credential_data.password)
    if credential_data.api_key:
        encrypted_data["api_key"] = encrypt_data(credential_data.api_key)
    if credential_data.token:
        encrypted_data["token"] = encrypt_data(credential_data.token)
    if credential_data.file_content:
        encrypted_data["file_content"] = encrypt_data(credential_data.file_content)
    
    credential_doc = {
        "id": credential_id,
        "namespace_id": credential_data.namespace_id,
        "title": credential_data.title,
        "credential_type": credential_data.credential_type,
        "username": credential_data.username,
        "password": encrypted_data.get("password"),
        "api_key": encrypted_data.get("api_key"),
        "token": encrypted_data.get("token"),
        "file_content": encrypted_data.get("file_content"),
        "file_name": credential_data.file_name,
        "notes": credential_data.notes,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    credentials_collection.insert_one(credential_doc)
    
    return {
        "id": credential_id,
        "message": "Credential created successfully"
    }

@app.get("/api/credentials/namespace/{namespace_id}", response_model=List[CredentialResponse])
async def get_credentials_by_namespace(namespace_id: str, current_user: dict = Depends(get_current_user)):
    """Get all credentials for a specific namespace"""
    # Verify namespace exists and belongs to user
    namespace = namespaces_collection.find_one({
        "id": namespace_id,
        "user_id": current_user["id"]
    })
    
    if not namespace:
        raise HTTPException(status_code=404, detail="Namespace not found")
    
    credentials = list(credentials_collection.find({"namespace_id": namespace_id}))
    
    result = []
    for cred in credentials:
        # Decrypt sensitive data for display
        decrypted_cred = CredentialResponse(
            id=cred["id"],
            namespace_id=cred["namespace_id"],
            title=cred["title"],
            credential_type=cred["credential_type"],
            username=cred.get("username"),
            password=decrypt_data(cred.get("password", "")),
            api_key=decrypt_data(cred.get("api_key", "")),
            token=decrypt_data(cred.get("token", "")),
            file_name=cred.get("file_name"),
            file_content=decrypt_data(cred.get("file_content", "")),
            notes=cred.get("notes"),
            created_at=cred["created_at"],
            updated_at=cred["updated_at"]
        )
        result.append(decrypted_cred)
    
    return result

@app.delete("/api/credentials/{credential_id}")
async def delete_credential(credential_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a credential"""
    # Find the credential
    credential = credentials_collection.find_one({"id": credential_id})
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    # Verify the namespace belongs to the user
    namespace = namespaces_collection.find_one({
        "id": credential["namespace_id"],
        "user_id": current_user["id"]
    })
    
    if not namespace:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Delete the credential
    credentials_collection.delete_one({"id": credential_id})
    
    return {"message": "Credential deleted successfully"}

@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get user statistics"""
    total_namespaces = namespaces_collection.count_documents({"user_id": current_user["id"]})
    
    # Get total credentials across all namespaces
    user_namespaces = list(namespaces_collection.find({"user_id": current_user["id"]}, {"id": 1}))
    namespace_ids = [ns["id"] for ns in user_namespaces]
    total_credentials = credentials_collection.count_documents({"namespace_id": {"$in": namespace_ids}})
    
    return {
        "total_namespaces": total_namespaces,
        "total_credentials": total_credentials
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)