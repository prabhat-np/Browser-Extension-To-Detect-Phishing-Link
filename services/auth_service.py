import hashlib
import jwt
import datetime
import os
import json
import secrets

SECRET_KEY = os.getenv("FINSHIELD_JWT_SECRET", "super-secret-fyp-key-nepal-secure-bank")
REVOKED_TOKENS_FILE = os.getenv("FINSHIELD_REVOKED_TOKENS_FILE", "data/revoked_tokens.json")

# Simulated User Database
# In a real system, this would be SQL/NoSQL
USERS_DB = {
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "Admin",
        "full_name": "System Administrator"
    },
    "analyst": {
        "password_hash": hashlib.sha256("analyst123".encode()).hexdigest(),
        "role": "Analyst",
        "full_name": "Security Analyst"
    },
    "employee": {
        "password_hash": hashlib.sha256("employee123".encode()).hexdigest(),
        "role": "Employee",
        "full_name": "Bank Staff"
    },
    "viewer": {
        "password_hash": hashlib.sha256("viewer123".encode()).hexdigest(),
        "role": "Viewer",
        "full_name": "Guest Viewer"
    }
}

class AuthService:
    """
    Handles User Authentication and Authorization using JWT.
    """
    
    @staticmethod
    def login(username, password):
        user = USERS_DB.get(username)
        if not user:
            return None
        
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        if input_hash == user["password_hash"]:
            jti = secrets.token_urlsafe(16)
            payload = {
                "username": username,
                "role": user["role"],
                "jti": jti,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            return {
                "token": token,
                "username": username,
                "role": user["role"],
                "full_name": user["full_name"]
            }
        return None

    @staticmethod
    def verify_token(token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if AuthService.is_token_revoked(payload.get("jti")):
                return None
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    @staticmethod
    def revoke_token(token):
        payload = AuthService._unsafe_decode_no_verify(token)
        if not payload:
            return False
        jti = payload.get("jti")
        if not jti:
            return False
        os.makedirs(os.path.dirname(REVOKED_TOKENS_FILE), exist_ok=True)
        revoked = AuthService._load_revoked_set()
        revoked.add(jti)
        with open(REVOKED_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(list(revoked)), f)
        return True

    @staticmethod
    def is_token_revoked(jti):
        if not jti:
            return False
        revoked = AuthService._load_revoked_set()
        return jti in revoked

    @staticmethod
    def _load_revoked_set():
        if not os.path.exists(REVOKED_TOKENS_FILE):
            return set()
        try:
            with open(REVOKED_TOKENS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return set(str(x) for x in data)
            return set()
        except Exception:
            return set()

    @staticmethod
    def _unsafe_decode_no_verify(token):
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None

    @staticmethod
    def check_permission(user_role, required_role):
        # Viewer < Employee < Analyst < Admin
        roles_hierarchy = {"Viewer": 1, "Employee": 1, "Analyst": 2, "Admin": 3}
        return roles_hierarchy.get(user_role, 0) >= roles_hierarchy.get(required_role, 0)
