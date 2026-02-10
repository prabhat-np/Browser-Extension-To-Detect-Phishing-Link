import os
import sys
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.model_trainer import ModelEngine
from services.auth_service import AuthService
from services.audit_log_service import AuditLogService


app = FastAPI(title="FinShield AI API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str
    full_name: str


class PredictRequest(BaseModel):
    url: str
    source: Optional[str] = "extension"
    event_type: Optional[str] = "page_load"


class ExplainFeature(BaseModel):
    name: str
    value: Any
    importance: float


class PredictResponse(BaseModel):
    url: str
    prediction: int
    prob_phishing: float
    risk: str
    top_features: List[ExplainFeature]


def get_engine():
    if not hasattr(app.state, "engine"):
        app.state.engine = ModelEngine()
        if not app.state.engine.model:
            app.state.engine.train("data/processed/training_dataset_v1.csv")
    return app.state.engine


def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    payload = AuthService.verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    payload["token"] = token
    return payload


@app.get("/health")
def health():
    AuditLogService.init_db()
    return {"status": "ok"}


@app.post("/api/v1/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    user = AuthService.login(req.username, req.password)
    if not user:
        AuditLogService.log_auth_event(req.username, "login_failed")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    AuditLogService.log_auth_event(user["username"], "login_success", {"role": user["role"]})
    return user


@app.post("/api/v1/auth/logout")
def logout(user=Depends(get_current_user)):
    AuthService.revoke_token(user["token"])
    AuditLogService.log_auth_event(user.get("username"), "logout")
    return {"status": "ok"}


@app.post("/api/v1/predict", response_model=PredictResponse)
def predict(req: PredictRequest, user=Depends(get_current_user)):
    engine = get_engine()
    result = engine.predict(req.url)
    if not result:
        raise HTTPException(status_code=400, detail="Unable to analyze URL")
    prediction, prob_phishing, risk, features = result
    top = []
    importances = getattr(engine.model, "feature_importances_", None)
    if importances is not None and engine.feature_columns:
        pairs = list(zip(engine.feature_columns, importances))
        pairs.sort(key=lambda x: x[1], reverse=True)
        for name, imp in pairs[:8]:
            top.append({"name": name, "value": features.get(name), "importance": float(imp)})
    AuditLogService.log_scan_event(
        username=user.get("username"),
        source=req.source or "extension",
        url=req.url,
        prediction=prediction,
        prob_phishing=float(prob_phishing),
        risk=risk,
        features=features,
        explain={"top_features": top, "event_type": req.event_type},
    )
    return {
        "url": req.url,
        "prediction": int(prediction),
        "prob_phishing": float(prob_phishing),
        "risk": risk,
        "top_features": top,
    }


@app.get("/api/v1/audit/scans")
def recent_scans(limit: int = 100, user=Depends(get_current_user)):
    if not AuthService.check_permission(user.get("role"), "Analyst"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"items": AuditLogService.get_recent_scans(limit=limit)}


@app.get("/api/v1/audit/auth")
def recent_auth(limit: int = 100, user=Depends(get_current_user)):
    if not AuthService.check_permission(user.get("role"), "Admin"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"items": AuditLogService.get_recent_auth(limit=limit)}

