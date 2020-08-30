from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

API_VERSION = '0.10.0'
    
api = FastAPI(
    title=f"HealthID API",
    version=API_VERSION
)

from .routers import account, auth, patient
api.include_router(account.router)
api.include_router(auth.router)
api.include_router(patient.router)

class APIInfo(BaseModel):
    title: str
    version: str

@api.get('/info', response_model=APIInfo)
def public_info():
    return APIInfo(title=api.title, version=api.version)
