from fastapi import APIRouter, HTTPException, Depends
import healthid.db as db
from pydantic import BaseModel
from healthid.security import User, get_remote_user
from healthid.fhir import random_patient
from typing import Optional, List

router = APIRouter()

@router.get('/RandomPatient')
def get_patient():
    patient = random_patient()
    return patient.as_json()

