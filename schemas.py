"""
Database Schemas for Clinical Referral Lab Management

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class Role(BaseModel):
    name: str = Field(..., description="Role name: admin, hospital_staff, lab_tech, viewer")
    description: Optional[str] = Field(None)

class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    role: str = Field(..., description="admin | hospital_staff | lab_tech | viewer")
    is_active: bool = True

class Patient(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: Optional[str] = None
    gender: Optional[str] = Field(None, description="male | female | other")
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    hospital_id: Optional[str] = Field(None, description="ID of the affiliated hospital")

class TestCatalog(BaseModel):
    code: str
    name: str
    description: Optional[str] = None
    sample_type: Optional[str] = None
    price: Optional[float] = None
    tat_hours: Optional[int] = Field(None, description="Turnaround time in hours")

class Referral(BaseModel):
    patient_id: str
    hospital_id: Optional[str] = None
    ordered_by: str = Field(..., description="user id of the requester")
    tests: List[str] = Field(default_factory=list, description="List of test codes")
    priority: str = Field("normal", description="low | normal | high | stat")
    status: str = Field("pending", description="pending | received | in_progress | completed | reported")
    notes: Optional[str] = None

class TestResult(BaseModel):
    referral_id: str
    test_code: str
    value: Optional[str] = None
    unit: Optional[str] = None
    reference_range: Optional[str] = None
    status: str = Field("pending", description="pending | completed | verified")
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
