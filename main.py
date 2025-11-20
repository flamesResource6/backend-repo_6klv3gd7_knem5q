import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Any, Dict

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db

# App setup
app = FastAPI(title="Clinical Referral Lab Management API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security / Auth
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Utilities
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[str] = None
    role: Optional[str] = None


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = Field(..., description="admin | hospital_staff | lab_tech | viewer")


class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    is_active: bool


class PatientIn(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    hospital_id: Optional[str] = None


class PatientOut(PatientIn):
    id: str


class TestCatalogIn(BaseModel):
    code: str
    name: str
    description: Optional[str] = None
    sample_type: Optional[str] = None
    price: Optional[float] = None
    tat_hours: Optional[int] = None


class TestCatalogOut(TestCatalogIn):
    id: str


class ReferralIn(BaseModel):
    patient_id: str
    hospital_id: Optional[str] = None
    ordered_by: Optional[str] = None
    tests: List[str] = Field(default_factory=list)
    priority: str = Field("normal")
    notes: Optional[str] = None


class ReferralOut(ReferralIn):
    id: str
    status: str


class TestResultIn(BaseModel):
    referral_id: str
    test_code: str
    value: Optional[str] = None
    unit: Optional[str] = None
    reference_range: Optional[str] = None
    status: str = Field("pending")


class TestResultOut(TestResultIn):
    id: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None


# Helper functions

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    d = dict(doc)
    if d.get("_id"):
        d["id"] = str(d.pop("_id"))
    # Convert datetimes to isoformat
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")
        if user_id is None or role is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user or not user.get("is_active", True):
        raise credentials_exception
    return serialize_doc(user)


def require_roles(*roles: str):
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user

    return role_checker


# Health endpoints
@app.get("/")
def read_root():
    return {"message": "Clinical Referral Lab Management API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set" if not os.getenv("DATABASE_URL") else "✅ Set",
        "database_name": "❌ Not Set" if not os.getenv("DATABASE_NAME") else "✅ Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        cols = db.list_collection_names()
        response.update({
            "database": "✅ Connected & Working",
            "connection_status": "Connected",
            "collections": cols[:10],
        })
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response


# Auth endpoints
@app.post("/auth/register", response_model=UserPublic)
def register_user(payload: UserCreate, _: dict = Depends(require_roles("admin"))):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "role": payload.role,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    user_doc["_id"] = res.inserted_id
    user = serialize_doc(user_doc)
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "is_active": user.get("is_active", True),
    }


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # OAuth2PasswordRequestForm has fields username and password
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user["_id"]), "role": user.get("role", "viewer")})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UserPublic)
async def me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "name": current_user["name"],
        "email": current_user["email"],
        "role": current_user["role"],
        "is_active": current_user.get("is_active", True),
    }


# Patients CRUD
@app.post("/patients", response_model=PatientOut)
async def create_patient(body: PatientIn, _: dict = Depends(require_roles("admin", "hospital_staff"))):
    doc = body.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = db["patient"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/patients", response_model=List[PatientOut])
async def list_patients(_: dict = Depends(require_roles("admin", "hospital_staff", "lab_tech", "viewer"))):
    items = [serialize_doc(d) for d in db["patient"].find().sort("created_at", -1).limit(200)]
    return items


@app.get("/patients/{patient_id}", response_model=PatientOut)
async def get_patient(patient_id: str, _: dict = Depends(require_roles("admin", "hospital_staff", "lab_tech", "viewer"))):
    doc = db["patient"].find_one({"_id": ObjectId(patient_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Patient not found")
    return serialize_doc(doc)


@app.put("/patients/{patient_id}", response_model=PatientOut)
async def update_patient(patient_id: str, body: PatientIn, _: dict = Depends(require_roles("admin", "hospital_staff"))):
    update = body.model_dump()
    update["updated_at"] = datetime.now(timezone.utc)
    res = db["patient"].find_one_and_update({"_id": ObjectId(patient_id)}, {"$set": update}, return_document=True)
    doc = db["patient"].find_one({"_id": ObjectId(patient_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Patient not found")
    return serialize_doc(doc)


@app.delete("/patients/{patient_id}")
async def delete_patient(patient_id: str, _: dict = Depends(require_roles("admin"))):
    db["patient"].delete_one({"_id": ObjectId(patient_id)})
    return {"ok": True}


# Test Catalog CRUD
@app.post("/tests", response_model=TestCatalogOut)
async def create_test(body: TestCatalogIn, _: dict = Depends(require_roles("admin", "lab_tech"))):
    doc = body.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = db["testcatalog"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/tests", response_model=List[TestCatalogOut])
async def list_tests(_: dict = Depends(require_roles("admin", "hospital_staff", "lab_tech", "viewer"))):
    items = [serialize_doc(d) for d in db["testcatalog"].find().sort("name", 1).limit(500)]
    return items


@app.put("/tests/{test_id}", response_model=TestCatalogOut)
async def update_test(test_id: str, body: TestCatalogIn, _: dict = Depends(require_roles("admin", "lab_tech"))):
    update = body.model_dump()
    update["updated_at"] = datetime.now(timezone.utc)
    db["testcatalog"].update_one({"_id": ObjectId(test_id)}, {"$set": update})
    doc = db["testcatalog"].find_one({"_id": ObjectId(test_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Test not found")
    return serialize_doc(doc)


@app.delete("/tests/{test_id}")
async def delete_test(test_id: str, _: dict = Depends(require_roles("admin"))):
    db["testcatalog"].delete_one({"_id": ObjectId(test_id)})
    return {"ok": True}


# Referrals
@app.post("/referrals", response_model=ReferralOut)
async def create_referral(body: ReferralIn, current_user: dict = Depends(require_roles("admin", "hospital_staff"))):
    doc = body.model_dump()
    doc.setdefault("status", "pending")
    doc.setdefault("ordered_by", current_user.get("id"))
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = db["referral"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/referrals", response_model=List[ReferralOut])
async def list_referrals(_: dict = Depends(require_roles("admin", "hospital_staff", "lab_tech", "viewer"))):
    items = [serialize_doc(d) for d in db["referral"].find().sort("created_at", -1).limit(200)]
    return items


@app.put("/referrals/{ref_id}", response_model=ReferralOut)
async def update_referral(ref_id: str, update: Dict[str, Any], _: dict = Depends(require_roles("admin", "lab_tech"))):
    update["updated_at"] = datetime.now(timezone.utc)
    db["referral"].update_one({"_id": ObjectId(ref_id)}, {"$set": update})
    doc = db["referral"].find_one({"_id": ObjectId(ref_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Referral not found")
    return serialize_doc(doc)


# Results
@app.post("/results", response_model=TestResultOut)
async def create_result(body: TestResultIn, _: dict = Depends(require_roles("admin", "lab_tech"))):
    doc = body.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = db["testresult"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/results", response_model=List[TestResultOut])
async def list_results(_: dict = Depends(require_roles("admin", "hospital_staff", "lab_tech", "viewer"))):
    items = [serialize_doc(d) for d in db["testresult"].find().sort("created_at", -1).limit(200)]
    return items


@app.put("/results/{result_id}", response_model=TestResultOut)
async def update_result(result_id: str, update: Dict[str, Any], _: dict = Depends(require_roles("admin", "lab_tech"))):
    update["updated_at"] = datetime.now(timezone.utc)
    db["testresult"].update_one({"_id": ObjectId(result_id)}, {"$set": update})
    doc = db["testresult"].find_one({"_id": ObjectId(result_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Result not found")
    return serialize_doc(doc)


# Seed admin endpoint (one-time use)
@app.post("/auth/seed-admin")
def seed_admin():
    if db["user"].count_documents({"role": "admin"}) > 0:
        return {"message": "Admin exists"}
    user_doc = {
        "name": "Super Admin",
        "email": "admin@lab.local",
        "password_hash": hash_password("admin123"),
        "role": "admin",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["user"].insert_one(user_doc)
    return {"message": "Admin seeded", "email": user_doc["email"], "password": "admin123"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
