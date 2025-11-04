from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from bson import ObjectId
import stripe
import os
from dotenv import load_dotenv

from models import (
    MerchantRegister, UpdateMerchant, Token,
    PropertyCreate, PropertyUpdate, Property,
    BillCreate, BillUpdate, Bill,
    PaymentCreate, Payment,
    StripePaymentIntent,
    PaymentReport, PropertyReport
)

load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key_change_this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")

# Initialize Stripe
stripe.api_key = STRIPE_SECRET_KEY

# Create FastAPI instance
app = FastAPI(
    title="Property Billing SaaS",
    description="SaaS application for property developers with utility billing and online payments",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
client = AsyncIOMotorClient(MONGODB_URL)
db = client.property_billing_db

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await db.merchants.find_one({"email": email})
    if user is None:
        raise credentials_exception
    return user


def calculate_bill_amount(property_data: dict) -> float:
    """Calculate bill amount based on property calculation type"""
    if property_data["calculation_type"] == "per_sqm":
        if property_data.get("area_sqm") and property_data.get("rate_per_sqm"):
            return property_data["area_sqm"] * property_data["rate_per_sqm"]
    elif property_data["calculation_type"] == "fixed":
        if property_data.get("fixed_rate"):
            return property_data["fixed_rate"]
    return 0.0


# ==================== AUTH ENDPOINTS ====================

@app.post("/register", response_model=Token)
async def register_merchant(merchant: MerchantRegister):
    """Register a new merchant account"""
    existing_merchant = await db.merchants.find_one({"email": merchant.email})
    if existing_merchant:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(merchant.password)
    new_merchant = {
        "name": merchant.name,
        "email": merchant.email,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    }
    await db.merchants.insert_one(new_merchant)

    access_token = create_access_token(data={"sub": merchant.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and get access token"""
    user = await db.merchants.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me")
async def get_current_merchant(current_user: dict = Depends(get_current_user)):
    """Get current merchant information"""
    return {
        "name": current_user["name"],
        "email": current_user["email"],
        "created_at": current_user.get("created_at")
    }


# ==================== PROPERTY ENDPOINTS ====================

@app.post("/properties", response_model=dict, status_code=201)
async def create_property(property_data: PropertyCreate, current_user: dict = Depends(get_current_user)):
    """Create a new property"""
    property_dict = property_data.model_dump()
    property_dict.update({
        "merchant_id": str(current_user["_id"]),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    })

    result = await db.properties.insert_one(property_dict)
    property_dict["_id"] = str(result.inserted_id)

    return {"message": "Property created successfully", "property_id": str(result.inserted_id)}


@app.get("/properties", response_model=List[dict])
async def get_properties(current_user: dict = Depends(get_current_user)):
    """Get all properties for current merchant"""
    properties = []
    cursor = db.properties.find({"merchant_id": str(current_user["_id"])})
    async for prop in cursor:
        prop["_id"] = str(prop["_id"])
        properties.append(prop)
    return properties


@app.get("/properties/{property_id}", response_model=dict)
async def get_property(property_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific property"""
    if not ObjectId.is_valid(property_id):
        raise HTTPException(status_code=400, detail="Invalid property ID")

    prop = await db.properties.find_one({
        "_id": ObjectId(property_id),
        "merchant_id": str(current_user["_id"])
    })

    if not prop:
        raise HTTPException(status_code=404, detail="Property not found")

    prop["_id"] = str(prop["_id"])
    return prop


@app.put("/properties/{property_id}", response_model=dict)
async def update_property(
    property_id: str,
    property_data: PropertyUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a property"""
    if not ObjectId.is_valid(property_id):
        raise HTTPException(status_code=400, detail="Invalid property ID")

    update_fields = {k: v for k, v in property_data.model_dump().items() if v is not None}
    if not update_fields:
        raise HTTPException(status_code=400, detail="No data to update")

    update_fields["updated_at"] = datetime.utcnow()

    result = await db.properties.update_one(
        {"_id": ObjectId(property_id), "merchant_id": str(current_user["_id"])},
        {"$set": update_fields}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Property not found")

    return {"message": "Property updated successfully"}


@app.delete("/properties/{property_id}", response_model=dict)
async def delete_property(property_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a property"""
    if not ObjectId.is_valid(property_id):
        raise HTTPException(status_code=400, detail="Invalid property ID")

    result = await db.properties.delete_one({
        "_id": ObjectId(property_id),
        "merchant_id": str(current_user["_id"])
    })

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Property not found")

    return {"message": "Property deleted successfully"}


# ==================== BILL ENDPOINTS ====================

@app.post("/bills", response_model=dict, status_code=201)
async def create_bill(bill_data: BillCreate, current_user: dict = Depends(get_current_user)):
    """Create a new bill with automatic amount calculation"""
    # Verify property exists and belongs to merchant
    if not ObjectId.is_valid(bill_data.property_id):
        raise HTTPException(status_code=400, detail="Invalid property ID")

    property_doc = await db.properties.find_one({
        "_id": ObjectId(bill_data.property_id),
        "merchant_id": str(current_user["_id"])
    })

    if not property_doc:
        raise HTTPException(status_code=404, detail="Property not found")

    # Calculate amount
    amount = calculate_bill_amount(property_doc)

    bill_dict = bill_data.model_dump()
    bill_dict.update({
        "merchant_id": str(current_user["_id"]),
        "amount": amount,
        "status": "pending",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    })

    result = await db.bills.insert_one(bill_dict)

    return {
        "message": "Bill created successfully",
        "bill_id": str(result.inserted_id),
        "amount": amount
    }


@app.get("/bills", response_model=List[dict])
async def get_bills(
    status: Optional[str] = None,
    property_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all bills for current merchant with optional filters"""
    query = {"merchant_id": str(current_user["_id"])}

    if status:
        query["status"] = status
    if property_id:
        if not ObjectId.is_valid(property_id):
            raise HTTPException(status_code=400, detail="Invalid property ID")
        query["property_id"] = property_id

    bills = []
    cursor = db.bills.find(query).sort("created_at", -1)
    async for bill in cursor:
        bill["_id"] = str(bill["_id"])

        # Get property info
        if ObjectId.is_valid(bill["property_id"]):
            property_doc = await db.properties.find_one({"_id": ObjectId(bill["property_id"])})
            if property_doc:
                bill["property_name"] = property_doc.get("name")
                bill["property_address"] = property_doc.get("address")
                bill["tenant_name"] = property_doc.get("tenant_name")

        bills.append(bill)

    return bills


@app.get("/bills/{bill_id}", response_model=dict)
async def get_bill(bill_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific bill"""
    if not ObjectId.is_valid(bill_id):
        raise HTTPException(status_code=400, detail="Invalid bill ID")

    bill = await db.bills.find_one({
        "_id": ObjectId(bill_id),
        "merchant_id": str(current_user["_id"])
    })

    if not bill:
        raise HTTPException(status_code=404, detail="Bill not found")

    bill["_id"] = str(bill["_id"])

    # Get property info
    if ObjectId.is_valid(bill["property_id"]):
        property_doc = await db.properties.find_one({"_id": ObjectId(bill["property_id"])})
        if property_doc:
            bill["property_name"] = property_doc.get("name")
            bill["property_address"] = property_doc.get("address")
            bill["tenant_name"] = property_doc.get("tenant_name")
            bill["tenant_email"] = property_doc.get("tenant_email")

    return bill


@app.put("/bills/{bill_id}", response_model=dict)
async def update_bill(
    bill_id: str,
    bill_data: BillUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a bill"""
    if not ObjectId.is_valid(bill_id):
        raise HTTPException(status_code=400, detail="Invalid bill ID")

    update_fields = {k: v for k, v in bill_data.model_dump().items() if v is not None}
    if not update_fields:
        raise HTTPException(status_code=400, detail="No data to update")

    update_fields["updated_at"] = datetime.utcnow()

    result = await db.bills.update_one(
        {"_id": ObjectId(bill_id), "merchant_id": str(current_user["_id"])},
        {"$set": update_fields}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Bill not found")

    return {"message": "Bill updated successfully"}


@app.delete("/bills/{bill_id}", response_model=dict)
async def delete_bill(bill_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a bill"""
    if not ObjectId.is_valid(bill_id):
        raise HTTPException(status_code=400, detail="Invalid bill ID")

    result = await db.bills.delete_one({
        "_id": ObjectId(bill_id),
        "merchant_id": str(current_user["_id"])
    })

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Bill not found")

    return {"message": "Bill deleted successfully"}


# ==================== STRIPE PAYMENT ENDPOINTS ====================

@app.post("/payments/create-payment-intent", response_model=dict)
async def create_payment_intent(
    payment_data: StripePaymentIntent,
    current_user: dict = Depends(get_current_user)
):
    """Create a Stripe payment intent for a bill"""
    if not ObjectId.is_valid(payment_data.bill_id):
        raise HTTPException(status_code=400, detail="Invalid bill ID")

    # Verify bill exists
    bill = await db.bills.find_one({
        "_id": ObjectId(payment_data.bill_id),
        "merchant_id": str(current_user["_id"])
    })

    if not bill:
        raise HTTPException(status_code=404, detail="Bill not found")

    if bill["status"] == "paid":
        raise HTTPException(status_code=400, detail="Bill already paid")

    try:
        # Create Stripe payment intent
        intent = stripe.PaymentIntent.create(
            amount=int(payment_data.amount * 100),  # Convert to cents
            currency=payment_data.currency,
            metadata={
                "bill_id": payment_data.bill_id,
                "merchant_id": str(current_user["_id"])
            }
        )

        return {
            "client_secret": intent.client_secret,
            "payment_intent_id": intent.id
        }
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/payments/confirm", response_model=dict)
async def confirm_payment(
    payment_data: PaymentCreate,
    current_user: dict = Depends(get_current_user)
):
    """Confirm a payment and update bill status"""
    if not ObjectId.is_valid(payment_data.bill_id):
        raise HTTPException(status_code=400, detail="Invalid bill ID")

    # Verify bill exists
    bill = await db.bills.find_one({
        "_id": ObjectId(payment_data.bill_id),
        "merchant_id": str(current_user["_id"])
    })

    if not bill:
        raise HTTPException(status_code=404, detail="Bill not found")

    # Create payment record
    payment_dict = payment_data.model_dump()
    payment_dict.update({
        "merchant_id": str(current_user["_id"]),
        "property_id": bill["property_id"],
        "status": "completed",
        "paid_at": datetime.utcnow(),
        "created_at": datetime.utcnow()
    })

    result = await db.payments.insert_one(payment_dict)

    # Update bill status
    await db.bills.update_one(
        {"_id": ObjectId(payment_data.bill_id)},
        {"$set": {"status": "paid", "updated_at": datetime.utcnow()}}
    )

    return {
        "message": "Payment confirmed successfully",
        "payment_id": str(result.inserted_id)
    }


@app.get("/payments", response_model=List[dict])
async def get_payments(current_user: dict = Depends(get_current_user)):
    """Get all payments for current merchant"""
    payments = []
    cursor = db.payments.find({"merchant_id": str(current_user["_id"])}).sort("created_at", -1)
    async for payment in cursor:
        payment["_id"] = str(payment["_id"])

        # Get bill info
        if ObjectId.is_valid(payment["bill_id"]):
            bill = await db.bills.find_one({"_id": ObjectId(payment["bill_id"])})
            if bill:
                payment["bill_period_start"] = bill.get("billing_period_start")
                payment["bill_period_end"] = bill.get("billing_period_end")

        # Get property info
        if ObjectId.is_valid(payment["property_id"]):
            property_doc = await db.properties.find_one({"_id": ObjectId(payment["property_id"])})
            if property_doc:
                payment["property_name"] = property_doc.get("name")
                payment["tenant_name"] = property_doc.get("tenant_name")

        payments.append(payment)

    return payments


# ==================== REPORTS ENDPOINTS ====================

@app.get("/reports/summary", response_model=dict)
async def get_payment_summary(current_user: dict = Depends(get_current_user)):
    """Get payment summary report"""
    merchant_id = str(current_user["_id"])

    # Count properties
    total_properties = await db.properties.count_documents({"merchant_id": merchant_id})

    # Count bills by status
    total_bills = await db.bills.count_documents({"merchant_id": merchant_id})
    pending_bills = await db.bills.count_documents({"merchant_id": merchant_id, "status": "pending"})
    paid_bills = await db.bills.count_documents({"merchant_id": merchant_id, "status": "paid"})
    overdue_bills = await db.bills.count_documents({"merchant_id": merchant_id, "status": "overdue"})

    # Calculate amounts
    pipeline_due = [
        {"$match": {"merchant_id": merchant_id, "status": {"$in": ["pending", "overdue"]}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    result_due = await db.bills.aggregate(pipeline_due).to_list(1)
    total_amount_due = result_due[0]["total"] if result_due else 0

    pipeline_paid = [
        {"$match": {"merchant_id": merchant_id, "status": "completed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    result_paid = await db.payments.aggregate(pipeline_paid).to_list(1)
    total_amount_paid = result_paid[0]["total"] if result_paid else 0

    return {
        "total_properties": total_properties,
        "total_bills": total_bills,
        "total_amount_due": total_amount_due,
        "total_amount_paid": total_amount_paid,
        "total_outstanding": total_amount_due,
        "overdue_bills": overdue_bills,
        "pending_bills": pending_bills,
        "paid_bills": paid_bills
    }


@app.get("/reports/properties", response_model=List[dict])
async def get_property_reports(current_user: dict = Depends(get_current_user)):
    """Get detailed reports for each property"""
    merchant_id = str(current_user["_id"])
    reports = []

    cursor = db.properties.find({"merchant_id": merchant_id})
    async for prop in cursor:
        property_id = str(prop["_id"])

        # Count bills
        total_bills = await db.bills.count_documents({
            "merchant_id": merchant_id,
            "property_id": property_id
        })

        # Calculate paid amount
        pipeline_paid = [
            {"$match": {"merchant_id": merchant_id, "property_id": property_id, "status": "completed"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]
        result_paid = await db.payments.aggregate(pipeline_paid).to_list(1)
        total_paid = result_paid[0]["total"] if result_paid else 0

        # Calculate outstanding
        pipeline_outstanding = [
            {"$match": {
                "merchant_id": merchant_id,
                "property_id": property_id,
                "status": {"$in": ["pending", "overdue"]}
            }},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]
        result_outstanding = await db.bills.aggregate(pipeline_outstanding).to_list(1)
        total_outstanding = result_outstanding[0]["total"] if result_outstanding else 0

        # Get last payment date
        last_payment = await db.payments.find_one(
            {"merchant_id": merchant_id, "property_id": property_id},
            sort=[("paid_at", -1)]
        )

        reports.append({
            "property_id": property_id,
            "property_name": prop.get("name"),
            "property_address": prop.get("address"),
            "tenant_name": prop.get("tenant_name"),
            "total_bills": total_bills,
            "total_paid": total_paid,
            "total_outstanding": total_outstanding,
            "last_payment_date": last_payment.get("paid_at") if last_payment else None
        })

    return reports


@app.get("/reports/payment-history", response_model=List[dict])
async def get_payment_history(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get payment history with optional date range"""
    query = {"merchant_id": str(current_user["_id"]), "status": "completed"}

    if start_date:
        query["paid_at"] = {"$gte": start_date}
    if end_date:
        if "paid_at" in query:
            query["paid_at"]["$lte"] = end_date
        else:
            query["paid_at"] = {"$lte": end_date}

    payments = []
    cursor = db.payments.find(query).sort("paid_at", -1)
    async for payment in cursor:
        payment["_id"] = str(payment["_id"])

        # Get property info
        if ObjectId.is_valid(payment["property_id"]):
            property_doc = await db.properties.find_one({"_id": ObjectId(payment["property_id"])})
            if property_doc:
                payment["property_name"] = property_doc.get("name")
                payment["tenant_name"] = property_doc.get("tenant_name")

        payments.append(payment)

    return payments


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "Property Billing SaaS API",
        "version": "1.0.0",
        "docs": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
