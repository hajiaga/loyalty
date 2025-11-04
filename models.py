from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Literal
from datetime import datetime
from bson import ObjectId


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


# User/Merchant Models
class MerchantRegister(BaseModel):
    name: str
    email: EmailStr
    password: str


class UpdateMerchant(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


# Property Models
class PropertyBase(BaseModel):
    name: str = Field(..., description="Property name or identifier")
    address: str = Field(..., description="Property address")
    calculation_type: Literal["per_sqm", "fixed"] = Field(
        ..., description="Calculation type: per_sqm or fixed"
    )
    area_sqm: Optional[float] = Field(None, description="Area in square meters")
    rate_per_sqm: Optional[float] = Field(None, description="Rate per square meter")
    fixed_rate: Optional[float] = Field(None, description="Fixed rate per unit")
    tenant_name: Optional[str] = Field(None, description="Tenant name")
    tenant_email: Optional[EmailStr] = Field(None, description="Tenant email")
    tenant_phone: Optional[str] = Field(None, description="Tenant phone")


class PropertyCreate(PropertyBase):
    pass


class PropertyUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    calculation_type: Optional[Literal["per_sqm", "fixed"]] = None
    area_sqm: Optional[float] = None
    rate_per_sqm: Optional[float] = None
    fixed_rate: Optional[float] = None
    tenant_name: Optional[str] = None
    tenant_email: Optional[EmailStr] = None
    tenant_phone: Optional[str] = None


class Property(PropertyBase):
    id: str = Field(alias="_id")
    merchant_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}


# Bill Models
class BillBase(BaseModel):
    property_id: str = Field(..., description="Property ID")
    billing_period_start: datetime = Field(..., description="Billing period start date")
    billing_period_end: datetime = Field(..., description="Billing period end date")
    due_date: datetime = Field(..., description="Payment due date")
    description: Optional[str] = Field(None, description="Bill description")


class BillCreate(BillBase):
    pass


class BillUpdate(BaseModel):
    billing_period_start: Optional[datetime] = None
    billing_period_end: Optional[datetime] = None
    due_date: Optional[datetime] = None
    description: Optional[str] = None
    status: Optional[Literal["pending", "paid", "overdue", "cancelled"]] = None


class Bill(BillBase):
    id: str = Field(alias="_id")
    merchant_id: str
    amount: float = Field(..., description="Calculated bill amount")
    status: Literal["pending", "paid", "overdue", "cancelled"] = "pending"
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}


# Payment Models
class PaymentBase(BaseModel):
    bill_id: str = Field(..., description="Bill ID")
    amount: float = Field(..., description="Payment amount")
    payment_method: Literal["stripe", "cash", "bank_transfer"] = "stripe"


class PaymentCreate(PaymentBase):
    stripe_payment_intent_id: Optional[str] = None


class Payment(PaymentBase):
    id: str = Field(alias="_id")
    merchant_id: str
    property_id: str
    stripe_payment_intent_id: Optional[str] = None
    status: Literal["pending", "completed", "failed", "refunded"] = "pending"
    paid_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}


# Stripe Models
class StripePaymentIntent(BaseModel):
    bill_id: str
    amount: float
    currency: str = "usd"
    customer_email: Optional[str] = None


# Report Models
class PaymentReport(BaseModel):
    total_properties: int
    total_bills: int
    total_amount_due: float
    total_amount_paid: float
    total_outstanding: float
    overdue_bills: int
    pending_bills: int
    paid_bills: int


class PropertyReport(BaseModel):
    property_id: str
    property_name: str
    property_address: str
    tenant_name: Optional[str]
    total_bills: int
    total_paid: float
    total_outstanding: float
    last_payment_date: Optional[datetime]
