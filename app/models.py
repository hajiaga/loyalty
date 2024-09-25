from pydantic import BaseModel, EmailStr

class MerchantRegister(BaseModel):
    name: str
    email: EmailStr
    password: str

class UpdateMerchant(BaseModel):
    name: str | None = None
    password: str | None = None

class Token(BaseModel):
    access_token: str
    token_type: str