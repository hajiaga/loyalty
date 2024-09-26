from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Configuration for JWT
SECRET_KEY = "your_secret_key"  # Replace with your actual secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Create FastAPI instance
app = FastAPI()

# Connect to MongoDB
client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.loyalty_db

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models for request validation
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

# Password hashing functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT token creation
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Get current user from token
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

# Registration endpoint
@app.post("/register", response_model=Token)
async def register_merchant(merchant: MerchantRegister):
    existing_merchant = await db.merchants.find_one({"email": merchant.email})
    if existing_merchant:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(merchant.password)
    new_merchant = {"name": merchant.name, "email": merchant.email, "password": hashed_password}
    await db.merchants.insert_one(new_merchant)
    
    access_token = create_access_token(data={"sub": merchant.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Login endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.merchants.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Update merchant information
@app.put("/merchants/update", response_model=dict)
async def update_merchant(update_data: UpdateMerchant, current_user: dict = Depends(get_current_user)):
    update_fields = {}
    if update_data.name:
        update_fields["name"] = update_data.name
    if update_data.password:
        update_fields["password"] = hash_password(update_data.password)

    if not update_fields:
        raise HTTPException(status_code=400, detail="No data to update")

    await db.merchants.update_one({"email": current_user["email"]}, {"$set": update_fields})
    return {"status": "Update successful"}

# Delete merchant account
@app.delete("/merchants/delete", response_model=dict)
async def delete_merchant(current_user: dict = Depends(get_current_user)):
    await db.merchants.delete_one({"email": current_user["email"]})
    return {"status": "Account deleted"}

# Protected route example
@app.get("/secure-data")
async def secure_data(current_user: dict = Depends(get_current_user)):
    return {"message": "This is a secure endpoint", "user": current_user["email"]}