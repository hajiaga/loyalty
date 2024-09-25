from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import timedelta, datetime
from app.models import MerchantRegister, Token
from app.database import db
from app.security import hash_password, verify_password, create_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
router = APIRouter()

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверные учетные данные.",
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

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_merchant(merchant: MerchantRegister):
    existing_merchant = await db.merchants.find_one({"email": merchant.email})
    if existing_merchant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Мерчант с таким email уже зарегистрирован.",
        )

    hashed_password = hash_password(merchant.password)
    new_merchant = {
        "name": merchant.name,
        "email": merchant.email,
        "password": hashed_password,
    }

    result = await db.merchants.insert_one(new_merchant)
    return {"status": "registered", "merchant_id": str(result.inserted_id)}

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    existing_merchant = await db.merchants.find_one({"email": form_data.username})
    if not existing_merchant or not verify_password(form_data.password, existing_merchant["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": existing_merchant["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}