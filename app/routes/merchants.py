from fastapi import APIRouter, Depends, HTTPException, status
from app.models import UpdateMerchant
from app.database import db
from app.security import hash_password
from app.routes.auth import get_current_user

router = APIRouter()

@router.put("/merchants/update")
async def update_merchant(update_data: UpdateMerchant, current_user: dict = Depends(get_current_user)):
    update_fields = {}
    if update_data.name:
        update_fields["name"] = update_data.name
    if update_data.password:
        update_fields["password"] = hash_password(update_data.password)

    if not update_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Нет данных для обновления."
        )

    await db.merchants.update_one({"email": current_user["email"]}, {"$set": update_fields})
    return {"status": "Обновление успешно"}

@router.delete("/merchants/delete")
async def delete_merchant(current_user: dict = Depends(get_current_user)):
    await db.merchants.delete_one({"email": current_user["email"]})
    return {"status": "Аккаунт удален"}