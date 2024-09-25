from fastapi import FastAPI
from app.database import connect_to_mongo
from app.routes import auth, merchants

app = FastAPI()

# Подключение к базе данных
connect_to_mongo()

# Подключение маршрутов
app.include_router(auth.router)
app.include_router(merchants.router)