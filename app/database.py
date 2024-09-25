from motor.motor_asyncio import AsyncIOMotorClient

client = None
db = None

def connect_to_mongo():
    global client, db
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client.loyalty_db