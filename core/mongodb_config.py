import os
from dotenv import load_dotenv
import djongo

# Load environment variables from .env file
load_dotenv()

# Retrieve MongoDB credentials from the .env file
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME")
MONGODB_USER = os.getenv("MONGODB_USER")
MONGODB_PASS = os.getenv("MONGODB_PASS")

# MongoDB connection configuration
mongo_config = {
    'ENGINE': 'djongo',
    'NAME': MONGO_DB_NAME,  
    'CLIENT': {
        'host': MONGO_URI,
        'username': MONGODB_USER,
        'password': MONGODB_PASS,
        'authSource': 'admin',
        'authMechanism': 'SCRAM-SHA-256',
    }
}