import logging
from app import app, socketio, mongo_auth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_mongodb():
    """Initialize MongoDB connection and ensure indexes"""
    try:
        mongo_auth.client.server_info()
        logger.info("Successfully connected to MongoDB")

        mongo_auth.users.create_index("username", unique=True)
        mongo_auth.keys.create_index("username", unique=True)
        mongo_auth.messages.create_index(
            [("sender", 1), ("recipient", 1), ("timestamp", -1)]
        )
        logger.info("MongoDB indexes ensured")
    except Exception as e:
        logger.error(f"Failed to initialize MongoDB: {e}")
        raise

# ✅ Call MongoDB init at module load (so Gunicorn triggers it)
initialize_mongodb()

# ✅ Expose the app for Gunicorn + Eventlet to run
app = socketio
