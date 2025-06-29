import os
import logging
from app import app, socketio, mongo_auth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_mongodb():
    """Initialize MongoDB connection and ensure indexes"""
    try:
        # Test the connection
        mongo_auth.client.server_info()
        logger.info("Successfully connected to MongoDB")
        
        # Ensure indexes
        mongo_auth.users.create_index("username", unique=True)
        mongo_auth.keys.create_index("username", unique=True)
        mongo_auth.messages.create_index([("sender", 1), ("recipient", 1), ("timestamp", -1)])
        logger.info("MongoDB indexes ensured")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize MongoDB: {e}")
        return False

if __name__ == "__main__":
    # Initialize MongoDB
    if not initialize_mongodb():
        logger.error("Failed to initialize MongoDB. Exiting...")
        exit(1)
        
    # Get port from environment variable or use default
    port = int(os.environ.get("PORT", 5000))
    
    # Run the application
    logger.info(f"Starting application on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
