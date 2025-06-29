#!/usr/bin/env python3
"""
Secure Chat Application with RSA Encryption
Builds on the existing Flask authentication system
Fixed: JSON serialization error with MongoDB ObjectId
"""

from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
import pymongo
import bcrypt
import os
from datetime import datetime, timedelta
import logging
import json
import base64
from bson import ObjectId
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Initialize SocketIO with CORS support
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# MongoDB Configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
DATABASE_NAME = 'securecomm_db'
USERS_COLLECTION = 'users'
MESSAGES_COLLECTION = 'messages'
KEYS_COLLECTION = 'user_keys'

# Custom JSON encoder for MongoDB ObjectId
class MongoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

# Add custom JSON filter for templates
def mongo_to_json(data):
    """Convert MongoDB documents to JSON-safe format"""
    return json.dumps(data, cls=MongoJSONEncoder)

app.jinja_env.filters['tojsonfilter'] = mongo_to_json

class CryptoManager:
    """Handles RSA key generation and encryption/decryption"""
    
    @staticmethod
    def generate_rsa_keypair():
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    
    @staticmethod
    def encrypt_message(message, public_key_pem):
        """Encrypt message with RSA public key"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # RSA can only encrypt small amounts of data, so we'll use it for a symmetric key
            # For demo purposes, we'll encrypt the message directly (limited to ~200 bytes)
            if len(message.encode('utf-8')) > 190:  # Leave room for padding
                raise ValueError("Message too long for RSA encryption")
            
            encrypted = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return None
    
    @staticmethod
    def decrypt_message(encrypted_message, private_key_pem):
        """Decrypt message with RSA private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
            
            decrypted = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

class MongoDBAuth:
    def __init__(self, mongo_uri, db_name):
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.users = self.db[USERS_COLLECTION]
        self.messages = self.db[MESSAGES_COLLECTION]
        self.keys = self.db[KEYS_COLLECTION]
        
        # Create indexes
        try:
            self.users.create_index("username", unique=True)
            self.keys.create_index("username", unique=True)
            self.messages.create_index([("sender", 1), ("recipient", 1), ("timestamp", -1)])
            logger.info("MongoDB connection established and indexes created")
        except Exception as e:
            logger.error(f"MongoDB setup error: {e}")
    
    def _serialize_document(self, doc):
        """Convert MongoDB document to JSON-safe format"""
        if doc is None:
            return None
        
        # Convert ObjectId to string
        if '_id' in doc:
            doc['_id'] = str(doc['_id'])
        
        # Convert datetime objects to ISO format
        for key, value in doc.items():
            if isinstance(value, datetime):
                doc[key] = value.isoformat()
        
        return doc
    
    def _serialize_documents(self, docs):
        """Convert list of MongoDB documents to JSON-safe format"""
        return [self._serialize_document(doc.copy()) for doc in docs]
    
    def hash_password(self, password):
        """Hash password using BCrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    def verify_password(self, password, hashed_password):
        """Verify password against BCrypt hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    
    def register_user(self, username, password, email=None):
        """Register a new user and generate RSA keys"""
        try:
            # Check if user already exists
            if self.users.find_one({"username": username}):
                return {"success": False, "message": "Username already exists"}
            
            # Hash the password
            hashed_password = self.hash_password(password)
            
            # Generate RSA key pair
            private_key, public_key = CryptoManager.generate_rsa_keypair()
            
            # Create user document
            user_doc = {
                "username": username,
                "password": hashed_password,
                "email": email,
                "created_at": datetime.utcnow(),
                "last_login": None,
                "is_active": True,
                "is_online": False
            }
            
            # Create keys document
            keys_doc = {
                "username": username,
                "private_key": private_key,
                "public_key": public_key,
                "created_at": datetime.utcnow()
            }
            
            # Insert user and keys
            user_result = self.users.insert_one(user_doc)
            keys_result = self.keys.insert_one(keys_doc)
            
            if user_result.inserted_id and keys_result.inserted_id:
                logger.info(f"User registered successfully with RSA keys: {username}")
                return {"success": True, "message": "User registered successfully"}
            else:
                return {"success": False, "message": "Registration failed"}
                
        except pymongo.errors.DuplicateKeyError:
            return {"success": False, "message": "Username already exists"}
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"success": False, "message": "Registration failed due to server error"}
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        try:
            # Find user
            user = self.users.find_one({"username": username, "is_active": True})
            
            if not user:
                return {"success": False, "message": "Invalid credentials"}
            
            # Verify password
            if self.verify_password(password, user['password']):
                # Update last login and online status
                self.users.update_one(
                    {"username": username},
                    {"$set": {"last_login": datetime.utcnow(), "is_online": True}}
                )
                
                logger.info(f"User authenticated successfully: {username}")
                return {
                    "success": True, 
                    "message": "Authentication successful",
                    "user": {
                        "username": username,
                        "email": user.get('email'),
                        "last_login": user.get('last_login')
                    }
                }
            else:
                return {"success": False, "message": "Invalid credentials"}
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return {"success": False, "message": "Authentication failed due to server error"}
    
    def get_user(self, username):
        """Get user information"""
        try:
            user = self.users.find_one(
                {"username": username, "is_active": True},
                {"password": 0}
            )
            return self._serialize_document(user) if user else None
        except Exception as e:
            logger.error(f"Get user error: {e}")
            return None
    
    def get_public_key(self, username):
        """Get user's public key"""
        try:
            key_doc = self.keys.find_one({"username": username})
            return key_doc['public_key'] if key_doc else None
        except Exception as e:
            logger.error(f"Get public key error: {e}")
            return None
    
    def get_private_key(self, username):
        """Get user's private key"""
        try:
            key_doc = self.keys.find_one({"username": username})
            return key_doc['private_key'] if key_doc else None
        except Exception as e:
            logger.error(f"Get private key error: {e}")
            return None
    
    def get_online_users(self):
        """Get list of online users"""
        try:
            users = self.users.find(
                {"is_online": True, "is_active": True},
                {"username": 1, "_id": 0}
            )
            return [user['username'] for user in users]
        except Exception as e:
            logger.error(f"Get online users error: {e}")
            return []
    
    def set_user_offline(self, username):
        """Set user as offline"""
        try:
            self.users.update_one(
                {"username": username},
                {"$set": {"is_online": False}}
            )
        except Exception as e:
            logger.error(f"Set user offline error: {e}")
    
    def save_message(self, sender, recipient, encrypted_message, message_id):
        """Save encrypted message to database"""
        try:
            message_doc = {
                "message_id": message_id,
                "sender": sender,
                "recipient": recipient,
                "encrypted_content": encrypted_message,
                "timestamp": datetime.utcnow(),
                "delivered": False,
                "read": False
            }
            
            result = self.messages.insert_one(message_doc)
            return result.inserted_id is not None
        except Exception as e:
            logger.error(f"Save message error: {e}")
            return False
    
    def get_messages(self, user1, user2, limit=50):
        """Get messages between two users (returns JSON-safe format)"""
        try:
            messages = self.messages.find({
                "$or": [
                    {"sender": user1, "recipient": user2},
                    {"sender": user2, "recipient": user1}
                ]
            }).sort("timestamp", -1).limit(limit)
            
            # Convert to list and serialize
            message_list = list(messages)
            return self._serialize_documents(message_list)
        except Exception as e:
            logger.error(f"Get messages error: {e}")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize MongoDB connection
mongo_auth = MongoDBAuth(MONGO_URI, DATABASE_NAME)

# Store active socket connections and online users
active_connections = {}  # username: sid
online_users = set()  # Set of usernames that are currently online

# Removed duplicate login_required decorator as it's already defined in auth.py

@app.route('/')
def index():
    """Home page - redirect to login if not authenticated"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        # Authenticate user
        result = mongo_auth.authenticate_user(username, password)
        
        if result['success']:
            session['username'] = username
            session['login_time'] = datetime.utcnow().isoformat()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(result['message'], 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        
        # Validation
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        # Register user
        result = mongo_auth.register_user(username, password, email)
        
        if result['success']:
            flash('Registration successful! RSA keys generated. Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash(result['message'], 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page - requires authentication"""
    username = session['username']
    user_info = mongo_auth.get_user(username)
    online_users = mongo_auth.get_online_users()
    
    # Remove current user from online users list
    if username in online_users:
        online_users.remove(username)
    
    return render_template('dashboard.html', user=user_info, online_users=online_users)

@app.route('/chat/<recipient>')
def chat(recipient):
    """Chat page with specific user"""
    if 'username' not in session:
        flash('Please login to access this page', 'error')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Check if recipient exists
    recipient_info = mongo_auth.get_user(recipient)
    if not recipient_info:
        flash('User not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get chat history (already serialized)
    messages = mongo_auth.get_messages(username, recipient)
    
    return render_template('chat.html', 
                         current_user=username, 
                         recipient=recipient,
                         messages=messages)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    
    # Get user data from database
    user = mongo_auth.get_user(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        # Update email if provided and different
        new_email = request.form.get('email')
        if new_email and new_email != user.get('email', ''):
            if not re.match(r'[^@]+@[^@]+\.[^@]+', new_email):
                flash('Invalid email address', 'danger')
            else:
                mongo_auth.users.update_one(
                    {'username': username},
                    {'$set': {'email': new_email}}
                )
                flash('Email updated successfully', 'success')
                # Update user data
                user['email'] = new_email
        
        # Update password if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password and confirm_password:
            # Get user with password for verification
            user_with_password = mongo_auth.users.find_one(
                {'username': username},
                {'password': 1}
            )
            
            if not user_with_password or 'password' not in user_with_password:
                flash('Error: Could not verify current password', 'danger')
            elif not bcrypt.checkpw(current_password.encode('utf-8'), user_with_password['password']):
                flash('Current password is incorrect', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'danger')
            elif len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
            else:
                hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                mongo_auth.users.update_one(
                    {'username': username},
                    {'$set': {'password': hashed}}
                )
                flash('Password updated successfully', 'success')
        
        # Refresh user data
        user = mongo_auth.get_user(username)
        
    # Prepare user data for template (remove sensitive info)
    user_data = {
        'username': user.get('username'),
        'email': user.get('email', 'Not set'),
        'created_at': user.get('created_at', datetime.utcnow())
    }
        
    return render_template('settings.html', user=user_data)

@app.route('/logout')
@login_required
def logout():
    mongo_auth.set_user_offline(session['username'])
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Socket.IO Events
@socketio.on('connect')
def on_connect():
    """Handle client connection"""
    if 'username' in session:
        username = session['username']
        active_connections[username] = request.sid
        user_went_online = username not in online_users
        online_users.add(username)
        join_room(username)
        
        # Get list of all online users (including the current user)
        all_online_users = list(online_users)
        
        # Send the complete list of online users to the newly connected user
        emit('online_users', {
            'users': all_online_users,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Only notify others if this is a new online status
        if user_went_online:
            emit('user_status', {
                'username': username, 
                'status': 'online',
                'timestamp': datetime.utcnow().isoformat()
            }, broadcast=True, skip_sid=request.sid)
        
        logger.info(f"User connected: {username}. Online users: {all_online_users}")
    else:
        logger.warning("Unauthorized connection attempt")

@socketio.on('disconnect')
def on_disconnect():
    """Handle client disconnection"""
    if 'username' in session:
        username = session['username']
        
        # Only process disconnection if this was the last connection for the user
        if username in active_connections and active_connections[username] == request.sid:
            if username in online_users:
                online_users.remove(username)
            
            if username in active_connections:
                del active_connections[username]
            
            mongo_auth.set_user_offline(username)
            leave_room(username)
            
            # Only notify others if the user is actually going offline
            if username not in active_connections:
                emit('user_status', {
                    'username': username, 
                    'status': 'offline',
                    'timestamp': datetime.utcnow().isoformat()
                }, broadcast=True, skip_sid=request.sid)
            
            logger.info(f"User disconnected: {username}. Remaining online users: {list(online_users)}")
        else:
            logger.info(f"User {username} has other active connections")

@socketio.on('send_message')
def handle_message(data):
    """Handle encrypted message sending"""
    if 'username' not in session:
        emit('error', {'message': 'Not authenticated'})
        return
    
    try:
        sender = session['username']
        recipient = data['recipient']
        message = data['message']
        message_id = secrets.token_urlsafe(16)
        
        # Get recipient's public key
        recipient_public_key = mongo_auth.get_public_key(recipient)
        if not recipient_public_key:
            emit('error', {'message': 'Recipient public key not found'})
            return
        
        # Encrypt the message
        encrypted_message = CryptoManager.encrypt_message(message, recipient_public_key)
        if not encrypted_message:
            emit('error', {'message': 'Failed to encrypt message'})
            return
        
        # Save encrypted message to database
        if mongo_auth.save_message(sender, recipient, encrypted_message, message_id):
            
            # Send encryption status to sender
            emit('encryption_status', {
                'message_id': message_id,
                'status': 'encrypted',
                'recipient': recipient,
                'original_length': len(message),
                'encrypted_length': len(encrypted_message),
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Send encrypted message to recipient if online
            if recipient in active_connections:
                socketio.emit('new_message', {
                    'message_id': message_id,
                    'sender': sender,
                    'encrypted_content': encrypted_message,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=recipient)
            
            # Confirm message sent
            emit('message_sent', {
                'message_id': message_id,
                'recipient': recipient,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        else:
            emit('error', {'message': 'Failed to save message'})
            
    except Exception as e:
        logger.error(f"Handle message error: {e}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('decrypt_message')
def handle_decrypt_message(data):
    """Handle message decryption request"""
    if 'username' not in session:
        emit('error', {'message': 'Not authenticated'})
        return
    
    try:
        username = session['username']
        encrypted_content = data['encrypted_content']
        message_id = data['message_id']
        
        # Get user's private key
        private_key = mongo_auth.get_private_key(username)
        if not private_key:
            emit('error', {'message': 'Private key not found'})
            return
        
        # Decrypt the message
        decrypted_message = CryptoManager.decrypt_message(encrypted_content, private_key)
        if decrypted_message is not None:
            # Send decryption status
            emit('decryption_status', {
                'message_id': message_id,
                'status': 'decrypted',
                'encrypted_length': len(encrypted_content),
                'decrypted_length': len(decrypted_message),
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Send decrypted content
            emit('message_decrypted', {
                'message_id': message_id,
                'content': decrypted_message,
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            emit('error', {'message': 'Failed to decrypt message'})
            
    except Exception as e:
        logger.error(f"Decrypt message error: {e}")
        emit('error', {'message': 'Failed to decrypt message'})

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test MongoDB connection
        mongo_auth.client.admin.command('ping')
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# Error handlers
@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Internal server error"), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found"), 404

if __name__ == '__main__':
    # Run with TLS in production
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
