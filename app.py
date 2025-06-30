#!/usr/bin/env python3
"""
Secure Chat Application with RSA Encryption
Builds on the existing Flask authentication system
Fixed: JSON serialization error with MongoDB ObjectId
"""

from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_pymongo import PyMongo
import pymongo
import bcrypt
import os
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import logging
import json
import base64
from bson import ObjectId, Binary
from bson.binary import Binary
from gridfs import GridFS, GridFSBucket
from bson.objectid import ObjectId
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import secrets
import re
import mimetypes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# File upload configuration
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', }
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max file size
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Initialize SocketIO with CORS support
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# MongoDB Configuration
MONGO_URI = os.environ.get('MONGO_URI')
DATABASE_NAME = 'securecomm_db'
USERS_COLLECTION = 'users'
MESSAGES_COLLECTION = 'messages'
KEYS_COLLECTION = 'user_keys'

# Configure MongoDB
app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)
# Obtain explicit database reference (Flask-PyMongo's mongo.db can be None if DB name not in URI)
_db = mongo.cx.get_database(DATABASE_NAME)

# Initialize GridFS after app context is available
def init_gridfs():
    """Initialize GridFS objects safely.
    Uses PyMongo client to get database by name to avoid cases where mongo.db is None
    (e.g., if default DB not parsed correctly from the URI)."""
    with app.app_context():
        # Obtain the database explicitly by name
        db = mongo.cx.get_database(DATABASE_NAME)
        return GridFS(db), GridFSBucket(db)

# Initialize GridFS
fs, fs_bucket = init_gridfs()  # Uses _db internally
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
            # Validate input
            if not encrypted_message or not private_key_pem:
                logger.error("Missing encrypted message or private key")
                return None
                
            # Load private key
            try:
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
            except Exception as e:
                logger.error(f"Failed to load private key: {e}")
                return None
            
            # Decode base64
            try:
                encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
            except Exception as e:
                logger.error(f"Invalid base64 encoding: {e}")
                return None
            
            # Decrypt
            try:
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
                logger.error(f"Decryption failed: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Unexpected error in decrypt_message: {e}", exc_info=True)
            return None

class MongoDBAuth:
    def __init__(self, mongo_db):
        self.db = mongo_db
        self.users = self.db[USERS_COLLECTION]
        self.messages = self.db[MESSAGES_COLLECTION]
        self.keys = self.db[KEYS_COLLECTION]
        
        # Create indexes
        try:
            self.users.create_index("username", unique=True)
            self.keys.create_index("username", unique=True)
            self.messages.create_index([("sender", 1), ("recipient", 1), ("timestamp", -1)])
            logger.info("MongoDB collections and indexes verified")
        except Exception as e:
            logger.error(f"MongoDB setup error: {e}")
            raise    
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
    
    def save_message(self, sender, recipient, enc_for_recipient, enc_for_sender, message_id, is_file=False, file_info=None):
        """Save encrypted message with copies for both recipient and sender"""
        try:
            message = {
                '_id': message_id,
                'message_id': message_id,
                'sender': sender,
                'recipient': recipient,
                'encrypted_for_recipient': enc_for_recipient,
                'encrypted_for_sender': enc_for_sender,
                'timestamp': datetime.utcnow(),
                'delivered': False,
                'read': False,
                'is_file': is_file,
                'file_info': file_info if is_file else None
            }
            # For backward compatibility
            message['encrypted_content'] = enc_for_recipient
            self.messages.insert_one(message)
            return True
        except Exception as e:
            logger.error(f"Error saving message: {e}", exc_info=True)
            return False
            
    def mark_message_delivered(self, message_id):
        """Mark a message as delivered"""
        try:
            self.messages.update_one(
                {'_id': message_id},
                {'$set': {'delivered': True, 'delivered_at': datetime.utcnow()}}
            )
            return True
        except Exception as e:
            logger.error(f"Error marking message as delivered: {e}", exc_info=True)
            return False
    
    def get_messages(self, user1, user2, limit=50):
        """Get messages between two users (returns JSON-safe format)"""
        query = {
            "$or": [
                {"$and": [{"sender": user1}, {"recipient": user2}]},
                {"$and": [{"sender": user2}, {"recipient": user1}]}
            ]
        }
        
        messages = list(self.messages
                        .find(query)
                        .sort("timestamp", -1)
                        .limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        return self._serialize_documents(messages)
        
    def search_users(self, query, current_user):
        """
        Search for users by username (case-insensitive partial match)
        Returns list of users with their online status
        """
        try:
            # Create a case-insensitive regex pattern for partial matching
            regex_pattern = f".*{re.escape(query)}.*"
            
            # Find users matching the query (case-insensitive)
            users_cursor = self.users.find({
                "username": {"$regex": regex_pattern, "$options": 'i'},
                "is_active": True,
                "username": {"$ne": current_user}  # Exclude current user from results
            }, {"password": 0})  # Exclude password hash
            
            # Get list of online users for status
            online_users = [user for user in self.get_online_users() if user != current_user]
            
            # Format results with online status
            results = []
            for user in users_cursor:
                username = user['username']
                results.append({
                    'username': username,
                    'is_online': username in online_users
                })
                
            return results
            
        except Exception as e:
            logger.error(f"Error searching users: {str(e)}")
            return []

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize MongoDB authentication
mongo_auth = MongoDBAuth(_db)

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
    if 'username' not in session:
        return redirect(url_for('login'))
        
    username = session['username']
    user = mongo_auth.get_user(username)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))
    
    online_users = mongo_auth.get_online_users()
    
    # Get recent messages for the activity feed
    recent_messages = list(mongo_auth.messages.find({
        '$or': [
            {'sender': username},
            {'recipient': username}
        ]
    }).sort('timestamp', -1).limit(5))
    
    # Convert ObjectId to string for JSON serialization
    for msg in recent_messages:
        msg['_id'] = str(msg['_id'])
        if 'timestamp' in msg and isinstance(msg['timestamp'], datetime):
            msg['timestamp'] = msg['timestamp'].isoformat()
    
    return render_template('dashboard.html', 
                         user=user, 
                         online_users=online_users,
                         recent_messages=recent_messages)

@app.route('/chat/<recipient>')
@login_required
def chat(recipient):
    """Chat page with specific user"""
    if 'username' not in session:
        return redirect(url_for('login'))
        
    username = session['username']
    user = mongo_auth.get_user(username)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))
    
    # Get user's public key for encryption
    public_key_pem = mongo_auth.get_public_key(username)
    
    # Get messages between the two users
    messages = mongo_auth.get_messages(username, recipient)
    
    # Get online status of the recipient
    online_users = mongo_auth.get_online_users()
    is_recipient_online = recipient in online_users
    
    return render_template('chat.html',
                           user=user,
                           current_user={'username': username},  # Add current_user for template
                           recipient=recipient,
                           messages=messages,
                           public_key=public_key_pem,
                           is_recipient_online=is_recipient_online)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    username = session['username']
    
    if request.method == 'POST':
        # Get the user with password for verification
        user_data = mongo_auth.users.find_one(
            {"username": username, "is_active": True}
        )
        
        if not user_data:
            flash('User not found', 'danger')
            return redirect(url_for('dashboard'))
        
        # Update email if provided
        new_email = request.form.get('email')
        if new_email and new_email != user_data.get('email'):
            # Validate email format
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
                flash('Invalid email format', 'danger')
                return redirect(url_for('user_settings'))
                
            mongo_auth.users.update_one(
                {'username': username},
                {'$set': {'email': new_email}}
            )
            flash('Email updated successfully', 'success')
        
        # Update password if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password and confirm_password:
            # Verify current password
            if not mongo_auth.verify_password(current_password, user_data['password']):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('user_settings'))
                
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('user_settings'))
                
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('user_settings'))
                
            # Update password
            hashed = mongo_auth.hash_password(new_password)
            mongo_auth.users.update_one(
                {'username': username},
                {'$set': {'password': hashed}}
            )
            flash('Password updated successfully', 'success')
        
        return redirect(url_for('user_settings'))
    
    # For GET request, get user data without password and render the settings page
    user = mongo_auth.get_user(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('settings.html', user=user)

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
    """Handle client connection and deliver pending messages"""
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
            
            # Check for undelivered messages
            try:
                undelivered_messages = mongo_auth.messages.find({
                    'recipient': username,
                    'delivered': False
                })
                
                for msg in undelivered_messages:
                    # Mark as delivered
                    mongo_auth.messages.update_one(
                        {'_id': msg['_id']},
                        {'$set': {'delivered': True}}
                    )
                    
                    if msg.get('is_file'):
                        # Send file message
                        emit('new_file_message', {
                            'message_id': msg['message_id'],
                            'sender': msg['sender'],
                            'encrypted_content': msg['encrypted_content'],
                            'file_info': msg.get('file_info', {}),
                            'timestamp': msg['timestamp'].isoformat(),
                            'delivered': True
                        }, room=request.sid)
                    else:
                        # Send regular text message
                        emit('new_message', {
                            'message_id': msg['message_id'],
                            'sender': msg['sender'],
                            'encrypted_content': msg['encrypted_content'],
                            'timestamp': msg['timestamp'].isoformat(),
                            'delivered': True
                        }, room=request.sid)
                    
                    # Notify sender that message was delivered
                    if msg['sender'] in active_connections:
                        emit('message_status', {
                            'message_id': msg['message_id'],
                            'status': 'delivered',
                            'recipient': username,
                            'timestamp': datetime.utcnow().isoformat()
                        }, room=active_connections[msg['sender']])
                        
                if undelivered_messages and undelivered_messages.retrieved > 0:
                    logger.info(f"Delivered {undelivered_messages.retrieved} pending messages to {username}")
                    
            except Exception as e:
                logger.error(f"Error delivering pending messages to {username}: {e}", exc_info=True)
        
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
    """Handle encrypted message sending with offline support"""
    if 'username' not in session:
        emit('error', {'message': 'Not authenticated'})
        return
    
    try:
        sender = session['username']
        recipient = data['recipient']
        message = data['message']
        message_id = secrets.token_urlsafe(16)
        is_recipient_online = recipient in active_connections
        
        # Get recipient's public key
        recipient_public_key = mongo_auth.get_public_key(recipient)
        if not recipient_public_key:
            emit('error', {'message': 'Recipient public key not found'})
            return
        
        # Encrypt the message
        try:
            encrypted_message = CryptoManager.encrypt_message(message, recipient_public_key)
            if not encrypted_message:
                emit('error', {'message': 'Failed to encrypt message'})
                return
        except Exception as e:
            logger.error(f"Encryption error: {e}", exc_info=True)
            emit('error', {'message': 'Failed to encrypt message'})
            return
        
        # Save encrypted message to database with delivery status
        message_doc = {
            'sender': sender,
            'recipient': recipient,
            'encrypted_content': encrypted_message,
            'timestamp': datetime.utcnow(),
            'message_id': message_id,
            'delivered': is_recipient_online  # Mark as delivered if recipient is online
        }
        
        # Save to database
        result = mongo_auth.messages.insert_one(message_doc)
        
        if result.inserted_id:
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
            if is_recipient_online:
                try:
                    socketio.emit('new_message', {
                        'message_id': message_id,
                        'sender': sender,
                        'encrypted_content': encrypted_message,
                        'timestamp': datetime.utcnow().isoformat(),
                        'delivered': True
                    }, room=active_connections[recipient])
                except Exception as e:
                    logger.error(f"Failed to send message to {recipient}: {e}", exc_info=True)
                    # Don't mark as delivered if we couldn't send it
                    mongo_auth.messages.update_one(
                        {'_id': result.inserted_id},
                        {'$set': {'delivered': False}}
                    )
            
            # Send delivery confirmation to sender
            emit('message_status', {
                'message_id': message_id,
                'status': 'delivered' if is_recipient_online else 'sent',
                'recipient': recipient,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # If recipient is offline, queue for delivery when they come online
            if not is_recipient_online:
                logger.info(f"Message {message_id} queued for offline delivery to {recipient}")
            
        else:
            emit('error', {'message': 'Failed to save message'})
            
    except Exception as e:
        logger.error(f"Handle message error: {e}", exc_info=True)
        emit('error', {'message': 'Failed to send message'})

@socketio.on('decrypt_message')
def handle_decrypt_message(data):
    """Handle message decryption request"""
    if 'username' not in session:
        emit('error', {'message': 'Not authenticated'})
        return
    
    try:
        username = session['username']
        
        # Validate request data
        if 'encrypted_content' not in data or 'message_id' not in data:
            logger.error(f"Missing required fields in decrypt_message: {data.keys()}")
            emit('error', {'message': 'Invalid request data'})
            return
            
        encrypted_content = data['encrypted_content']
        message_id = data['message_id']
        
        logger.info(f"Decryption request from {username} for message {message_id[:8]}...")
        
        # Get user's private key
        private_key = mongo_auth.get_private_key(username)
        if not private_key:
            logger.error(f"Private key not found for user {username}")
            emit('error', {'message': 'Private key not found'})
            return
        
        try:
            # Decrypt the message
            decrypted_message = CryptoManager.decrypt_message(encrypted_content, private_key)
            if decrypted_message is not None:
                logger.info(f"Successfully decrypted message {message_id[:8]}... for {username}")
                
                # Send decryption status
                emit('message_decrypted', {
                    'message_id': message_id,
                    'status': 'decrypted',
                    'content': decrypted_message
                })
            else:
                raise Exception("Decryption returned None")
                
        except Exception as e:
            logger.error(f"Failed to decrypt message {message_id[:8]}... for {username}: {str(e)}", exc_info=True)
            emit('decryption_error', {
                'message_id': message_id,
                'status': 'failed',
                'message': 'Failed to decrypt message: ' + str(e)
            })
            
    except KeyError as ke:
        error_msg = f"Missing required field: {ke}"
        logger.error(error_msg)
        emit('error', {'message': error_msg})
    except Exception as e:
        error_msg = f"Unexpected error during decryption: {str(e)}"
        logger.error(error_msg, exc_info=True)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test MongoDB connection
        mongo_auth.client.admin.command('ping')
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'online_users': len(online_users),
            'active_connections': len(active_connections)
        }), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/api/chat/clear', methods=['POST'])
@login_required
def clear_chat():
    try:
        current_user = session.get('username')
        if not current_user:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401
            
        data = request.get_json()
        other_user = data.get('other_user')
        
        if not other_user:
            return jsonify({'success': False, 'message': 'Other user is required'}), 400
            
        # Delete messages in both directions
        result = mongo_auth.messages.delete_many({
            '$or': [
                {'sender': current_user, 'recipient': other_user},
                {'sender': other_user, 'recipient': current_user}
            ]
        })
        
        # Notify both users to clear their chat UI
        socketio.emit('chat_cleared', {
            'from_user': current_user,
            'with_user': other_user
        })
        
        return jsonify({
            'success': True,
            'message': f'Chat with {other_user} has been cleared',
            'deleted_count': result.deleted_count
        })
        
    except Exception as e:
        logger.error(f"Error clearing chat: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to clear chat'}), 500

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file_to_gridfs(file, filename, content_type, metadata=None):
    """Save file to GridFS and return file ID"""
    try:
        file_id = fs.put(
            file,
            filename=filename,
            content_type=content_type,
            metadata=metadata or {}
        )
        return file_id
    except Exception as e:
        logger.error(f"Error saving file to GridFS: {e}", exc_info=True)
        raise

def format_file_size(size_in_bytes):
    """Convert file size in bytes to human-readable format"""
    if not size_in_bytes:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.1f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.1f} TB"

@app.route('/api/files/<file_id>')
@login_required
def download_file(file_id):
    """Serve files from GridFS"""
    try:
        file = fs.get(ObjectId(file_id))
        response = app.response_class(
            file,
            mimetype=file.content_type
        )
        response.headers["Content-Disposition"] = f"attachment; filename={file.filename}"
        return response
    except Exception as e:
        logger.error(f"Error downloading file: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'File not found'}), 404

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file uploads"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400
        
    file = request.files['file']
    recipient = request.form.get('recipient')
    
    if not recipient:
        return jsonify({'success': False, 'message': 'Recipient is required'}), 400
        
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
        
    if not file or not allowed_file(file.filename):
        return jsonify({
            'success': False, 
            'message': 'File type not allowed. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS)
        }), 400
    
    try:
        # Get content type
        # Read file into memory to determine size accurately
        import io
        file_bytes = file.read()
        file_size = len(file_bytes)
        # Reset stream for GridFS
        file_stream = io.BytesIO(file_bytes)
        
        content_type = file.content_type or mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
        
        # Prepare metadata
        metadata = {
            'uploader': session['username'],
            'recipient': recipient,
            'original_filename': file.filename,
            'upload_date': datetime.utcnow()
        }
        
        # Save file to GridFS
        file_id = save_file_to_gridfs(
            file_stream,
            filename=secure_filename(file.filename),
            content_type=content_type,
            metadata=metadata
        )
        
        # Generate download URL
        download_url = url_for('download_file', file_id=str(file_id))
        
        # Prepare file info
        file_info = {
            'file_id': str(file_id),
            'filename': file.filename,
            'size': file_size,
            'content_type': content_type,
            'download_url': download_url
        }
        
        # Save the file message to database
        sender = session['username']
        message_id = secrets.token_urlsafe(16)
        
        # Create a file message that will be encrypted
        file_message = f"📎 {file.filename} ({format_file_size(file_size)}) [FILE]"
        
        # Encrypt the file message with recipient's public key
        recipient_public_key = mongo_auth.get_public_key(recipient)
        if not recipient_public_key:
            return jsonify({'success': False, 'message': 'Recipient public key not found'}), 400
            
        encrypted_message = CryptoManager.encrypt_message(file_message, recipient_public_key)
        if not encrypted_message:
            return jsonify({'success': False, 'message': 'Failed to encrypt file message'}), 500
        
        # Save the encrypted message
        if not mongo_auth.save_message(sender, recipient, encrypted_message, message_id, is_file=True, file_info=file_info):
            return jsonify({'success': False, 'message': 'Failed to save file message'}), 500
        
        # Prepare response
        response_data = {
            'success': True,
            'message_id': message_id,
            'download_url': download_url,
            'file_info': file_info
        }
        
        # If recipient is online, send the file message directly
        if recipient in active_connections:
            socketio.emit('new_file_message', {
                'message_id': message_id,
                'sender': sender,
                'encrypted_content': encrypted_message,
                'file_info': file_info,
                'timestamp': datetime.utcnow().isoformat(),
                'delivered': True
            }, room=active_connections[recipient])
            
            # Mark as delivered
            mongo_auth.mark_message_delivered(message_id)
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Failed to upload file: {str(e)}'
        }), 500

@app.route('/api/users/search', methods=['GET'])
@login_required
def search_users():
    """Search for users by username (case-insensitive partial match)"""
    try:
        query = request.args.get('q', '').strip()
        if not query:
            return jsonify({
                'success': False,
                'message': 'Search query is required'
            }), 400
            
        current_user = session.get('username')
        if not current_user:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401
            
        # Search for users
        results = mongo_auth.search_users(query, current_user)
        
        return jsonify({
            'success': True,
            'users': results
        })
        
    except Exception as e:
        logger.error(f"Error in search_users: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while searching for users'
        }), 500

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
