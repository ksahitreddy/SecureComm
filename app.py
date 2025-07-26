#!/usr/bin/env python3
"""
Secure Chat Application with RSA Encryption
Builds on the existing Flask authentication system
Fixed: JSON serialization error with MongoDB ObjectId
"""

import eventlet
eventlet.monkey_patch()

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
from flask_mail import Mail, Message
import requests
from transformers import AutoTokenizer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3WUC1FCsePbuQf/9lRrhPmKbebzuxgLe4Or6we2NZGxsnFYBECnZzv2ZNRglZsHh49odqHWQjQ0mnUvUfhr6FJY6j2h23wpwqGJ1/PT6svDE5ZhfmPBNE4rnnL9f1xLe5hNyfI3JxjM+XhNhav0qClyoNm0NwND3gVeY+wdwRRfHNOsU8l3w4vvQxw4ooSRPpv//mPNnjXAchMjKkhB4O7dtwVsEw8brzQQ6S/gx5d/c/PXEXJ5kyIv797Rqbe8MC5hr22dWeh93VG80DmPCP9Pe9We+Anc299qXSric0Mw82A6wG6Rfi7mbT2zEaByPFe4wBzyn6hQQMfmw3Ws+9AgMBAAECggEAPSrhk4eu+t/Ne1+4bKkzRBrBUOP7HjS7FhNDGs2PT2LjpB5gNFLpQaRRFOaQqANfrbtRYe18Qudn4xKiBGqHlRP6il9yGqQqRUEBCjn8dtQx99w/jOft5cVeD+q+OZfvU00n7U9+FrPLbdk79MpsqTSVKwTpcr17ByShM76pFHmW2o3AFb2euvQdagnQBcipYpjHge2APXQCMl3PtTy5yEzAinFDbw8JkYVzzq99YuIV+g4R3uIQG7hAAtxRBgVCvmFrQZKOphAXC9YhBUaVMbTxR/+Ufxfe22SVyOH4+9JkZj1xEMfPJdujlqVOaYXeHImp2eQlgzfEnGXI117mYQKBgQC47fUvnLZl+hKQdM0i5wk9a/gb3+Mo2ewOhceycpR9K1JlfktY/FLMKS7za3mUQfrVA0+Iw9L6C+SEfZ2YV7NSuJhnIToJE4MRvg7HRmC5/ZzlaQZfYDALcRUlQg+1hHC3obCzA/f+VAMc7glaXGMP65ILWGQS5kLvkmzQJXZCfwKBgQD9z8MqPOWf1tqQiLQnkGR4+HaPgLfl7QFx1cW2BQQnVx6WvUmI/HvMl+AGH7RJipSKiLD54KHpRK6+wAyVQJ5HOF0jjDZq7oLRMieRXHaRhZR0KBqnF2Ki4faQbL8E9ijQf/nmlE6tTZk3gvzGLMbtUx+ppcnkIU9iFJie0dNXwwKBgAPHQNovLn7Y5CY1bLeI1uR9Xz1ajq6X/T2yuAjKVIRWLUHLmciAp0Rqlv38NSi1TGWrwqU9swLO2WVnl5+0MwK+qMZ6pE/pKSVkp7KkmndSWjFJuwqZ0YF6Vv9C4UVJJnBqCk0uCJQWrVWa+2/wMUny+zHmJW1JbRat/DEogskLAoGAIRvKBKd++LPJPRNoFMUkJhebN6r90jNxfcz6Bn1vBka6CcXVYtY0vAKPyZy3IuS97bhZBa+Ez24TMXTR72JHg1jZ5Xoz2w0T6YAWY0LhgKghLmnQ2D0Xs9GwHTTiUh5eQpx/F9H+1WKK+w/OM3fB11GBjtq+lFC4Dz5KjmUmoYsCgYEAnEtKtkg80hOs2CcrNm83J+OeYw/3K/ijhcCDqPZ0r4r98mzXEmCkcCXl0gWNzyGcbTAgv+zDUyygNOlDoW9DeqkIZ8JKME+nWAfmYOm7lDj89Q1/ThjcHSCI7eDnd1bqwUlSjaw1EhtfuvZn4PfWQmGMI9O1bDbBP0fn3Kx4KQs=')


# File upload configuration
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', }
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 10MB max file size
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Initialize SocketIO with CORS support
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# ---------------- Mail configuration ----------------
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'iliketrainshm59@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'jwsm rlev xbqs iywp')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'iliketrainshm59@gmail.com')

mail = Mail(app)

# ---------------- AI Configuration ----------------
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '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')
GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions'
GROQ_MODEL = 'meta-llama/llama-4-scout-17b-16e-instruct'
AI_SYSTEM_PROMPT = """You are SecureAI, an intelligent assistant integrated into SecureComm chat application. You help users with questions and provide information. Be helpful, concise, and friendly. When asked for code, you will always start with @.<correct extension of the type of code> and then the code"""
MAX_CONTEXT_TOKENS = 8192

# Initialize tokenizer for AI (disabled for now to avoid startup issues)
ai_tokenizer = None
logger.info('AI tokenizer disabled - using simple token counting')

# MongoDB Configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb+srv://admins:4postr0phe@stock.sxr4y.mongodb.net/securecomm_db?retryWrites=true&w=majority&appName=Stock')
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

# ---------------- AI Helper Functions ----------------
class AIManager:
    @staticmethod
    def count_tokens(messages):
        """Count tokens in messages using tokenizer"""
        if not ai_tokenizer:
            # Fallback: rough estimation
            combined = ''.join([f"{m['role']}: {m['content']}\n" for m in messages])
            return len(combined) // 4  # Rough token estimation
        
        combined = ''.join([f"{m['role']}: {m['content']}\n" for m in messages])
        return len(ai_tokenizer.encode(combined))
    
    @staticmethod
    def query_ai(prompt, history=None):
        """Query Groq AI with prompt and optional history"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {GROQ_API_KEY}'
            }
            
            messages = [{'role': 'system', 'content': AI_SYSTEM_PROMPT}]
            
            # Add history if provided
            if history:
                for msg in reversed(history[-10:]):  # Last 10 messages
                    if AIManager.count_tokens(messages + [msg, {'role': 'user', 'content': prompt}]) < MAX_CONTEXT_TOKENS:
                        messages.insert(1, msg)
                    else:
                        break
            
            # Truncate prompt if too long
            if ai_tokenizer:
                prompt_tokens = ai_tokenizer.encode(prompt)
                if len(prompt_tokens) > MAX_CONTEXT_TOKENS:
                    prompt_tokens = prompt_tokens[:MAX_CONTEXT_TOKENS]
                    prompt = ai_tokenizer.decode(prompt_tokens)
            
            messages.append({'role': 'user', 'content': prompt})
            
            payload = {
                'model': GROQ_MODEL,
                'messages': messages,
                'max_tokens': 6000,
                'temperature': 0.4,
                'stream': False
            }
            
            response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            
            return response.json()['choices'][0]['message']['content']
            
        except requests.exceptions.RequestException as e:
            logger.error(f'AI API request failed: {e}')
            return f'🚨 AI service temporarily unavailable: {str(e)}'
        except Exception as e:
            logger.error(f'AI query error: {e}', exc_info=True)
            return f'🚨 AI error: {str(e)}'
    
    @staticmethod
    def is_ai_message(message):
        """Check if message is an AI command"""
        return message.strip().startswith('@SecureAI ')
    
    @staticmethod
    def extract_ai_prompt(message):
        """Extract prompt from AI message"""
        if AIManager.is_ai_message(message):
            return message.strip()[10:].strip()  # Remove '@SecureAI '
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
    
    def save_message(self, sender, recipient, encrypted_content, message_id, is_file=False, file_info=None, enc_for_sender=None):
        """Save encrypted message with copies for both recipient and sender"""
        try:
            # Determine appropriate encrypted fields
            encrypted_for_recipient = encrypted_content
            encrypted_for_sender = enc_for_sender

            message = {
                '_id': message_id,
                'message_id': message_id,
                'sender': sender,
                'recipient': recipient,
                'encrypted_for_recipient': encrypted_for_recipient,
                'encrypted_for_sender': encrypted_for_sender,
                'timestamp': datetime.utcnow(),
                'delivered': False,
                'read': False,
                'is_file': is_file,
                'file_info': file_info if is_file else None
            }
            # For backward compatibility with existing clients/records
            message['encrypted_content'] = encrypted_for_recipient
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
                {"$and": [{"sender": user2}, {"recipient": user1}]},
                {"$and": [{"sender": "SecureAI"}, {"$or": [{"recipient": user1}, {"recipient": user2}]}]}
            ]
        }
        
        logger.info(f'Getting messages between {user1} and {user2} with query: {query}')
        
        messages = list(self.messages
                        .find(query)
                        .sort("timestamp", -1)
                        .limit(limit))
        
        logger.info(f'Found {len(messages)} messages in database')
        
        # Process messages to include appropriate encrypted content for the requesting user
        processed_messages = []
        for msg in messages:
            processed_msg = msg.copy()
            
            # Handle AI messages (stored as plaintext)
            if msg.get('is_ai_response') or msg.get('is_ai_prompt'):
                # AI messages are stored as plaintext, no decryption needed
                processed_msg['encrypted_content'] = msg.get('encrypted_for_sender', msg.get('encrypted_content', ''))
                processed_msg['is_plaintext'] = True
                if msg.get('is_ai_response'):
                    processed_msg['is_ai_response'] = True
                if msg.get('is_ai_prompt'):
                    processed_msg['is_ai_prompt'] = True
            else:
                # Regular encrypted messages
                # Determine which encrypted content to use based on who is requesting
                if msg['sender'] == user1:
                    # user1 sent this message, so they need the sender version
                    processed_msg['encrypted_content'] = msg.get('encrypted_for_sender', msg.get('encrypted_content', ''))
                else:
                    # user1 received this message, so they need the recipient version
                    processed_msg['encrypted_content'] = msg.get('encrypted_for_recipient', msg.get('encrypted_content', ''))
            
            # Remove the separate encrypted fields to avoid confusion
            processed_msg.pop('encrypted_for_sender', None)
            processed_msg.pop('encrypted_for_recipient', None)
            
            processed_messages.append(processed_msg)
        
        # Convert ObjectId to string for JSON serialization
        result = self._serialize_documents(processed_messages)
        logger.info(f'Returning {len(result)} processed messages to frontend')
        return result
        
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

# Store WebRTC peer connections and call data
call_rooms = {}
peer_connections = {}

# ICE Servers configuration (you may want to use your own STUN/TURN servers in production)
ICE_SERVERS = [
    {'urls': 'stun:stun.l.google.com:19302'},
    {'urls': 'stun:stun1.l.google.com:19302'},
    {'urls': 'stun:stun2.l.google.com:19302'}
]

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

@app.route('/api/keys', methods=['GET'])
@login_required
def get_user_keys():
    """Get current user's encryption keys"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
        
    username = session['username']
    
    try:
        # Get both public and private keys
        public_key = mongo_auth.get_public_key(username)
        private_key = mongo_auth.get_private_key(username)
        
        if not public_key or not private_key:
            return jsonify({'success': False, 'message': 'Keys not found'}), 404
            
        return jsonify({
            'success': True,
            'public_key': public_key,
            'private_key': private_key
        })
        
    except Exception as e:
        logger.error(f"Error fetching user keys: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to fetch keys'}), 500

# ------------------------------
# Invite friend endpoint
# ------------------------------
@app.route('/api/invite', methods=['POST'])
@login_required
def invite_friend():
    """Send invitation email to provided address"""
    data = request.get_json(silent=True) or {}
    recipient_email = data.get('email')
    if not recipient_email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    try:
        invite_link = f"{request.host_url.rstrip('/')}/register"
        html_body = f"""
        <p>Hello!</p>
        <p>You have been invited to join SecureComm.</p>
        <p><a href='{invite_link}'>Click here to register</a></p>
        <p>Welcome aboard!<br>Sahit and Hemanth</p>
        """
        plain_text_body = (
            "Hello!\n\nYou have been invited to join SecureComm.\n\n"
            f"Please register at {invite_link}\n\nWelcome aboard!\n\nSahit and Hemanth"
        )
        msg = Message(subject='Join me on SecureComm', recipients=[recipient_email], body=plain_text_body, html=html_body)
        mail.send(msg)
        return jsonify({'success': True, 'message': f'Email sent to {recipient_email}'})
    except Exception as e:
        logger.error(f'Error sending invite email: {e}', exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to send email'}), 500

# ------------------------------
# Dashboard stats endpoint
# ------------------------------
@app.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    """Return total messages and contacts counts for current user"""
    try:
        username = session['username']

        # Total messages involving current user
        total_messages = _db['messages'].count_documents({
            '$or': [
                {'sender': username},
                {'recipient': username}
            ]
        })

        # Distinct contacts user has chatted with
        contacts_cursor = _db['messages'].aggregate([
            {'$match': {
                '$or': [
                    {'sender': username},
                    {'recipient': username}
                ]
            }},
            {'$project': {
                'contact': {
                    '$cond': [
                        {'$eq': ['$sender', username]},
                        '$recipient',
                        '$sender'
                    ]
                }
            }},
            {'$group': {'_id': '$contact'}}
        ])

        total_contacts = len(list(contacts_cursor))

        return jsonify({
            'success': True,
            'total_messages': total_messages,
            'total_contacts': total_contacts
        })

    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to load stats'}), 500


@app.route('/api/validate-encryption', methods=['POST'])
@login_required
def validate_encryption():
    """
    Validate that a message can be decrypted by the intended recipient.
    This is a test endpoint to verify the encryption/decryption flow.
    """
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
        
    data = request.get_json()
    if not data or 'recipient' not in data or 'message' not in data:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
    sender = session['username']
    recipient = data['recipient']
    test_message = data['message']
    
    try:
        # 1. Get recipient's public key
        recipient_public_key = mongo_auth.get_public_key(recipient)
        if not recipient_public_key:
            return jsonify({
                'success': False,
                'message': 'Recipient public key not found'
            }), 404
            
        # 2. Encrypt the message with recipient's public key
        encrypted_message = CryptoManager.encrypt_message(test_message, recipient_public_key)
        if not encrypted_message:
            return jsonify({
                'success': False,
                'message': 'Failed to encrypt message'
            }), 500
            
        # 3. Get recipient's private key (for validation)
        recipient_private_key = mongo_auth.get_private_key(recipient)
        if not recipient_private_key:
            return jsonify({
                'success': False,
                'message': 'Recipient private key not found (for validation)'
            }), 500
        
        # 4. Decrypt the message with recipient's private key
        decrypted_message = CryptoManager.decrypt_message(encrypted_message, recipient_private_key)
        
        # 5. Compare original and decrypted messages
        is_valid = decrypted_message == test_message
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'original_message': test_message,
            'encrypted_message': encrypted_message,
            'decrypted_message': decrypted_message,
            'validation_passed': is_valid,
            'validation_details': {
                'encrypted_with': f"{recipient}'s public key",
                'decrypted_with': f"{recipient}'s private key"
            }
        })
        
    except Exception as e:
        logger.error(f"Encryption validation error: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Validation failed: {str(e)}',
            'validation_passed': False
        }), 500


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
    logger.info(f'Chat route: Got {len(messages)} messages for template')
    
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
    username = None
    for user, sid in active_connections.items():
        if sid == request.sid:
            username = user
            break
            
    if username:
        # Clean up any active calls
        if username in call_rooms:
            room = call_rooms[username]
            if 'caller' in room and room['caller'] == username:
                # If the caller disconnects, notify the callee
                if 'callee' in room and room['callee'] in active_connections:
                    emit('call_ended', {
                        'reason': 'caller_disconnected',
                        'caller': username,
                        'callee': room['callee']
                    }, room=active_connections[room['callee']])
            elif 'callee' in room and room['callee'] == username:
                # If the callee disconnects, notify the caller
                if 'caller' in room and room['caller'] in active_connections:
                    emit('call_ended', {
                        'reason': 'callee_disconnected',
                        'caller': room['caller'],
                        'callee': username
                    }, room=active_connections[room['caller']])
            
            # Clean up the call room
            if 'caller' in room and room['caller'] in call_rooms:
                call_rooms.pop(room['caller'], None)
            if 'callee' in room and room['callee'] in call_rooms:
                call_rooms.pop(room['callee'], None)
        
        # Remove from active connections
        active_connections.pop(username, None)
        
        # Update online status if this was the last session
        if username not in active_connections:
            online_users.discard(username)
            mongo_auth.set_user_offline(username)
            
            # Notify other users
            emit('user_status', {
                'username': username,
                'status': 'offline',
                'timestamp': datetime.utcnow().isoformat()
            }, broadcast=True, include_self=False)
            
            logger.info(f"User {username} disconnected")
    else:
        logger.warning(f"Unknown session disconnected: {request.sid}")

def handle_ai_message(sender, recipient, message, message_id):
    """Handle AI message requests"""
    try:
        # Extract the AI prompt
        prompt = AIManager.extract_ai_prompt(message)
        if not prompt:
            emit('error', {'message': 'Invalid AI command'})
            return
        
        # Get recent chat history for context (optional)
        try:
            recent_messages = mongo_auth.get_messages(sender, recipient, limit=10)
            history = []
            for msg in recent_messages:
                if msg.get('sender') == sender:
                    history.append({'role': 'user', 'content': msg.get('decrypted_content', '')})
                else:
                    history.append({'role': 'assistant', 'content': msg.get('decrypted_content', '')})
        except Exception as e:
            logger.warning(f'Could not get chat history for AI context: {e}')
            history = None
        
        # Store the AI prompt message for both users
        prompt_message_doc = {
            'sender': sender,
            'recipient': recipient,
            'encrypted_for_sender': message,  # Store as plaintext for AI prompts
            'encrypted_for_recipient': message,  # Store as plaintext for AI prompts
            'timestamp': datetime.utcnow(),
            'message_id': message_id,
            'delivered': True,
            'is_ai_prompt': True
        }
        
        # Save AI prompt to database
        mongo_auth.messages.insert_one(prompt_message_doc)
        
        # Send AI prompt to both users
        sender_sid = active_connections.get(sender)
        recipient_sid = active_connections.get(recipient)
        
        prompt_data = {
            'message_id': message_id,
            'sender': sender,
            'content': message,
            'timestamp': datetime.utcnow().isoformat(),
            'delivered': True,
            'is_plaintext': True,
            'is_ai_prompt': True
        }
        
        # Send to sender
        if sender_sid:
            socketio.emit('new_message', prompt_data, room=sender_sid)
        
        # Send to recipient if online
        if recipient_sid:
            socketio.emit('new_message', prompt_data, room=recipient_sid)
        
        # Send typing indicator to both users
        typing_data = {
            'message_id': message_id,
            'sender': 'SecureAI',
            'recipient': sender
        }
        
        # Send to sender
        if sender_sid:
            socketio.emit('ai_typing', typing_data, room=sender_sid)
        
        # Send to recipient if online
        if recipient_sid:
            socketio.emit('ai_typing', typing_data, room=recipient_sid)
        
        # Query AI in background
        def query_ai_async():
            try:
                ai_response = AIManager.query_ai(prompt, history)
                
                # Create AI response message
                ai_message_id = secrets.token_urlsafe(16)
                
                # Store AI message as plaintext (no encryption needed for AI responses)
                # Store AI response for both users in the conversation
                ai_message_doc = {
                    'sender': 'SecureAI',
                    'recipient': recipient,  # Store with original recipient
                    'encrypted_for_sender': ai_response,  # Store as plaintext
                    'encrypted_for_recipient': ai_response,  # Store as plaintext
                    'timestamp': datetime.utcnow(),
                    'message_id': ai_message_id,
                    'delivered': True,
                    'is_ai_response': True
                }
                
                # Save to database
                mongo_auth.messages.insert_one(ai_message_doc)
                
                # Send AI response to both users in the chat
                sender_sid = active_connections.get(sender)
                recipient_sid = active_connections.get(recipient)
                
                ai_response_data = {
                    'message_id': ai_message_id,
                    'sender': 'SecureAI',
                    'content': ai_response,
                    'timestamp': datetime.utcnow().isoformat(),
                    'original_prompt': prompt
                }
                
                # Send to sender
                if sender_sid:
                    socketio.emit('ai_response', ai_response_data, room=sender_sid)
                    logger.info(f'AI response sent to {sender} (sid: {sender_sid})')
                
                # Send to recipient if online
                if recipient_sid:
                    socketio.emit('ai_response', ai_response_data, room=recipient_sid)
                    logger.info(f'AI response sent to {recipient} (sid: {recipient_sid})')
                
                if not sender_sid and not recipient_sid:
                    logger.warning(f'Neither {sender} nor {recipient} found in active connections for AI response')
                
                logger.info(f'AI response sent to {sender} for prompt: {prompt[:50]}...')
                
            except Exception as e:
                logger.error(f'AI async query error: {e}', exc_info=True)
                sender_sid = active_connections.get(sender)
                if sender_sid:
                    socketio.emit('ai_error', {
                        'message_id': message_id,
                        'error': str(e)
                    }, room=sender_sid)
                else:
                    logger.warning(f'User {sender} not found in active connections for AI error')
        
        # Run AI query in background thread
        socketio.start_background_task(query_ai_async)
        
        # Send confirmation that AI request was received
        emit('ai_request_received', {
            'message_id': message_id,
            'prompt': prompt,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f'Handle AI message error: {e}', exc_info=True)
        emit('error', {'message': 'Failed to process AI request'})

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
        
        # Check if this is an AI message
        logger.info(f'Checking message from {sender}: "{message}"')
        if AIManager.is_ai_message(message):
            logger.info(f'AI message detected from {sender}: {message}')
            handle_ai_message(sender, recipient, message, message_id)
            return
        
        # Get both sender's and recipient's public keys
        recipient_public_key = mongo_auth.get_public_key(recipient)
        sender_public_key = mongo_auth.get_public_key(sender)
        
        if not recipient_public_key:
            emit('error', {'message': 'Recipient public key not found'})
            return
        if not sender_public_key:
            emit('error', {'message': 'Sender public key not found'})
            return
        
        # Encrypt the message for both sender and recipient
        try:
            encrypted_for_recipient = CryptoManager.encrypt_message(message, recipient_public_key)
            encrypted_for_sender = CryptoManager.encrypt_message(message, sender_public_key)
            
            if not encrypted_for_recipient or not encrypted_for_sender:
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
            'encrypted_for_sender': encrypted_for_sender,
            'encrypted_for_recipient': encrypted_for_recipient,
            'timestamp': datetime.utcnow(),
            'message_id': message_id,
            'delivered': is_recipient_online  # Mark as delivered if recipient is online
        }
        
        # Save to database
        result = mongo_auth.messages.insert_one(message_doc)
        logger.info(f'Message saved to database with ID: {result.inserted_id}')
        
        if result.inserted_id:
            # Send encryption status to sender
            emit('encryption_status', {
                'message_id': message_id,
                'status': 'encrypted',
                'recipient': recipient,
                'original_length': len(message),
                'encrypted_length': len(encrypted_for_recipient),
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Send encrypted message to recipient if online
            if is_recipient_online:
                try:
                    socketio.emit('new_message', {
                        'message_id': message_id,
                        'sender': sender,
                        'encrypted_content': encrypted_for_recipient,
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
        
        # Encrypt the file message for both sender and recipient
        recipient_public_key = mongo_auth.get_public_key(recipient)
        sender_public_key = mongo_auth.get_public_key(sender)
        
        if not recipient_public_key:
            return jsonify({'success': False, 'message': 'Recipient public key not found'}), 400
        if not sender_public_key:
            return jsonify({'success': False, 'message': 'Sender public key not found'}), 400
            
        encrypted_for_recipient = CryptoManager.encrypt_message(file_message, recipient_public_key)
        encrypted_for_sender = CryptoManager.encrypt_message(file_message, sender_public_key)
        
        if not encrypted_for_recipient or not encrypted_for_sender:
            return jsonify({'success': False, 'message': 'Failed to encrypt file message'}), 500
        
        # Save the encrypted message
        if not mongo_auth.save_message(sender, recipient, encrypted_for_recipient, message_id, is_file=True, file_info=file_info, enc_for_sender=encrypted_for_sender):
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

# WebRTC Signaling Events
@socketio.on('start_call')
def handle_start_call(data):
    """Handle call initiation"""
    caller = data.get('from')
    callee = data.get('to')
    call_type = data.get('type', 'video')  # 'video' or 'voice'
    
    if not caller or not callee:
        return
    
    # Create a call room
    call_rooms[caller] = {
        'caller': caller,
        'callee': callee,
        'type': call_type,
        'status': 'calling'
    }
    call_rooms[callee] = call_rooms[caller]  # Both users point to the same room
    
    # Notify the callee
    if callee in active_connections:
        emit('incoming_call', {
            'from': caller,
            'type': call_type,
            'caller_username': caller,
            'caller_avatar': url_for('static', filename=f'uploads/avatars/{caller}.jpg')
        }, room=active_connections[callee])

@socketio.on('accept_call')
def handle_accept_call(data):
    """Handle call acceptance"""
    caller = data.get('caller')
    callee = data.get('callee')
    
    if caller in call_rooms and callee in call_rooms:
        call_rooms[caller]['status'] = 'in-progress'
        call_rooms[callee]['status'] = 'in-progress'
        
        # Notify the caller that the call was accepted
        if caller in active_connections:
            emit('call_accepted', {
                'callee': callee
            }, room=active_connections[caller])

@socketio.on('reject_call')
def handle_reject_call(data):
    """Handle call rejection"""
    caller = data.get('caller')
    callee = data.get('callee')
    reason = data.get('reason', 'declined')
    
    # Notify the caller that the call was rejected
    if caller in active_connections:
        emit('call_rejected', {
            'callee': callee,
            'reason': reason
        }, room=active_connections[caller])
    
    # Clean up
    if caller in call_rooms:
        call_rooms.pop(caller, None)
    if callee in call_rooms:
        call_rooms.pop(callee, None)

@socketio.on('end_call')
def handle_end_call(data):
    """Handle call termination with proper cleanup and notifications"""
    try:
        caller = data.get('caller')
        callee = data.get('callee')
        reason = data.get('reason', 'Call ended')
        
        if not caller or not callee:
            logger.error(f'Missing caller or callee in end_call: {data}')
            return
            
        logger.info(f'Ending call between {caller} and {callee}. Reason: {reason}')
        
        # Find all rooms that involve either the caller or callee
        rooms_to_clean = set()
        for username, room in call_rooms.items():
            if username in [caller, callee] or room.get('caller') in [caller, callee] or room.get('callee') in [caller, callee]:
                rooms_to_clean.add(username)
        
        # Notify both parties and clean up
        notified = set()
        for username in rooms_to_clean:
            room = call_rooms.get(username)
            if not room:
                continue
                
            other_party = room.get('callee') if room.get('caller') == username else room.get('caller')
            
            # Notify the other party if they're still connected and not already notified
            if other_party and other_party not in notified and other_party in active_connections:
                emit('call_ended', {
                    'reason': reason,
                    'caller': caller,
                    'callee': callee,
                    'ended_by': caller if caller != other_party else callee,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=active_connections[other_party])
                logger.info(f'Notified {other_party} that call was ended by {caller}')
                notified.add(other_party)
            
            # Clean up the room
            call_rooms.pop(username, None)
        
        # If we didn't find rooms but have active users, still notify
        if not rooms_to_clean:
            for user in [caller, callee]:
                if user in active_connections and user not in notified:
                    emit('call_ended', {
                        'reason': reason,
                        'caller': caller,
                        'callee': callee,
                        'ended_by': caller if caller != user else callee,
                        'timestamp': datetime.utcnow().isoformat()
                    }, room=active_connections[user])
                    logger.info(f'Notified {user} that call was ended (no room found)')
                    
    except Exception as e:
        logger.error(f'Error in handle_end_call: {str(e)}', exc_info=True)
        # Try to notify both parties of the error
        for user in [caller, callee]:
            if user and user in active_connections:
                emit('call_ended', {
                    'reason': 'An error occurred',
                    'caller': caller,
                    'callee': callee,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=active_connections[user])

# WebRTC signaling
@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    """Forward WebRTC offer to the callee"""
    target = data.get('target')
    if target in active_connections:
        emit('webrtc_offer', {
            'sdp': data.get('sdp'),
            'caller': data.get('caller'),
            'callee': data.get('callee'),
            'type': data.get('type')
        }, room=active_connections[target])

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    """Forward WebRTC answer to the caller"""
    target = data.get('target')
    if target in active_connections:
        emit('webrtc_answer', {
            'sdp': data.get('sdp'),
            'caller': data.get('caller'),
            'callee': data.get('callee')
        }, room=active_connections[target])

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    """Forward ICE candidate to the other peer"""
    target = data.get('target')
    if target in active_connections:
        emit('ice_candidate', {
            'candidate': data.get('candidate'),
            'caller': data.get('caller'),
            'callee': data.get('callee')
        }, room=active_connections[target])

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
