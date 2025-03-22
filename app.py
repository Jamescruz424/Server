import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://client-xqp2.onrender.com"}})  # Your React URL

# Hardcoded Firebase credentials for inventory-eec69 project
firebase_credentials = {
    "type": "service_account",
    "project_id": "inventory-eec69",
    "private_key_id": "b392ed4c8e7162543fdb9af0f4204f0bbcb73549",
    "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdkvWU+UfQnYFO
PKdMaBjxFB/3NpsnYUQ1qPUHihA5MCvUjNOUufG4dKBFipBxr3mZLHc5AXr+pyJ2
P6uGiVTHT37lyA91QXsKkDGICAHEX66zA0blqialcxj1fj+5taBxpxqWnlgSORwJ
eRML5NDCYCmcalURY0P6mr8mAOBHT3th5/bXrdO1dVrDFxiu++zCX7qxGB0NZb4q
pz4k9GHkzHtURiFPBGUNc5UJ0ls9hTv0VfgBxTfR7FZJOVAbzb36Xe3Dkk9l/APm
3kJAh5t17E7Zzti5INRQNe9tei8kuUActFAdvWJwWSYgFxMP3DJzc3+FgOej6Dn+
PO1d9hwXAgMBAAECggEAMAi+iD09YSDCbCEdNrN89vCVlfy1a1nBO0JX/4Zcz7IZ
il+rl+jfAMW8nbZRtfYx8TmW1m/XGI3GeZmLJiXzDBb1rgJAhBQD+AJgtwEJ2Nz6
GmPjVtt5kHH3p85miqwNTtgLyOJYIqX6IAEihzunT7mUtbPMXtKNxHUr09/sfpAH
rva3FMo1vkhhue9uRYTlZBQ4Y2PJgHjM91dej6gXlbFh+PvFYuw8sMU+ZLvAwxwk
N5C1z3jDkCl70U3oBHQQkAVpDg1w7SmggxsukpeQOIu9pKRmTIRvAKNeM5fDkrpC
t+t1FMzKE+kqN3x/uRPFLX9WU3Lmn2LYHDq7XAbi0QKBgQDJNLH3lBR3ev2RzOb3
U18Ap9FE0IyowinSmMkA9bbn7CIgA63+g7GUdPjLD89fjUm+bvGUiMTAeMNPDaLd
SaP1j/sBknwG1eDwhvGXXPCLT/HklQwAExZXlWdg7GvlZIBhTTTgd6kqLYjZx2iG
+SpnkBNKVPxsxqhq3r+K/Dd3tQKBgQDIfGwsrv2CJtxZk9Z68Rzl1oTEWwuVdBTe
um7pUOGvnSkRF0Rt8+xiR2skD1upxQfoze8E+qxQyqdzzy8ZRX0wirQzkrleY/D5
BP/kjitqDPcu/FXWaD30bN3lrc2WbJLoxxBZyNusODaatYYKB/BssDcgx4dZcQCq
7BgvEIAMGwKBgC1fh76YEyF6h9IoTfF6SJNCROvqx72Kw5mtQK7JumyEkJF9ovAh
TJt44V4Re6dFmlqqdCoVyaDJ2ulp3s9eOu42gNky6ms0MhyrobGLkOcpqRfuEJ23
sDMiCwUNa6t4RYcrvP/dnDVZvWG3GThO2iQullsN3Tq+dd5bywARroR9AoGBAKLW
XE5Wu1UxFxwytawZlm0ftap+gIQdSq41IsyigwxOTAKzsULVMhQJCf658quLewcd
7JtQtxDP6P5pM0oFZM8+eWrCK4l9B0ZbRzRuPNjgOwyQq2+AL4INwpVAe5FIEnK6
7I7gU3woFEHIWlxfYmoFHmGjbk25ON+a73Gap0YtAoGAXgsZFIAtCVKKlMhcASUy
mI6Zfx9AxZ0v1XAeazkHcKugRCLhlImu9KH0DqU7wHNdWQ9jQY/7bY9Q4XJyfM4E
5yf3ir0hVb+LYoxys7grY6QyUaD36pcPtgXC0GYqXhhuFnkoROgIXmS5OCJSwpdk
8tW5RBN4EPpWGOAWXYfPNv4=
-----END PRIVATE KEY-----""",
    "client_email": "firebase-adminsdk-fbsvc@inventory-eec69.iam.gserviceaccount.com",
    "client_id": "105947406222937872714",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40inventory-eec69.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}

cred = credentials.Certificate(firebase_credentials)
firebase_admin.initialize_app(cred)
db = firestore.client()

# Root route for health check
@app.route('/', methods=['GET'])
def home():
    logger.info("Health check hit")
    return jsonify({"message": "Flask server is running"}), 200

# User class (unchanged)
class User:
    def __init__(self, id, name, email, local_id, dept, password_hash, role='user'):
        self.id = id
        self.name = name
        self.email = email
        self.local_id = local_id
        self.dept = dept
        self.password_hash = password_hash
        self.role = role

    def to_dict(self):
        return {
            'name': self.name,
            'email': self.email,
            'local_id': self.local_id,
            'dept': self.dept,
            'password_hash': self.password_hash,
            'role': self.role
        }

    @staticmethod
    def from_dict(doc_id, data):
        return User(
            id=doc_id,
            name=data['name'],
            email=data['email'],
            local_id=data['local_id'],
            dept=data['dept'],
            password_hash=data['password_hash'],
            role=data.get('role', 'user')
        )

def check_existing_user(email, local_id):
    logger.debug(f"Checking existing user with email: {email}, local_id: {local_id}")
    email_query = db.collection('users').where('email', '==', email).limit(1).stream()
    for doc in email_query:
        return doc.id
    local_id_query = db.collection('users').where('local_id', '==', local_id).limit(1).stream()
    for doc in local_id_query:
        return doc.id
    return None

# Inventory class (unchanged)
class InventoryItem:
    def __init__(self, id, name, category, sku, quantity, unit_price, image_url=None):
        self.id = id
        self.name = name
        self.category = category
        self.sku = sku
        self.quantity = quantity
        self.unit_price = unit_price
        self.image_url = image_url

    def to_dict(self):
        return {
            'name': self.name,
            'category': self.category,
            'sku': self.sku,
            'quantity': self.quantity,
            'unit_price': self.unit_price,
            'image_url': self.image_url if self.image_url else None
        }

    @staticmethod
    def from_dict(doc_id, data):
        return InventoryItem(
            id=doc_id,
            name=data['name'],
            category=data['category'],
            sku=data['sku'],
            quantity=data['quantity'],
            unit_price=data['unit_price'],
            image_url=data.get('image_url', None)
        )

def check_existing_sku(sku, exclude_id=None):
    logger.debug(f"Checking existing SKU: {sku}")
    query = db.collection('inventory').where('sku', '==', sku).stream()
    for doc in query:
        if exclude_id is None or doc.id != exclude_id:
            return doc.id
    return None

# Register endpoint (with optional Firebase Auth integration)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    logger.debug(f"Received registration request: {data}")
    name = data.get('name')
    email = data.get('email')
    local_id = data.get('id')
    dept = data.get('dept')
    password = data.get('password')
    role = data.get('role', 'user')

    if not all([name, email, local_id, dept, password]):
        logger.error("Missing fields in registration data")
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    existing_user_id = check_existing_user(email, local_id)
    if existing_user_id:
        logger.error(f"User already exists with email: {email} or local_id: {local_id}")
        return jsonify({'success': False, 'message': 'Email or ID already exists'}), 400

    if role not in ['user', 'admin']:
        logger.error(f"Invalid role: {role}")
        return jsonify({'success': False, 'message': 'Invalid role'}), 400

    # Optional: Create user in Firebase Authentication
    try:
        user = auth.create_user(email=email, password=password)
        logger.info(f"Firebase Auth user created: {user.uid}")
    except Exception as e:
        logger.error(f"Firebase Auth error: {str(e)}")
        # Continue even if Firebase Auth fails, since you're using Firestore

    hashed_password = generate_password_hash(password)
    new_user = User(None, name, email, local_id, dept, hashed_password, role)

    user_ref = db.collection('users').document()
    new_user.id = user_ref.id
    user_ref.set(new_user.to_dict())
    logger.info(f"User registered in Firestore: {new_user.id}")

    return jsonify({'success': True, 'message': 'User registered successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    logger.debug(f"Received login request: {data}")
    role = data.get('role')
    email = data.get('email')
    password = data.get('password')

    if not all([role, email, password]):
        logger.error("Missing fields in login data")
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    if role not in ['user', 'admin']:
        logger.error(f"Invalid role: {role}")
        return jsonify({'success': False, 'message': 'Invalid role selected'}), 400

    users_ref = db.collection('users').where('email', '==', email).limit(1).stream()
    user = None
    for doc in users_ref:
        user = User.from_dict(doc.id, doc.to_dict())
        break

    if user and check_password_hash(user.password_hash, password):
        if user.role != role:
            logger.error(f"Role mismatch: expected {role}, got {user.role}")
            return jsonify({'success': False, 'message': 'Role does not match'}), 400
        logger.info(f"Login successful for {email}")
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'role': user.role,
            'user': {'name': user.name, 'email': user.email, 'id': user.local_id, 'dept': user.dept}
        }), 200
    else:
        logger.error(f"Invalid credentials for {email}")
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

# Remaining endpoints (unchanged)
@app.route('/inventory', methods=['GET'])
def get_inventory():
    inventory_ref = db.collection('inventory').stream()
    items = [InventoryItem.from_dict(doc.id, doc.to_dict()) for doc in inventory_ref]
    return jsonify({
        'success': True,
        'items': [{'id': item.id, 'name': item.name, 'category': item.category, 'sku': item.sku, 'quantity': item.quantity, 'unit_price': item.unit_price, 'image_url': item.image_url} for item in items]
    }), 200

@app.route('/inventory', methods=['POST'])
def add_inventory():
    try:
        logger.debug("Received POST request to /inventory")
        data = request.json
        name = data.get('name')
        category = data.get('category')
        sku = data.get('sku')
        quantity = data.get('quantity')
        unit_price = data.get('unit_price')
        image_url = data.get('image_url')

        logger.debug(f"Form data: name={name}, category={category}, sku={sku}, quantity={quantity}, unit_price={unit_price}, image_url={image_url}")

        if not all([name, category, sku, quantity, unit_price]):
            logger.error("Missing fields in form data")
            return jsonify({'success': False, 'message': 'Missing fields'}), 400

        if check_existing_sku(sku):
            logger.error(f"SKU {sku} already exists")
            return jsonify({'success': False, 'message': 'SKU already exists'}), 400

        try:
            quantity = int(quantity)
            unit_price = float(unit_price)
        except ValueError as e:
            logger.error(f"Invalid quantity or unit_price: {str(e)}")
            return jsonify({'success': False, 'message': 'Invalid quantity or unit price'}), 400

        new_item = InventoryItem(None, name, category, sku, quantity, unit_price, image_url)
        item_ref = db.collection('inventory').document()
        new_item.id = item_ref.id
        item_ref.set(new_item.to_dict())
        logger.debug(f"Item saved to Firestore with ID: {new_item.id}")

        return jsonify({'success': True, 'message': 'Item added successfully', 'id': new_item.id}), 201
    except Exception as e:
        logger.exception("Error in add_inventory: %s", str(e))
        return jsonify({'success': False, 'message': f'Internal server error: {str(e)}'}), 500

# Add other endpoints (update_inventory, delete_inventory, requests, dashboard) here as in your original code...

if __name__ == '__main__':
    port = int(os.getenv("PORT", 10000))  # Use Render's PORT
    app.run(host="0.0.0.0", port=port)
