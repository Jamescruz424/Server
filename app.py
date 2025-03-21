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
CORS(app, resources={r"/*": {"origins": "https://client-xqp2.onrender.com"}})  # Your React URL

# Hardcoded Firebase credentials (for testing only - replace with env vars in production)
firebase_credentials = {
    "type": "service_account",
    "project_id": "esplorado-c5207",
    "private_key_id": "0d542af3495b91042a219b553a1e501623f94763",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCoXzhHKyIom/qH\nwJGnws5PZdX3b5N05N2vsnN6JBLogX/uhV8B3hq379tBvx7OA9EIL34mlQTjX4Oq\nvNpARqKgFmXPql+W8xqsjniDdftZaZfV1Sgc7FT/2ODgI7RGiPpHvk4BA5dLRZz4\nummGwh8Tze4r9Z3j9lVzMmiI+eqrMppO3lV1Q4Y9LTD4GlIwWeEGBstnE11/gzvm\nTnGZG2xh/33SNlTCwAxrHD85PACAuosZx2AfxIJCxtCXUA+yNJTjXqLTw53o/Rgy\nH0a0rsjNrbqlTiUFlqcnp6KeTHlI0Gynum2IhoCsoTF5b/zc8H1WjLk3SvNb3n/3\nw4eOzUEDAgMBAAECggEANZy8Ss0NP2kLSRakSorZLqb6jqNUjLAjdsKXypiZ/Lbf\niY+mRO34DAGwCytUH71PXg/hV1+0AsJzJnaj+DuFpPv8xzc04Nff8nobHaD/u+TH\nmCsbbrpCBoWEdVppGNyc9SM/q0r9bdZouTqCR4qgYqn74LuA3wmdA+VVK+iINKKP\nuEpO4MbBSqTWA2o44/3N6u+a5duqoe4O5SusMikMM+Hh3JnaynE0Our2tQ/8vs+i\nI0DxxwlRu1JuQ3o+5T5artIWKqe45Qx8h+kbgj5aEaruxt0rzMkQ3kx/tF1SHyst\nylT8Sxh/VNcy4XXzwDdHG8bE33FSFsV+DIrRzuzAoQKBgQDBJ1DgWsejjxc9GRHy\nnycYTh3p13Forh6jQ2tlLjLb+duXBWfB9ewHublSBRv8A43eNfv4AxGFSJwy/9UK\nf2MfW9bk6auNzF1nbzHanYPEvDJmwyEk0tP7xoF17FL7IWX+EH6tQh0JGZFhukDP\nnRXm+e6OW9bbYxvyq/9l6UnuDwKBgQDfJ7lWJrtCTQwt96nDDgASKulyi8YQ6mkN\nMBRyEaJdUCsX8CQcSqUGdTxvfC0lbg5jJpcu5XUAv21hgZbD19OR7T5enFfosujJ\nMY+bWmuv0HOFIMpJofF2V5zZ5yd9gpKPTVk1zCsFE7Fz4QhY5Tubkyk5jRw9Knku\nhCMm4CtxzQKBgQC0PqEdS/mCqtPvwwZZl6Ue7D7D6bU+D0Yt6os8lzkEyAvfyT6C\n5J+Gsgy6+mOb8CEiXNQuI4blDtYcTVqb+jYgnE5Tva7GmxAKptwp+tVs8IZEGRFD\n0K3bBOnohkkFaqxHw1LDEbAQvthJD0rNsvQuX8r6877zaXA6K8Egc+v2hwKBgDvu\njj8N/eLLkIbT6frhyrEWZ0YFNfebDQWmsQcFp2aKPliafQhAH9wBJm8GmZVg3mpQ\nle/ZXjgKMVUrmZMVZtPdNI/yS0XKruxB7ECb4yn/wNazPMDTxmazFwQKqbdyluv3\nqQriv3cIl/L4L+a4Ae9BcaPsOvZObudIQ6yQLfrNAoGAFWjZAlwLEOF3yLNVFeSA\nh+yFXNJG3IefoCgXSaHxghVGfMLW/RYen77H+L4pY8B2d+PvVtiqt3mNQqydentm\noJ0Ly7q6QS4Dh76hhMDhuJYqKX8e5bPvxUqDB+Tl9PNOH3g7hLPuxY6VxdMAmjF/\nlNfi7m8S0GJryKv2Go0sHqM=\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-npav1@esplorado-c5207.iam.gserviceaccount.com",
    "client_id": "113707747410150082229",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-npav1%40esplorado-c5207.iam.gserviceaccount.com",
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
