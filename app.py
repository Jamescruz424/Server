import os
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS
cors_allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "*")  # Adjust for production
CORS(app, resources={r"/*": {"origins": cors_allowed_origins}})

# Hardcoded Firebase credentials (move to env var in production)
cred_dict = {
    "type": "service_account",
    "project_id": "inventory-eec69",
    "private_key_id": "7e4c13d95a3084a86170118f4b7eeb9f957781ab",
    "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCU3QJfdPcG3QvH
DwBfSqLWIXymbv+7NKUtAafAJdtyhLSyh+wUx7ONdM9jtcsgGeFE05W6O0Xy6sT3
XkMhw4aT8PYI9u8VGiQhcLkw5r3G7kG8ksRL4+JrOAdBvZrAX/AM27FRy9ZGeK9x
ijzsqNgLtZxvM9Y/W8djT5pwEl6Ex3vUS6l1F9EGNhTFFV7/t4waEFV1kIX8SHLW
0vsD7DzEi/AMpCgCn+82A4jgcY88xar0jh8lZINw4EExDJl2BwInqoVx2OgLjsB5
CjebGc+whZlFWbaPuUH4VCR4hm0302gd4M+9JwHxfzydD/dPBFWiDGavNp9wjUTR
l+JvqZzDAgMBAAECggEAATFSrp2IyWsTiCbSHgOd/17E4onossEOuXE6vQ0ndARc
Bx5vhdo9vz8H+zG+moVPIc1kdOwD78+obec5OFM+7JE6A/o6f7cj1Imdc12ieFLn
7TWiY7IffqH9Npv7WjVc2exg9xmW6R3F/O3RZCRMKtNHK4HFK7xaSz8vPROgmYWV
XCyDXMDA0RVGe6ceHJXvAoDIiEyUTna8uWPfuz712z7scCP6Ymh7MIYsh2kixJsY
BS8mYRZmQzb2da50syam3CcIDOeMbX5ncYCjbYQhZusOFMq+UeRgU1snSuuEGBvr
hWhKIyQRoT6Fe7lvXe7x23vL81WQeZMM8o8a52QikQKBgQDF0UQ5e3foiXFI5SjA
R0/Y64lmYUUuE26BfJx+43SrdpRs2BjSgQMfT/NGeAxrC09qBIv75yS5YyrWm4dA
jV9HAT4d5jF4cr8kTXS9VReSqL8UekcP7Z46KeMrfqq+gJ2tQczxftGv4TJg/gG8
e0vrwGnB03uqiQSPVuBkLD1AkwKBgQDApbl7IPSjgkLU0zLoWJ0cLP29e5nbhxxM
Lx78/cHeleshLQcx74RISWqssBboElNvx/sbXIQD6YUZMmosAHpz9VaKMWiWr1rx
A+DNvmfl8ZPz7OdpwyndRqsF9v3E+ka7FUiAhygf79bLRd+N6hmti/6mQdSchSPy
7V7Yq+FBEQKBgG4KyKIVbhG8i3laiT3VLbTk6e07BQnpo1qC4GexzlAnyc92svA+
9mavygwUcgwGIao/V0PNRF+gq87we9/MBQlxxoVJbZGse2oNcHh2YoOiPZF9qBRT
QebnMEkc0Izi7VPZO9HHk4v8gVL1Wi/ogsZlpi89nxix2giG8pKnDXfjAoGACCp+
NEPvWsb4wkC5lbO75SfbEZ8dpHqTrn8I1zyCbUb5koxwE6PNfarvBKbqMaglNUXK
1RwU1H2fkLPcYEUc67Fom68AefKw7ip16wK5MLwOw3Y1UPxe1+xY74XKuADL4r5C
NoCEKOZnunIZydA0inC2uKFtu7zBC1kYfiK7B6ECgYBXr89xON0TTxphCsNfMIrt
O+O/3k+ONvYqLMjA/US8Bnt5Ce5ZvbjU8mkoJn5rcHie4gIlmBijMvVOU7vs7nNK
s+tqqOWtY2lUmiF+hZ+CGfJx8GJZbsL+Cui4TtIQFnwKNdM6uTbG1c1ZYAFi9N0V
3I/qUo20JTWCuX8jSuOgqA==
-----END PRIVATE KEY-----""",
    "client_email": "firebase-adminsdk-fbsvc@inventory-eec69.iam.gserviceaccount.com",
    "client_id": "105947406222937872714",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40inventory-eec69.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}

# Global Firestore client
db = None

def initialize_firebase():
    global db
    try:
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        logger.info("Firebase initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {str(e)}")
        db = None

# Initialize Firebase at startup
initialize_firebase()

if not db:
    logger.critical("Firebase initialization failed, app will not function correctly")

# User class
class User:
    def __init__(self, doc_id, name, email, id, dept, password_hash, role='user'):
        self.doc_id = doc_id
        self.name = name
        self.email = email
        self.id = id
        self.dept = dept
        self.password_hash = password_hash
        self.role = role

    def to_dict(self):
        return {
            'name': self.name,
            'email': self.email,
            'id': self.id,
            'dept': self.dept,
            'password_hash': self.password_hash,
            'role': self.role
        }

    @staticmethod
    def from_dict(doc_id, data):
        return User(
            doc_id=doc_id,
            name=data['name'],
            email=data['email'],
            id=data['id'],
            dept=data['dept'],
            password_hash=data['password_hash'],
            role=data.get('role', 'user')
        )

# Inventory class
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

def check_existing_user(email, id):
    if not db:
        return "database_error", None
    try:
        logger.debug(f"Checking if user exists with email: {email}, id: {id}")
        email_query = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()
        for doc in email_query:
            return "email", doc.id
        id_query = db.collection('users').where(filter=firestore.FieldFilter('id', '==', id)).limit(1).stream()
        for doc in id_query:
            return "id", doc.id
        return None, None
    except Exception as e:
        logger.error(f"Error checking existing user: {str(e)}")
        return "error", None

def check_existing_sku(sku, exclude_id=None):
    if not db:
        return None
    try:
        logger.debug(f"Checking existing SKU: {sku}")
        query = db.collection('inventory').where(filter=firestore.FieldFilter('sku', '==', sku)).stream()
        for doc in query:
            if exclude_id is None or doc.id != exclude_id:
                return doc.id
        return None
    except Exception as e:
        logger.error(f"Error checking existing SKU: {str(e)}")
        return None

# API Routes
@app.route('/register', methods=['POST'])
def register():
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        logger.debug(f"Received registration data: {data}")
        name = data.get('name')
        email = data.get('email')
        id = data.get('id')
        dept = data.get('dept')
        password = data.get('password')
        role = data.get('role', 'user')

        if not all([name, email, id, dept, password]):
            return jsonify({'success': False, 'message': 'Missing fields'}), 400

        conflict_field, existing_id = check_existing_user(email, id)
        if conflict_field:
            return jsonify({'success': False, 'message': f"{conflict_field.capitalize()} already exists"}), 400

        if role not in ['user', 'admin']:
            return jsonify({'success': False, 'message': 'Invalid role'}), 400

        password_hash = generate_password_hash(password)
        user = User(id, name, email, id, dept, password_hash, role)
        db.collection('users').document(id).set(user.to_dict())
        return jsonify({'success': True, 'message': 'User registered successfully'}), 200
    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        role = data.get('role')
        email = data.get('email')
        password = data.get('password')

        if not all([role, email, password]):
            return jsonify({'success': False, 'message': 'Missing fields'}), 400

        if role not in ['user', 'admin']:
            return jsonify({'success': False, 'message': 'Invalid role selected'}), 400

        users_ref = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()
        user = None
        for doc in users_ref:
            user = User.from_dict(doc.id, doc.to_dict())
            break

        if user and check_password_hash(user.password_hash, password) and user.role == role:
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'role': user.role,
                'user': {'name': user.name, 'email': user.email, 'id': user.id, 'dept': user.dept}
            }), 200
        return jsonify({'success': False, 'message': 'Invalid credentials or role mismatch'}), 401
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/inventory', methods=['GET'])
def get_inventory():
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        inventory_ref = db.collection('inventory').stream()
        items = [InventoryItem.from_dict(doc.id, doc.to_dict()) for doc in inventory_ref]
        return jsonify({
            'success': True,
            'items': [{'id': item.id, 'name': item.name, 'category': item.category, 'sku': item.sku, 'quantity': item.quantity, 'unit_price': item.unit_price, 'image_url': item.image_url} for item in items]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching inventory: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/inventory', methods=['POST'])
def add_inventory():
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        logger.debug(f"Received inventory data: {data}")
        name = data.get('name')
        category = data.get('category')
        sku = data.get('sku')
        quantity = data.get('quantity')
        unit_price = data.get('unit_price')
        image_url = data.get('image_url')

        if not all([name, category, sku, quantity is not None, unit_price is not None]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        if not isinstance(quantity, int) or quantity < 0:
            return jsonify({'success': False, 'message': 'Quantity must be a non-negative integer'}), 400
        if not isinstance(unit_price, (int, float)) or unit_price < 0:
            return jsonify({'success': False, 'message': 'Unit price must be a non-negative number'}), 400

        if check_existing_sku(sku):
            return jsonify({'success': False, 'message': 'SKU already exists'}), 400

        new_item_ref = db.collection('inventory').document()
        new_item = InventoryItem(new_item_ref.id, name, category, sku, quantity, unit_price, image_url)
        new_item_ref.set(new_item.to_dict())
        return jsonify({'success': True, 'message': 'Item added successfully', 'id': new_item.id}), 201
    except Exception as e:
        logger.error(f"Error adding inventory: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/inventory/<item_id>', methods=['PUT'])
def update_inventory(item_id):
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        name = data.get('name')
        category = data.get('category')
        sku = data.get('sku')
        quantity = data.get('quantity')
        unit_price = data.get('unit_price')
        image_url = data.get('image_url')

        if not all([name, category, sku, quantity is not None, unit_price is not None]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        if not isinstance(quantity, int) or quantity < 0:
            return jsonify({'success': False, 'message': 'Quantity must be a non-negative integer'}), 400
        if not isinstance(unit_price, (int, float)) or unit_price < 0:
            return jsonify({'success': False, 'message': 'Unit price must be a non-negative number'}), 400

        existing_sku_id = check_existing_sku(sku, exclude_id=item_id)
        if existing_sku_id:
            return jsonify({'success': False, 'message': 'SKU already exists'}), 400

        item_ref = db.collection('inventory').document(item_id)
        if not item_ref.get().exists:
            return jsonify({'success': False, 'message': 'Item not found'}), 404

        updated_item = InventoryItem(item_id, name, category, sku, quantity, unit_price, image_url)
        item_ref.set(updated_item.to_dict())
        return jsonify({'success': True, 'message': 'Item updated successfully'}), 200
    except Exception as e:
        logger.error(f"Error updating inventory: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/inventory/<item_id>', methods=['DELETE'])
def delete_inventory(item_id):
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        item_ref = db.collection('inventory').document(item_id)
        if not item_ref.get().exists:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
        item_ref.delete()
        return jsonify({'success': True, 'message': 'Item deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error deleting inventory: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests', methods=['POST'])
def create_request():
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        user_id = data.get('userId')
        product_id = data.get('productId')
        product_name = data.get('productName')
        timestamp = data.get('timestamp')
        status = data.get('status', 'Pending')

        if not all([user_id, product_id, product_name, timestamp]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        user_ref = db.collection('users').where(filter=firestore.FieldFilter('id', '==', user_id)).limit(1).stream()
        if not any(doc.exists for doc in user_ref):
            return jsonify({'success': False, 'message': 'User not found'}), 404

        product_ref = db.collection('inventory').document(product_id)
        if not product_ref.get().exists:
            return jsonify({'success': False, 'message': 'Product not found'}), 404

        request_data = {
            'userId': user_id,
            'productId': product_id,
            'productName': product_name,
            'timestamp': timestamp,
            'status': status,
        }
        request_ref = db.collection('requests').document()
        request_ref.set(request_data)
        return jsonify({'success': True, 'message': 'Request created successfully', 'requestId': request_ref.id}), 201
    except Exception as e:
        logger.error(f"Error creating request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests', methods=['GET'])
def get_requests():
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        requests_ref = db.collection('requests').stream()
        requests = []
        for doc in requests_ref:
            req = doc.to_dict()
            req['requestId'] = doc.id
            user_ref = db.collection('users').where(filter=firestore.FieldFilter('id', '==', req['userId'])).limit(1).stream()
            req['requester'] = next((u.to_dict()['name'] for u in user_ref), 'Unknown')
            requests.append(req)
        return jsonify({'success': True, 'requests': requests}), 200
    except Exception as e:
        logger.error(f"Error fetching requests: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests/<request_id>', methods=['PUT'])
def update_request(request_id):
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        status = data.get('status')
        if not status:
            return jsonify({'success': False, 'message': 'Status is required'}), 400

        request_ref = db.collection('requests').document(request_id)
        if not request_ref.get().exists:
            return jsonify({'success': False, 'message': 'Request not found'}), 404

        request_ref.update({'status': status})
        return jsonify({'success': True, 'message': f'Request {status} successfully'}), 200
    except Exception as e:
        logger.error(f"Error updating request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests/<request_id>', methods=['DELETE'])
def delete_request(request_id):
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json or {}
        user_id = data.get('userId')
        if not user_id:
            return jsonify({'success': False, 'message': 'User ID is required'}), 400

        request_ref = db.collection('requests').document(request_id)
        request_doc = request_ref.get()
        if not request_doc.exists:
            return jsonify({'success': False, 'message': 'Request not found'}), 404

        if request_doc.to_dict()['userId'] != user_id:
            return jsonify({'success': False, 'message': 'You can only delete your own requests'}), 403

        request_ref.delete()
        return jsonify({'success': True, 'message': 'Request deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error deleting request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/dashboard', methods=['GET'])
def get_dashboard_data():
    if not db:
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        inventory_ref = db.collection('inventory').stream()
        inventory_items = [InventoryItem.from_dict(doc.id, doc.to_dict()) for doc in inventory_ref]
        total_items = len(inventory_items)
        total_value = sum(item.unit_price * item.quantity for item in inventory_items)
        low_stock_items = [item.to_dict() for item in inventory_items if item.quantity < 5]

        requests_ref = db.collection('requests').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(5).stream()
        recent_orders = []
        total_orders = 0
        pending_orders = 0
        for doc in db.collection('requests').stream():
            total_orders += 1
            if doc.to_dict().get('status') == 'Pending':
                pending_orders += 1

        for doc in requests_ref:
            req = doc.to_dict()
            req['requestId'] = doc.id
            user_ref = db.collection('users').where(filter=firestore.FieldFilter('id', '==', req['userId'])).limit(1).stream()
            req['requester'] = next((u.to_dict()['name'] for u in user_ref), 'Unknown')
            recent_orders.append(req)

        return jsonify({
            'success': True,
            'data': {
                'total_items': total_items,
                'total_value': round(total_value, 2),
                'low_stock_items': low_stock_items,
                'total_orders': total_orders,
                'pending_orders': pending_orders,
                'recent_orders': recent_orders
            }
        }), 200
    except Exception as e:
        logger.error(f"Error fetching dashboard data: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))  # Use Render's PORT env var
    host = "0.0.0.0"  # Bind to all interfaces for Render
    app.run(host=host, port=port, debug=False)  # Debug=False for production
