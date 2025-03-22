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
# Allow all origins for debugging; revert to specific origins in production
CORS(app, resources={r"/*": {"origins": "*"}})

# Hardcoded Firebase credentials (move to env vars in production)
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

# User class (unchanged)
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

def check_existing_user(email, id):
    if not db:
        logger.error("Firestore not initialized")
        return "database_error", None
    try:
        logger.debug(f"Checking if user exists with email: {email}, id: {id}")
        email_query = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()
        for doc in email_query:
            logger.debug(f"Email '{email}' already exists with doc ID: {doc.id}")
            return "email", doc.id
        id_query = db.collection('users').where(filter=firestore.FieldFilter('id', '==', id)).limit(1).stream()
        for doc in id_query:
            logger.debug(f"ID '{id}' already exists with doc ID: {doc.id}")
            return "id", doc.id
        logger.debug("No existing user found")
        return None, None
    except Exception as e:
        logger.error(f"Error checking existing user: {str(e)}")
        return "error", None

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
    if not db:
        logger.error("Firestore not initialized")
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

# Input validation helper
def validate_input(data, required_fields):
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing or empty field: {field}"
    return True, None

# Routes
@app.route('/register', methods=['POST'])
def register():
    if not db:
        logger.error("Database connection not initialized")
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        logger.debug(f"Received registration data: {data}")

        required_fields = ['name', 'email', 'id', 'dept', 'password']
        is_valid, error_message = validate_input(data, required_fields)
        if not is_valid:
            logger.error(error_message)
            return jsonify({'success': False, 'message': error_message}), 400

        name = data.get('name')
        email = data.get('email')
        id = data.get('id')
        dept = data.get('dept')
        password = data.get('password')
        role = data.get('role', 'user')

        conflict_field, existing_user_id = check_existing_user(email, id)
        if conflict_field:
            message = f"{conflict_field.capitalize()} already exists"
            logger.error(message)
            return jsonify({'success': False, 'message': message}), 400

        if role not in ['user', 'admin']:
            logger.error("Invalid role selected")
            return jsonify({'success': False, 'message': 'Invalid role'}), 400

        password_hash = generate_password_hash(password)
        user_data = {
            'name': name,
            'email': email,
            'id': id,
            'dept': dept,
            'password_hash': password_hash,
            'role': role
        }
        logger.debug(f"Saving user data to Firestore: {user_data}")

        db.collection('users').document(id).set(user_data)
        logger.info(f"User {id} successfully saved to Firestore")
        response = jsonify({'success': True, 'message': 'User registered successfully'})
        logger.debug(f"Sending response: {response.get_data(as_text=True)}")
        return response, 200

    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500

# (Other routes remain mostly unchanged; adding similar logging and db checks where needed)
@app.route('/login', methods=['POST'])
def login():
    if not db:
        logger.error("Database connection not initialized")
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        data = request.json
        required_fields = ['role', 'email', 'password']
        is_valid, error_message = validate_input(data, required_fields)
        if not is_valid:
            logger.error(error_message)
            return jsonify({'success': False, 'message': error_message}), 400

        role = data.get('role')
        email = data.get('email')
        password = data.get('password')

        if role not in ['user', 'admin']:
            logger.error("Invalid role selected")
            return jsonify({'success': False, 'message': 'Invalid role selected'}), 400

        users_ref = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()
        user = None
        for doc in users_ref:
            user = User.from_dict(doc.id, doc.to_dict())
            break

        if user and check_password_hash(user.password_hash, password):
            if user.role != role:
                logger.error(f"Role mismatch: expected {role}, got {user.role}")
                return jsonify({'success': False, 'message': 'Role does not match'}), 400
            response = jsonify({
                'success': True,
                'message': 'Login successful',
                'role': user.role,
                'user': {'name': user.name, 'email': user.email, 'id': user.id, 'dept': user.dept}
            })
            logger.debug(f"Sending response: {response.get_data(as_text=True)}")
            return response, 200
        else:
            logger.error("Invalid credentials")
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'success': False, 'message': f'Login failed: {str(e)}'}), 500

@app.route('/inventory', methods=['GET'])
def get_inventory():
    if not db:
        logger.error("Database connection not initialized")
        return jsonify({'success': False, 'message': 'Database connection not initialized'}), 503
    try:
        inventory_ref = db.collection('inventory').stream()
        items = [InventoryItem.from_dict(doc.id, doc.to_dict()) for doc in inventory_ref]
        response = jsonify({
            'success': True,
            'items': [{'id': item.id, 'name': item.name, 'category': item.category, 'sku': item.sku, 'quantity': item.quantity, 'unit_price': item.unit_price, 'image_url': item.image_url} for item in items]
        })
        logger.debug(f"Sending response: {response.get_data(as_text=True)}")
        return response, 200
    except Exception as e:
        logger.error(f"Error fetching inventory: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching inventory: {str(e)}'}), 500

# (Add similar logging and db checks to other routes as needed)

# Main execution with Render compatibility
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))  # Use Render's PORT env var, fallback to 5000
    host = "0.0.0.0"  # Bind to all interfaces for Render
    max_retries = 3
    retry_delay = 5  # seconds

    for attempt in range(max_retries):
        try:
            logger.info(f"Starting Flask server on {host}:{port} (attempt {attempt + 1}/{max_retries})")
            app.run(host=host, port=port, debug=False)  # Debug=False for production
            break  # Exit loop if successful
        except Exception as e:
            logger.critical(f"Failed to start Flask server: {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                import time
                time.sleep(retry_delay)
            else:
                logger.error("Max retries reached. Server failed to start.")
                raise  # Raise the last exception after max retries
