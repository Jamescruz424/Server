from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://client-xqp2.onrender.com"}})  # Replace with your React app URL

# Hardcoded Firebase service account credentials
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

# Initialize Firebase with hardcoded credentials
cred = credentials.Certificate(firebase_credentials)
firebase_admin.initialize_app(cred)
db = firestore.client()


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
    email_query = db.collection('users').where(filter=firestore.FieldFilter('email', '==', email)).limit(1).stream()
    for doc in email_query:
        return doc.id
    local_id_query = db.collection('users').where(filter=firestore.FieldFilter('local_id', '==', local_id)).limit(1).stream()
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
    query = db.collection('inventory').where(filter=firestore.FieldFilter('sku', '==', sku)).stream()
    for doc in query:
        if exclude_id is None or doc.id != exclude_id:
            return doc.id
    return None

# Existing Routes (unchanged)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    local_id = data.get('id')
    dept = data.get('dept')
    password = data.get('password')
    role = data.get('role', 'user')

    if not all([name, email, local_id, dept, password]):
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    existing_user_id = check_existing_user(email, local_id)
    if existing_user_id:
        return jsonify({'success': False, 'message': 'Email or ID already exists'}), 400

    if role not in ['user', 'admin']:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(None, name, email, local_id, dept, hashed_password, role)

    user_ref = db.collection('users').document()
    new_user.id = user_ref.id
    user_ref.set(new_user.to_dict())

    return jsonify({'success': True, 'message': 'User registered successfully'}), 201

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

@app.route('/inventory/<item_id>', methods=['PUT'])
def update_inventory(item_id):
    try:
        logger.debug(f"Received PUT request to /inventory/{item_id}")
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

        existing_sku_id = check_existing_sku(sku, exclude_id=item_id)
        if existing_sku_id:
            logger.error(f"SKU {sku} already exists for another item")
            return jsonify({'success': False, 'message': 'SKU already exists'}), 400

        try:
            quantity = int(quantity)
            unit_price = float(unit_price)
        except ValueError as e:
            logger.error(f"Invalid quantity or unit_price: {str(e)}")
            return jsonify({'success': False, 'message': 'Invalid quantity or unit price'}), 400

        item_ref = db.collection('inventory').document(item_id)
        item = item_ref.get()
        if not item.exists:
            logger.error(f"Item {item_id} not found")
            return jsonify({'success': False, 'message': 'Item not found'}), 404

        updated_item = InventoryItem(item_id, name, category, sku, quantity, unit_price, image_url)
        item_ref.set(updated_item.to_dict())
        logger.debug(f"Item {item_id} updated in Firestore")

        return jsonify({'success': True, 'message': 'Item updated successfully'}), 200

    except Exception as e:
        logger.exception("Error in update_inventory: %s", str(e))
        return jsonify({'success': False, 'message': f'Internal server error: {str(e)}'}), 500

@app.route('/inventory/<item_id>', methods=['DELETE'])
def delete_inventory(item_id):
    try:
        item_ref = db.collection('inventory').document(item_id)
        item = item_ref.get()
        if not item.exists:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
        item_ref.delete()
        return jsonify({'success': True, 'message': 'Item deleted successfully'}), 200
    except Exception as e:
        logger.exception("Error in delete_inventory: %s", str(e))
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
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

    if user and check_password_hash(user.password_hash, password):
        if user.role != role:
            return jsonify({'success': False, 'message': 'Role does not match'}), 400
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'role': user.role,
            'user': {'name': user.name, 'email': user.email, 'id': user.local_id, 'dept': user.dept}
        }), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

# New Requests Endpoint
@app.route('/requests', methods=['POST'])
def create_request():
    try:
        logger.debug("Received POST request to /requests")
        data = request.json
        user_id = data.get('userId')
        product_id = data.get('productId')
        product_name = data.get('productName')
        timestamp = data.get('timestamp')
        status = data.get('status', 'Pending')

        if not all([user_id, product_id, product_name, timestamp]):
            logger.error("Missing required fields in request data")
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        # Verify user exists
        user_ref = db.collection('users').where(filter=firestore.FieldFilter('local_id', '==', user_id)).limit(1).stream()
        user_exists = any(doc.exists for doc in user_ref)
        if not user_exists:
            logger.error(f"User {user_id} not found")
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Verify product exists
        product_ref = db.collection('inventory').document(product_id)
        if not product_ref.get().exists:
            logger.error(f"Product {product_id} not found")
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
        logger.debug(f"Request saved to Firestore with ID: {request_ref.id}")

        return jsonify({'success': True, 'message': 'Request created successfully', 'requestId': request_ref.id}), 201
    except Exception as e:
        logger.exception("Error in create_request: %s", str(e))
        return jsonify({'success': False, 'message': str(e)}), 500
# New Endpoints for Requests Page
@app.route('/requests', methods=['GET'])
def get_requests():
    try:
        requests_ref = db.collection('requests').stream()
        requests = []
        for doc in requests_ref:
            req = doc.to_dict()
            req['requestId'] = doc.id
            # Fetch requester name
            user_ref = db.collection('users').where(filter=firestore.FieldFilter('local_id', '==', req['userId'])).limit(1).stream()
            requester_name = next((u.to_dict()['name'] for u in user_ref), 'Unknown')
            req['requester'] = requester_name
            requests.append(req)
        return jsonify({'success': True, 'requests': requests}), 200
    except Exception as e:
        logger.error(f"Error fetching requests: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/requests/<request_id>', methods=['PUT'])
def update_request(request_id):
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
    try:
        # Get userId from request headers or body (assuming sent from frontend)
        data = request.json or {}
        user_id = data.get('userId')
        if not user_id:
            return jsonify({'success': False, 'message': 'User ID is required'}), 400

        request_ref = db.collection('requests').document(request_id)
        request_doc = request_ref.get()
        if not request_doc.exists:
            return jsonify({'success': False, 'message': 'Request not found'}), 404

        request_data = request_doc.to_dict()
        if request_data['userId'] != user_id:
            return jsonify({'success': False, 'message': 'You can only delete your own requests'}), 403

        request_ref.delete()
        return jsonify({'success': True, 'message': 'Request deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error deleting request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

        

# New Dashboard Endpoint
@app.route('/dashboard', methods=['GET'])
def get_dashboard_data():
    try:
        # Inventory stats
        inventory_ref = db.collection('inventory').stream()
        inventory_items = [InventoryItem.from_dict(doc.id, doc.to_dict()) for doc in inventory_ref]
        total_items = len(inventory_items)
        total_value = sum(item.unit_price * item.quantity for item in inventory_items)
        low_stock_items = [item.to_dict() for item in inventory_items if item.quantity < 5]  # Threshold: 5

        # Orders (requests) stats
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
            user_ref = db.collection('users').where(filter=firestore.FieldFilter('local_id', '==', req['userId'])).limit(1).stream()
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


if __name__ == '__main__':
    app.run(debug=True, port=5000)
