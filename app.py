from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os, logging, datetime, jwt
from functools import wraps
import mysql.connector
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean

# -----------------------------
# CONFIGURATION
# -----------------------------
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
HF_API_URL = 'https://api-inference.huggingface.co/models/cardiffnlp/twitter-roberta-base-sentiment'
HF_API_TOKEN = 'YOUR_HF_API_KEY_HERE'
JWT_SECRET = 'SUPER_SECRET_KEY_123!'
JWT_EXP_DELTA_SECONDS = 3600

app = Flask(__name__, template_folder='templates')
CORS(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Rate Limiter
limiter = Limiter(app, key_func=get_remote_address, default_limits=["100 per hour"])
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Database config
db_config = {'host': 'localhost', 'user': 'root', 'password': 'YOUR_DB_PASSWORD', 'database': 'emotion_sense'}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# -----------------------------
# HELPERS
# -----------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_text(text):
    return clean(text, strip=True)

# JWT decorator with role check
def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('x-access-token')
            if not token:
                return jsonify({'error': 'Token is missing'}), 401
            try:
                data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                user_id = data['user_id']
                user_role = data.get('role', 'user')
                if role and user_role != role:
                    return jsonify({'error': 'Unauthorized access'}), 403
            except:
                return jsonify({'error': 'Token is invalid'}), 401
            return f(user_id, *args, **kwargs)
        return decorated
    return decorator

def analyze_text_emotion(text):
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    payload = {"inputs": text}
    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and 'label' in data[0] and 'score' in data[0]:
                emotion = data[0]['label']
                score = round(data[0]['score'] * 100, 2)
                all_scores = {item['label']: round(item['score'] * 100, 2) for item in data}
                return emotion, score, all_scores
    except requests.RequestException as e:
        logging.error("Hugging Face API error: %s", e)
    return "Unknown", 0, {}

# -----------------------------
# ROUTES
# -----------------------------
@app.route('/')
def home():
    return render_template('index.html')

# Registration
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    name = sanitize_text(data.get('name', ''))
    email = sanitize_text(data.get('email', '')).lower()
    password_hash = generate_password_hash(data.get('password', 'defaultpassword'))
    if not name or not email:
        return jsonify({'error': 'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Email already registered'}), 400

    cursor.execute(
        "INSERT INTO users (name, email, password, age, location, phone, id_number, marital_status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (name, email, password_hash, data.get('age'), data.get('location'), data.get('phone'), data.get('idNumber'), data.get('maritalStatus'))
    )
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'message': 'User registered successfully'}), 201

# Login
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    email = sanitize_text(data.get('email', '')).lower()
    password = data.get('password', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close(); conn.close()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid email or password'}), 401

    payload = {
        'user_id': user['id'],
        'role': user.get('role', 'user'),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token, 'role': user.get('role', 'user')})

# Journal entry submission
@app.route('/api/entries', methods=['POST'])
@token_required()
@limiter.limit("20 per hour")
def submit_entry(user_id):
    section = sanitize_text(request.form.get('section', ''))
    entry_text = sanitize_text(request.form.get('entry', ''))
    if not section or not entry_text:
        return jsonify({'error': 'Missing required fields'}), 400

    image_path = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"user{user_id}_{file.filename}")
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(image_path)

    emotion, score, all_scores = analyze_text_emotion(entry_text)
    RECOMMENDATIONS = {
        "happy": "Keep enjoying your day! Consider sharing your joy with others.",
        "sad": "Try talking to a friend or visiting a counselor for support.",
        "angry": "Take a few deep breaths or a short walk to calm down.",
        "fear": "Practice mindfulness or relaxation exercises to reduce anxiety.",
        "neutral": "Stay balanced and continue your routine."
    }
    auto_response = RECOMMENDATIONS.get(emotion.lower(), "Take care of yourself today!")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO journal_entries (user_id, section, entry_text, image_path, emotion, score, recommendation) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (user_id, section, entry_text, image_path, emotion, score, auto_response)
    )
