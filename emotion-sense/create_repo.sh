#!/usr/bin/env bash
set -e

ROOT="emotion-sense"
echo "Creating project folder: $ROOT"
rm -rf "$ROOT"
mkdir -p "$ROOT"/{templates,static,sql,uploads}

echo "Writing app.py..."
cat > "$ROOT/app.py" <<'PY'
# (BEGIN app.py)
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os, logging, datetime, jwt, io
from functools import wraps
import mysql.connector
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean

# -----------------------------
# CONFIGURATION (update these)
# -----------------------------
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB

# Hugging Face models / endpoints (you must provide HF API token)
HF_API_TOKEN = 'YOUR_HF_API_KEY_HERE'  # <--- replace
HF_TEXT_MODEL = 'cardiffnlp/twitter-roberta-base-sentiment'   # example text model
HF_IMAGE_MODEL = 'nateraw/face-emotion'                      # example image model (change if desired)
HF_BASE_URL = 'https://api-inference.huggingface.co/models/'

JWT_SECRET = 'SUPER_SECRET_KEY_123!'     # change for production
JWT_EXP_DELTA_SECONDS = 3600

# -----------------------------
# APP INITIALIZATION
# -----------------------------
app = Flask(__name__, template_folder='templates')
CORS(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Rate Limiter
limiter = Limiter(app, key_func=get_remote_address, default_limits=["100 per hour"])
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Database config — update with your credentials
db_config = {'host': 'localhost', 'user': 'root', 'password': 'YOUR_DB_PASSWORD', 'database': 'emotion_sense'}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# -----------------------------
# HELPERS
# -----------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_text(text):
    return clean(text or '', strip=True)

def hf_text_analyze(text):
    url = HF_BASE_URL + HF_TEXT_MODEL
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    payload = {"inputs": text}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            all_scores = {item['label']: round(item['score']*100,2) for item in data if 'label' in item and 'score' in item}
            top = max(data, key=lambda x: x.get('score',0))
            emotion = top.get('label','unknown')
            score = round(top.get('score',0)*100,2)
            return emotion, score, all_scores
    except Exception as e:
        logging.error("Text HF error: %s", e)
    return "unknown", 0.0, {}

def hf_image_analyze(image_path):
    url = HF_BASE_URL + HF_IMAGE_MODEL
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    try:
        with open(image_path,'rb') as f:
            data = f.read()
        resp = requests.post(url, headers=headers, data=data, timeout=20)
        resp.raise_for_status()
        out = resp.json()
        if isinstance(out, list):
            all_scores = {item['label']: round(item['score']*100,2) for item in out if 'label' in item and 'score' in item}
            top = max(out, key=lambda x: x.get('score',0))
            emotion = top.get('label','unknown')
            score = round(top.get('score',0)*100,2)
            return emotion, score, all_scores
    except Exception as e:
        logging.error("Image HF error: %s", e)
    return "unknown", 0.0, {}

RECOMMENDATIONS = {
    "happy": {
        "message": "You're feeling happy — that's wonderful! Keep engaging in activities that bring you joy.",
        "severity": "low",
        "resources": []
    },
    "sad": {
        "message": "You seem sad. Consider talking to someone you trust. If it persists, see a counselor.",
        "severity": "medium",
        "resources": [
            {"type":"Counselor","name":"Local Counseling Center","phone":"+254700000001"},
            {"type":"Hospital","name":"Mental Health Unit - City Hospital","phone":"+254700000002"}
        ]
    },
    "angry": {
        "message": "You're showing signs of anger. Try calming exercises and consider counseling if frequent.",
        "severity":"medium",
        "resources":[]
    },
    "fear": {
        "message":"Fear/anxiety detected. Practice breathing and grounding techniques; consult a professional if needed.",
        "severity":"medium",
        "resources":[{"type":"Counselor","name":"Anxiety Clinic","phone":"+254700000003"}]
    },
    "neutral": {
        "message":"You're neutral. Keep monitoring how you feel and practice regular self-care.",
        "severity":"low",
        "resources":[]
    },
    "unknown": {
        "message":"We couldn't confidently detect an emotion. If you're distressed, consider reaching out for support.",
        "severity":"unknown",
        "resources":[]
    }
}

def generate_ai_response(emotion_label, text=None):
    key = (emotion_label or "unknown").lower()
    rec = RECOMMENDATIONS.get(key, RECOMMENDATIONS['unknown'])
    response = {
        "emotion": emotion_label,
        "message": rec['message'],
        "severity": rec.get('severity','low'),
        "resources": rec.get('resources', [])
    }
    return response

# -----------------------------
# AUTH DECORATOR
# -----------------------------
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
                user_role = data.get('role','user')
                if role and user_role != role:
                    return jsonify({'error':'Unauthorized access'}), 403
            except Exception as e:
                logging.warning("Token decode failed: %s", e)
                return jsonify({'error': 'Token is invalid'}), 401
            return f(user_id, *args, **kwargs)
        return decorated
    return decorator

# -----------------------------
# ROUTES
# -----------------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    name = sanitize_text(data.get('name',''))
    email = sanitize_text(data.get('email','')).lower()
    password = data.get('password','')
    password_hash = generate_password_hash(password or 'defaultpassword')

    if not name or not email:
        return jsonify({'error':'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error':'Email already registered'}), 400

    cursor.execute(
        "INSERT INTO users (name, email, password, age, location, phone, id_number, marital_status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (name, email, password_hash, data.get('age'), data.get('location'), data.get('phone'), data.get('idNumber'), data.get('maritalStatus'))
    )
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'message':'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    email = sanitize_text(data.get('email','')).lower()
    password = data.get('password','')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close(); conn.close()
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'error':'Invalid email or password'}), 401

    payload = {
        'user_id': user['id'],
        'role': user.get('role','user'),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token, 'role': user.get('role','user')})

@app.route('/api/entries', methods=['POST'])
@token_required()
@limiter.limit("30 per hour")
def submit_entry(user_id):
    section = sanitize_text(request.form.get('section',''))
    entry_text = sanitize_text(request.form.get('entry',''))
    if not section or not entry_text:
        return jsonify({'error':'Missing required fields'}), 400

    image_path = None
    img_emotion = None
    img_scores = {}
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"user{user_id}_{int(datetime.datetime.utcnow().timestamp())}_{file.filename}")
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(image_path)
            img_emotion, img_score, img_scores = hf_image_analyze(image_path)

    text_emotion, text_score, text_scores = hf_text_analyze(entry_text)

    final_emotion = text_emotion
    final_score = text_score
    combined_scores = text_scores.copy()
    for k,v in img_scores.items():
        combined_scores[k] = max(combined_scores.get(k,0), v)
    if img_emotion and img_scores:
        if max(img_scores.values(), default=0) > max(text_scores.values(), default=0) + 5:
            final_emotion = img_emotion
            final_score = max(img_scores.values())

    ai_resp = generate_ai_response(final_emotion, entry_text)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO journal_entries (user_id, section, entry_text, image_path, emotion, score, recommendation) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (user_id, section, entry_text, image_path, final_emotion, float(final_score), ai_resp['message'])
    )
    conn.commit()
    cursor.close(); conn.close()

    return jsonify({
        'emotion': final_emotion,
        'score': final_score,
        'all_scores': combined_scores,
        'recommendation': ai_resp['message'],
        'resources': ai_resp['resources']
    })

@app.route('/api/comments', methods=['POST'])
@token_required()
def submit_comment(user_id):
    data = request.get_json()
    comment = sanitize_text(data.get('comment',''))
    if not comment:
        return jsonify({'error':'Comment required'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (user_id, comment) VALUES (%s,%s)", (user_id, comment))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message':'Comment submitted successfully'})

@app.route('/api/admin/users', methods=['GET'])
@token_required(role='admin')
def admin_list_users(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, email, role, created_at FROM users")
    rows = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify({'users': rows})

@app.route('/uploads/<path:filename>', methods=['GET'])
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(413)
def file_too_large(e):
    return jsonify({'error':'File too large (max 5MB)'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error':'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logging.exception("Server error: %s", e)
    return jsonify({'error':'Internal server error'}), 500

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
# (END app.py)
PY

echo "Writing templates/index.html..."
cat > "$ROOT/templates/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Emotion Sense</title>
  <link rel="stylesheet" href="/static/styles.css" />
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <header>
    <h1>Emotion Sense</h1>
    <p>AI-powered emotion detection from text & images — private and secure.</p>
  </header>

  <main>
    <section id="authSection">
      <div class="card">
        <h2>Register</h2>
        <form id="registerForm">
          <input name="name" placeholder="Full name" required />
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password" required />
          <input name="age" type="number" placeholder="Age" />
          <input name="location" placeholder="Location" />
          <input name="phone" placeholder="Phone" />
          <input name="idNumber" placeholder="ID number" />
          <select name="maritalStatus"><option value="">Marital status</option><option>Single</option><option>Married</option></select>
          <button type="submit">Register</button>
        </form>
      </div>

      <div class="card">
        <h2>Login</h2>
        <form id="loginForm">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password" required />
          <button type="submit">Login</button>
          <p id="loginStatus" class="muted"></p>
        </form>
      </div>
    </section>

    <section id="privateSection" style="display:none;">
      <div class="card">
        <h2>Journal Entry</h2>
        <form id="journalForm" enctype="multipart/form-data">
          <select name="section" required>
            <option value="">Select category</option>
            <option>Daily Reflection</option>
            <option>Stress / Anxiety</option>
            <option>Relationships</option>
            <option>Work</option>
            <option>Other</option>
          </select>
          <textarea name="entry" placeholder="How are you feeling today?" required></textarea>

          <!-- file upload -->
          <label class="file-label">Upload image (optional):
            <input type="file" name="image" accept="image/*" id="uploadImage" />
          </label>

          <!-- camera capture -->
          <div class="camera-wrap">
            <video id="camera" autoplay playsinline></video>
            <button type="button" id="captureBtn">Capture Photo</button>
            <canvas id="capturedCanvas" style="display:none;"></canvas>
          </div>

          <button type="submit">Analyze Emotion</button>
        </form>
      </div>

      <div id="resultCard" class="card" style="display:none;">
        <h3>Analysis Result</h3>
        <div id="emotionOutput"></div>
        <canvas id="emotionChart" width="400" height="200"></canvas>
        <div id="resources"></div>
      </div>

      <div class="card">
        <h2>Comments</h2>
        <form id="commentForm">
          <textarea name="comment" placeholder="Leave a comment..." required></textarea>
          <button type="submit">Submit Comment</button>
        </form>
      </div>
    </section>

    <section id="adminSection" style="display:none;">
      <div class="card">
        <h2>Admin Dashboard</h2>
        <button id="loadUsersBtn">Load users</button>
        <pre id="adminResults"></pre>
      </div>
    </section>
  </main>

  <footer>
    <small>&copy; 2025 Emotion Sense</small>
  </footer>

  <script src="/static/app.js"></script>
</body>
</html>
HTML

echo "Writing static/app.js..."
cat > "$ROOT/static/app.js" <<'JS'
// Frontend JS: handles register, login, JWT, camera, submit, chart
let jwtToken = null;
let userRole = null;
let capturedBlob = null;
let emotionChart = null;

function setPrivateUI() {
  document.getElementById('authSection').style.display = 'none';
  document.getElementById('privateSection').style.display = 'block';
  if (userRole === 'admin') document.getElementById('adminSection').style.display = 'block';
}

function showLoginStatus(msg, ok=true) {
  const el = document.getElementById('loginStatus');
  el.innerText = msg;
  el.style.color = ok ? 'green' : 'red';
}

document.getElementById('registerForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch('/api/register',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  const d = await res.json();
  if (res.ok) { alert('Registered. You can now login.'); e.target.reset(); } else alert(d.error || 'Registration failed');
});

document.getElementById('loginForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch('/api/login',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  const d = await res.json();
  if (res.ok || res.status === 200) {
    jwtToken = d.token;
    userRole = d.role;
    setPrivateUI();
    showLoginStatus('Logged in', true);
  } else {
    showLoginStatus(d.error || 'Login failed', false);
  }
});

const video = document.getElementById('camera');
const canvas = document.getElementById('capturedCanvas');
const captureBtn = document.getElementById('captureBtn');
navigator.mediaDevices.getUserMedia({video:true}).then(stream => { video.srcObject = stream }).catch(err => { console.warn('No camera', err) });

captureBtn.addEventListener('click', () => {
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext('2d').drawImage(video, 0, 0);
  canvas.toBlob(blob => {
    capturedBlob = blob;
    alert('Photo captured — it will be submitted with your entry.');
  }, 'image/png');
});

document.getElementById('journalForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  if (!jwtToken) { alert('You must be logged in'); return; }

  const form = document.getElementById('journalForm');
  const formData = new FormData(form);

  const fileInput = document.getElementById('uploadImage');
  if (fileInput && fileInput.files && fileInput.files[0]) {
  } else if (capturedBlob) {
    formData.append('image', capturedBlob, 'capture.png');
  }

  const res = await fetch('/api/entries', { method:'POST', headers: {'x-access-token': jwtToken}, body: formData });
  const d = await res.json();
  if (res.ok) {
    document.getElementById('resultCard').style.display = 'block';
    document.getElementById('emotionOutput').innerHTML = `<strong>Detected:</strong> ${d.emotion} (${d.score}%)<br><strong>Recommendation:</strong> ${d.recommendation}`;
    const rEl = document.getElementById('resources');
    if (d.resources && d.resources.length) {
      rEl.innerHTML = '<h4>Recommended resources:</h4><ul>' + d.resources.map(r => `<li>${r.type}: ${r.name} — ${r.phone || ''}</li>`).join('') + '</ul>';
    } else rEl.innerHTML = '';

    if (emotionChart) emotionChart.destroy();
    const ctx = document.getElementById('emotionChart').getContext('2d');
    const labels = Object.keys(d.all_scores || {});
    const values = labels.map(k => d.all_scores[k]);
    emotionChart = new Chart(ctx, { type:'bar', data:{ labels, datasets:[{ label:'Scores', data: values }] }, options:{ responsive:true, scales:{ y:{ beginAtZero:true, max:100 } } }});
  } else alert(d.error || 'Analysis failed');
});

document.getElementById('commentForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  if (!jwtToken) { alert('You must be logged in'); return; }
  const data = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch('/api/comments', { method:'POST', headers: {'Content-Type':'application/json', 'x-access-token': jwtToken}, body: JSON.stringify(data) });
  const d = await res.json();
  if (res.ok) { alert('Comment submitted'); e.target.reset(); } else alert(d.error || 'Failed');
});

document.getElementById('loadUsersBtn').addEventListener('click', async ()=>{
  if (!jwtToken) { alert('Login as admin'); return; }
  const res = await fetch('/api/admin/users', { headers: {'x-access-token': jwtToken} });
  const d = await res.json();
  if (res.ok) document.getElementById('adminResults').innerText = JSON.stringify(d, null, 2);
  else alert(d.error || 'Failed');
});
JS

echo "Writing static/styles.css..."
cat > "$ROOT/static/styles.css" <<'CSS'
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial;background:linear-gradient(135deg,#ff4d4d,#4dff4d,#4d4dff,#ffff4d);background-size:400% 400%;animation:bg 12s ease infinite;padding:20px;color:#111}
@keyframes bg{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
header{max-width:1000px;margin:0 auto 20px;background:rgba(255,255,255,0.85);padding:20px;border-radius:12px;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,0.12)}
main{max-width:1000px;margin:0 auto}
.card{background:rgba(255,255,255,0.9);padding:18px;border-radius:12px;margin-bottom:16px;box-shadow:0 6px 18px rgba(0,0,0,0.08)}
form input, form select, form textarea{width:100%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid #ccc;font-size:1rem}
form button{background:#1f6feb;color:#fff;padding:10px 14px;border:none;border-radius:8px;cursor:pointer;font-weight:600}
form button:hover{background:#155ac6}
.camera-wrap{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
video{width:320px;height:320px;object-fit:cover;border-radius:8px;border:2px solid #ddd}
canvas{display:none}
#resultCard{max-width:720px}
#emotionOutput{font-size:1rem;margin-bottom:8px}
#resources ul{margin-left:16px}
@media(max-width:768px){video{width:100%;height:220px}}
footer{max-width:1000px;margin:24px auto;text-align:center;color:#222}
CSS

echo "Writing sql/schema.sql..."
cat > "$ROOT/sql/schema.sql" <<'SQL'
-- Create DB and tables for Emotion Sense
CREATE DATABASE IF NOT EXISTS emotion_sense;
USE emotion_sense;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  age INT,
  location VARCHAR(255),
  phone VARCHAR(50),
  id_number VARCHAR(100),
  marital_status VARCHAR(50),
  role ENUM('user','admin') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Default admin (replace hashed password)
INSERT INTO users (name, email, password, role) VALUES
('Admin User','uyomakokiri@gmail.com','<HASHED_PASSWORD>','admin1234');

CREATE TABLE IF NOT EXISTS journal_entries (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  section VARCHAR(100),
  entry_text TEXT NOT NULL,
  image_path VARCHAR(255),
  emotion VARCHAR(100),
  score FLOAT,
  recommendation TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS comments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  comment TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
SQL

echo "Writing requirements.txt..."
cat > "$ROOT/requirements.txt" <<'REQ'
flask
flask-cors
mysql-connector-python
requests
werkzeug
bleach
flask-limiter
pyjwt
REQ

echo "Writing README.md..."
cat > "$ROOT/README.md" <<'MD'
# Emotion Sense - Ready Repo

## Setup (local)

1. Create & activate Python venv:
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate

2. Install deps:
   pip install -r requirements.txt

3. Edit files:
   - app.py: set HF_API_TOKEN and db_config password
   - sql/schema.sql: replace <HASHED_PASSWORD> with generate_password_hash result

4. Import DB:
   mysql -u root -p < sql/schema.sql

5. Run:
   python app.py

6. Open: http://localhost:8000

MD

echo "Creating zip..."
cd "$ROOT"
zip -r ../emotion-sense.zip . > /dev/null
cd ..

echo "Done. Created emotion-sense.zip with the project scaffold."
