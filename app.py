from flask import Flask, request, jsonify, render_template, session, send_file
import sqlite3
import hashlib
import secrets
import os
import hmac
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

def require_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f'Missing required environment variable: {name}')
    return value

DB_PATH = os.getenv('DATABASE', 'ecorp.db')
FLAG_KEY = require_env('FLAG_KEY')
DECRYPT_KEY_PART1 = require_env('DECRYPT_KEY_PART1')
DECRYPT_KEY_PART2 = require_env('DECRYPT_KEY_PART2')
DECRYPT_KEY_PART3 = require_env('DECRYPT_KEY_PART3')
DECRYPT_KEY = f"{DECRYPT_KEY_PART1}{DECRYPT_KEY_PART2}{DECRYPT_KEY_PART3}"
DECOY_FLAG = os.getenv('DECOY_FLAG', 'XPL8{fake_flag_i_require_something}')
IDENTITY_FLAGS = {
    'elliot': require_env('FLAG_1'),
    'whiterose': require_env('FLAG_2'),
    'tyrell': require_env('FLAG_3'),
    'darlene': require_env('FLAG_4'),
    'mrrobot': require_env('FLAG_5'),
}

app = Flask(__name__)
app.secret_key = require_env('SECRET_KEY')

def keystream(secret, length):
    output = b''
    counter = 0
    while len(output) < length:
        output += hashlib.sha256(f'{secret}:{counter}'.encode()).digest()
        counter += 1
    return output[:length]

def decrypt_bytes(hex_data):
    ciphertext = bytes.fromhex(hex_data)
    stream = keystream(FLAG_KEY, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream)).decode()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def root_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        if session.get('is_root') != 1:
            return jsonify({'error': 'Root access required'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM employees WHERE username = ? AND password = ?',
        (username, password)
    ).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    if user['is_root'] == 1:
        conn.close()
        return jsonify({'error': 'Interactive root login disabled'}), 403
    
    if user['two_factor_enabled']:
        session['pending_user_id'] = user['id']
        session['pending_username'] = user['username']
        conn.close()
        return jsonify({
            'requires_2fa': True,
            'message': '2FA code required'
        })
    
    session['user_id'] = user['id']
    session['employee_id'] = user['employee_id']
    session['username'] = user['username']
    session['clearance_level'] = user['clearance_level']
    session['is_root'] = user['is_root']
    
    session_token = secrets.token_hex(32)
    conn.execute('UPDATE employees SET session_token = ? WHERE id = ?', (session_token, user['id']))
    conn.commit()
    
    conn.execute(
        'INSERT INTO access_logs (employee_id, action, ip_address) VALUES (?, ?, ?)',
        (user['employee_id'], 'login', request.remote_addr)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'username': user['username'],
        'clearance_level': user['clearance_level'],
        'is_root': user['is_root']
    })

@app.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        return jsonify({'error': 'No pending authentication'}), 400
    
    data = request.get_json()
    code = data.get('code', '')
    
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM employees WHERE id = ?',
        (session['pending_user_id'],)
    ).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid session'}), 401
    
    try:
        if int(code) == int(user['two_factor_secret']):
            session['user_id'] = user['id']
            session['employee_id'] = user['employee_id']
            session['username'] = user['username']
            session['clearance_level'] = user['clearance_level']
            session['is_root'] = user['is_root']
            
            session_token = secrets.token_hex(32)
            conn.execute('UPDATE employees SET session_token = ? WHERE id = ?', (session_token, user['id']))
            conn.commit()
            
            del session['pending_user_id']
            del session['pending_username']
            
            conn.execute(
                'INSERT INTO access_logs (employee_id, action, ip_address) VALUES (?, ?, ?)',
                (user['employee_id'], 'login_2fa', request.remote_addr)
            )
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'username': user['username'],
                'clearance_level': user['clearance_level'],
                'is_root': user['is_root']
            })
    except (TypeError, ValueError):
        pass
    
    conn.close()
    return jsonify({'error': 'Invalid 2FA code'}), 401

@app.route('/api/search', methods=['GET'])
@login_required
def search_employees():
    query = request.args.get('q', '')
    
    if not query:
        return jsonify({'results': []})
    
    conn = get_db()
    
    sql = f"SELECT employee_id, username, email, department, clearance_level FROM employees WHERE username LIKE '%{query}%' OR department LIKE '%{query}%'"
    
    try:
        results = conn.execute(sql).fetchall()
        conn.close()
        
        employees = []
        for row in results:
            employees.append({
                'employee_id': row['employee_id'],
                'username': row['username'],
                'email': row['email'],
                'department': row['department'],
                'clearance_level': row['clearance_level']
            })
        
        return jsonify({'results': employees})
    except Exception as e:
        conn.close()
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/documents', methods=['GET'])
@login_required
def list_documents():
    conn = get_db()
    clearance = session.get('clearance_level', 1)
    
    docs = conn.execute(
        'SELECT filename, clearance_required, created_at FROM documents WHERE clearance_required <= ? ORDER BY clearance_required DESC',
        (clearance,)
    ).fetchall()
    conn.close()
    
    documents = []
    for doc in docs:
        documents.append({
            'filename': doc['filename'],
            'clearance_required': doc['clearance_required'],
            'created_at': doc['created_at']
        })
    
    return jsonify({'documents': documents})

@app.route('/api/download', methods=['GET'])
@login_required
def download_file():
    filename = request.args.get('file', '')
    
    if not filename:
        return jsonify({'error': 'Filename required'}), 400

    clearance = session.get('clearance_level', 1)
    if clearance < 3:
        return jsonify({'error': 'Level 3 clearance required'}), 403
    
    conn = get_db()
    doc = conn.execute(
        'SELECT * FROM documents WHERE filename = ?',
        (filename,)
    ).fetchone()
    
    if doc:
        if doc['clearance_required'] > clearance:
            conn.close()
            return jsonify({'error': 'Insufficient clearance level'}), 403

        try:
            response = send_file(doc['filepath'], as_attachment=True, download_name=doc['filename'])
            conn.close()
            return response
        except Exception:
            conn.close()
            return jsonify({'error': 'File access error'}), 500

    conn.close()
    filepath = os.path.join('uploads', 'public', filename.replace('../', '', 1))

    try:
        return send_file(filepath, as_attachment=True, download_name=os.path.basename(filename))
    except Exception:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    conn = get_db()
    user = conn.execute(
        'SELECT employee_id, username, email, department, clearance_level, is_root FROM employees WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'employee_id': user['employee_id'],
        'username': user['username'],
        'email': user['email'],
        'department': user['department'],
        'clearance_level': session.get('clearance_level', user['clearance_level']),
        'is_root': session.get('is_root', user['is_root'])
    })

@app.route('/api/elevate', methods=['POST'])
@login_required
def elevate_privileges():
    data = request.get_json()
    target_level = data.get('level', 1)
    
    current_level = session.get('clearance_level', 1)

    if current_level < 3:
        return jsonify({'error': 'Level 3 clearance required'}), 403
    
    if target_level <= current_level:
        return jsonify({'error': 'Cannot downgrade or maintain same level'}), 400
    
    if target_level - current_level > 1:
        return jsonify({'error': 'Can only elevate by one level at a time'}), 400
    
    required_approvals = 1
    provided_approvals = list(dict.fromkeys(data.get('approvals', [])))
    
    if len(provided_approvals) < required_approvals:
        return jsonify({'error': f'Requires {required_approvals} approval(s)'}), 400
    
    conn = get_db()
    
    valid_approvals = 0
    for approval in provided_approvals:
        approver = conn.execute(
            'SELECT clearance_level FROM employees WHERE employee_id = ?',
            (approval,)
        ).fetchone()
        
        if approver and approver['clearance_level'] >= target_level:
            valid_approvals += 1
    
    if valid_approvals >= required_approvals:
        new_is_root = 1 if target_level == 5 else session.get('is_root', 0)
        session['clearance_level'] = target_level
        session['is_root'] = new_is_root
        
        conn.execute(
            'INSERT INTO access_logs (employee_id, action, ip_address) VALUES (?, ?, ?)',
            (session['employee_id'], f'privilege_elevation_to_level_{target_level}', request.remote_addr)
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'new_clearance_level': target_level
        })
    
    conn.close()
    return jsonify({'error': 'Invalid approvals'}), 400

@app.route('/api/root/decrypt', methods=['POST'])
@root_required
def decrypt_flag():
    data = request.get_json()
    encrypted = data.get('data', '')
    provided_key = data.get('key', '')
    
    if not encrypted:
        return jsonify({'error': 'No data provided'}), 400
    if not provided_key:
        return jsonify({'error': 'Decryption key required'}), 400
    
    try:
        with open(os.path.join('uploads', 'private', 'flag.enc'), 'r') as flag_file:
            expected = flag_file.read().strip()

        # Require exact ciphertext captured from Stage 3.
        if not hmac.compare_digest(encrypted.strip(), expected):
            return jsonify({'error': 'Decryption failed'}), 400
        if not hmac.compare_digest(provided_key.strip(), DECRYPT_KEY):
            return jsonify({'error': 'Decryption failed'}), 400

        identity = request.headers.get('X-CTF-Identity', '').strip().lower()
        mapped_flag = IDENTITY_FLAGS.get(identity, DECOY_FLAG)
        return jsonify({'decrypted': mapped_flag})
    except:
        return jsonify({'error': 'Decryption failed'}), 400

@app.route('/api/root/key-fragment', methods=['GET'])
@root_required
def root_key_fragment():
    return jsonify({'fragment': DECRYPT_KEY_PART3})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
