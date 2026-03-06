import sqlite3
import hashlib
import os
import shutil
from dotenv import load_dotenv

load_dotenv()

def require_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f'Missing required environment variable: {name}')
    return value

DB_PATH = os.getenv('DATABASE', 'ecorp.db')
FLAG_KEY = require_env('FLAG_KEY')
ROOT_PASSWORD = require_env('ROOT_PASSWORD')
FLAG_ARTIFACT = os.getenv('FLAG_ARTIFACT', 'ecorp_root_artifact_v1')
DECRYPT_KEY_PART1 = require_env('DECRYPT_KEY_PART1')
DECRYPT_KEY_PART2 = require_env('DECRYPT_KEY_PART2')
DECRYPT_KEY_PART3 = require_env('DECRYPT_KEY_PART3')
UPLOADS_DIR = 'uploads'
PUBLIC_UPLOADS_DIR = os.path.join(UPLOADS_DIR, 'public')
PRIVATE_UPLOADS_DIR = os.path.join(UPLOADS_DIR, 'private')

def keystream(secret, length):
    output = b''
    counter = 0
    while len(output) < length:
        output += hashlib.sha256(f'{secret}:{counter}'.encode()).digest()
        counter += 1
    return output[:length]

def encrypt_flag(flag):
    data = flag.encode()
    stream = keystream(FLAG_KEY, len(data))
    return bytes(a ^ b for a, b in zip(data, stream)).hex()

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    if os.path.isdir(UPLOADS_DIR):
        shutil.rmtree(UPLOADS_DIR)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            department TEXT NOT NULL,
            clearance_level INTEGER DEFAULT 1,
            is_root INTEGER DEFAULT 0,
            two_factor_enabled INTEGER DEFAULT 1,
            two_factor_secret TEXT,
            session_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            clearance_required INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    employees_data = [
        ('EMP001', 'angela.moss', 'allsafe2015', 'angela.moss@ecorp.com', 'Cybersecurity', 2, 0, 1, '234567'),
        ('EMP002', 'tyrell.wellick', 'joanna<3', 'tyrell.wellick@ecorp.com', 'CTO Office', 3, 0, 1, '000000'),
        ('EMP003', 'elliot.alderson', 'daem0n', 'elliot.alderson@ecorp.com', 'IT Security', 2, 0, 1, '456789'),
        ('EMP004', 'price.phillip', 'ecorp_ceo_1', 'phillip.price@ecorp.com', 'Executive', 4, 0, 1, '567890'),
        ('EMP005', 'guest', 'guest123', 'guest@ecorp.com', 'Visitor', 1, 0, 0, None),
    ]
    
    for emp in employees_data:
        cursor.execute(
            'INSERT INTO employees (employee_id, username, password, email, department, clearance_level, is_root, two_factor_enabled, two_factor_secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            emp
        )
    
    cursor.execute(
        'INSERT INTO employees (employee_id, username, password, email, department, clearance_level, is_root, two_factor_enabled, two_factor_secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        ('ROOT', 'root', ROOT_PASSWORD, 'root@ecorp.internal', 'System', 5, 1, 0, None)
    )
    
    documents_data = [
        ('merger_proposal.pdf', 'uploads/public/merger_proposal.pdf', 2),
        ('financial_q3.xlsx', 'uploads/public/financial_q3.xlsx', 3),
        ('security_audit.pdf', 'uploads/public/security_audit.pdf', 2),
        ('board_meeting_notes.txt', 'uploads/public/board_meeting_notes.txt', 3),
    ]
    
    for doc in documents_data:
        cursor.execute(
            'INSERT INTO documents (filename, filepath, clearance_required, uploaded_by) VALUES (?, ?, ?, ?)',
            (doc[0], doc[1], doc[2], 'system')
        )
    
    encrypted_flag = encrypt_flag(FLAG_ARTIFACT)
    
    os.makedirs(PUBLIC_UPLOADS_DIR, exist_ok=True)
    os.makedirs(PRIVATE_UPLOADS_DIR, exist_ok=True)
    with open(os.path.join(PRIVATE_UPLOADS_DIR, 'flag.enc'), 'w') as f:
        f.write(encrypted_flag)
    with open(os.path.join(PRIVATE_UPLOADS_DIR, '.part2.key'), 'w') as f:
        f.write(DECRYPT_KEY_PART2)
    
    with open(os.path.join(PUBLIC_UPLOADS_DIR, 'merger_proposal.pdf'), 'w') as f:
        f.write('E Corp Merger Proposal - Confidential\nThis document contains sensitive merger information.')
    
    with open(os.path.join(PUBLIC_UPLOADS_DIR, 'security_audit.pdf'), 'w') as f:
        f.write('Security Audit Report Q3 2015\nMultiple vulnerabilities detected in employee portal.')

    with open(os.path.join(PUBLIC_UPLOADS_DIR, 'financial_q3.xlsx'), 'w') as f:
        f.write('Quarter,Revenue,Forecast\nQ3,18400000000,19000000000')

    with open(os.path.join(PUBLIC_UPLOADS_DIR, 'board_meeting_notes.txt'), 'w') as f:
        f.write('Board Notes:\n- Privilege elevation approvals remain manual.\n- Root decryption service restricted.\n- Key material is distributed through internal out-of-band channels.')
    
    cursor.execute(
        "INSERT INTO system_config (key, value) VALUES ('maintenance_mode', '0')"
    )
    
    cursor.execute(
        "INSERT INTO system_config (key, value) VALUES ('debug_enabled', '0')"
    )

    cursor.execute(
        "INSERT INTO system_config (key, value) VALUES ('kms_shard_alpha', ?)",
        (DECRYPT_KEY_PART1,)
    )
    
    conn.commit()
    conn.close()
    
    print("E-Corp database initialized successfully!")
    print("\nAvailable credentials:")
    print("  guest / guest123 (Level 1 - Start here)")
    print("\nObjective: Become root user and retrieve the flag")

if __name__ == '__main__':
    init_db()
