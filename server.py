#!/usr/bin/env python3
"""Daftna   small dependency-free university resource website.
Start: python server.py (Python 3.10+). SQLite database is created on first run.
"""
from __future__ import annotations
import base64, binascii, hashlib, hmac, html, json, mimetypes, os, re, secrets, shutil, socket, sqlite3, subprocess, sys, tempfile, threading, time, uuid, zipfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
UPLOADS = ROOT / 'uploads'
WEB = ROOT / 'web'
DB = DATA / 'mis_students.sqlite3'
LEGACY_DB = DATA / 'daftna.sqlite3'
CREDS = DATA / 'initial_admin_credentials.txt'
SECURITY_SECRET_FILE = DATA / '.security_secret'
BACKUPS = DATA / 'backups'
PDF_CACHE = DATA / 'pdf_cache'
for directory in (DATA, UPLOADS, BACKUPS, PDF_CACHE):
    directory.mkdir(parents=True, exist_ok=True)
    try: os.chmod(directory, 0o700)
    except OSError: pass
if not DB.exists() and LEGACY_DB.exists():
    LEGACY_DB.replace(DB)
MAX_FILE = 30 * 1024 * 1024
PASSWORD_ITERS = 600_000
SESSION_TTL = 8 * 3600
SESSION_IDLE = 90 * 60
DANGEROUS_EXTENSIONS = {'.exe','.com','.scr','.msi','.dll','.sys','.bat','.cmd','.ps1','.vbs','.vbe','.jscript','.wsf','.wsh','.hta','.jar','.apk','.app','.dmg','.pkg','.deb','.rpm','.elf','.so','.dylib','.php','.phtml','.phar','.cgi','.pl','.py','.pyw','.rb','.sh','.bash','.zsh'}
MAX_JSON = 42 * 1024 * 1024
ALLOWED_ENTITIES = {'subjects', 'announcements', 'exams', 'lectures', 'explanations'}
REQUIRED_FIELDS = {
    'subjects': ['title_ar'], 'announcements': ['title', 'body'],
    'exams': ['subject_id', 'title', 'exam_date'],
    'lectures': ['subject_id', 'title', 'section'],
    'explanations': ['subject_id', 'title'],
}
FIELDS = {
    'subjects': ['title_ar', 'title_en', 'description', 'color', 'sort_order', 'is_published'],
    'announcements': ['title', 'body', 'source', 'pinned', 'is_active', 'expires_at'],
    'exams': ['subject_id', 'title', 'exam_date', 'notes', 'is_active'],
    'lectures': ['subject_id', 'title', 'section', 'number', 'description'],
    'explanations': ['subject_id', 'lecture_id', 'number', 'title', 'summary', 'content', 'is_published'],
}
RATE = {}
RATE_LOCK = threading.Lock()

def find_chromium_browser():
    candidates=[]
    env_browser=os.getenv('MIS_BROWSER','').strip()
    if env_browser:candidates.append(env_browser)
    if os.name=='nt':
        roots=[os.getenv('PROGRAMFILES',''),os.getenv('PROGRAMFILES(X86)',''),os.getenv('LOCALAPPDATA','')]
        rels=[
            r'Microsoft\Edge\Application\msedge.exe',
            r'Google\Chrome\Application\chrome.exe',
            r'Chromium\Application\chrome.exe',
        ]
        for root in roots:
            if root:
                for rel in rels:candidates.append(str(Path(root)/rel))
    for name in ('msedge','microsoft-edge','google-chrome','google-chrome-stable','chromium','chromium-browser','chrome'):
        found=shutil.which(name)
        if found:candidates.append(found)
    for candidate in candidates:
        if candidate and Path(candidate).is_file():return candidate
    return None

def inject_print_css(raw):
    style=(b'<style id="mis-pdf-print-style">@media print{'
           b'html,body{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}'
           b'body{margin:0!important}*{animation:none!important;transition:none!important}}'
           b'@page{margin:0}</style>')
    if re.search(br'</head\s*>',raw,re.I):
        return re.sub(br'</head\s*>',style+b'</head>',raw,count=1,flags=re.I)
    return style+raw

def safe_pdf_name(value):
    stem=Path(str(value or 'explanation')).stem.strip() or 'explanation'
    stem=re.sub(r'[\\/:*?"<>|]+','-',stem)[:120].strip(' .-') or 'explanation'
    return stem+'.pdf'


def connection():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA busy_timeout=15000')
    c.execute('PRAGMA trusted_schema=OFF')
    c.execute('PRAGMA secure_delete=ON')
    return c

def security_secret():
    if not SECURITY_SECRET_FILE.exists():
        SECURITY_SECRET_FILE.write_bytes(secrets.token_bytes(32))
        try: os.chmod(SECURITY_SECRET_FILE,0o600)
        except OSError: pass
    return SECURITY_SECRET_FILE.read_bytes()

def opaque_client_key(value):
    return hmac.new(security_secret(), str(value or '').encode('utf-8','ignore'), hashlib.sha256).hexdigest()

def user_agent_hash(value):
    return hashlib.sha256(str(value or '').encode('utf-8','ignore')).hexdigest()

def backup_database():
    if not DB.exists() or DB.stat().st_size == 0:
        return
    stamp=datetime.now().strftime('%Y%m%d-%H%M%S')
    target=BACKUPS/f'mis-{stamp}.sqlite3'
    try:
        src=sqlite3.connect(DB); dst=sqlite3.connect(target)
        with dst: src.backup(dst)
        src.close(); dst.close()
        try: os.chmod(target,0o600)
        except OSError: pass
        backups=sorted(BACKUPS.glob('mis-*.sqlite3'), key=lambda x:x.stat().st_mtime, reverse=True)
        for old in backups[5:]: old.unlink(missing_ok=True)
    except (sqlite3.Error,OSError):
        try: target.unlink(missing_ok=True)
        except OSError: pass


def items(c, sql, params=()):
    return [dict(row) for row in c.execute(sql, params).fetchall()]


def row_role(row):
    if row is None: return 'admin'
    try: return row['role'] or 'admin'
    except (KeyError, IndexError, TypeError): return 'admin'


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def audit(c, admin_id, action, target=''):
    c.execute('INSERT INTO audit_log(admin_id,action,target) VALUES(?,?,?)',(admin_id,action,str(target)[:240]))
    c.execute('DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 5000)')

def login_allowed(c, client_key, username):
    row=c.execute('SELECT * FROM login_attempts WHERE client_key=? AND username=?',(client_key,username)).fetchone()
    return not row or int(row['blocked_until'] or 0) <= int(time.time())

def register_login_failure(c, client_key, username):
    t=int(time.time())
    row=c.execute('SELECT * FROM login_attempts WHERE client_key=? AND username=?',(client_key,username)).fetchone()
    failures=1 if not row or t-int(row['last_at'] or 0)>1800 else int(row['failures'] or 0)+1
    blocked=t+(3600 if failures>=10 else 900 if failures>=5 else 0)
    c.execute('''INSERT INTO login_attempts(client_key,username,failures,last_at,blocked_until) VALUES(?,?,?,?,?)
                 ON CONFLICT(client_key,username) DO UPDATE SET failures=excluded.failures,last_at=excluded.last_at,blocked_until=excluded.blocked_until''',
              (client_key,username,failures,t,blocked))
    return blocked

def clear_login_failures(c, client_key, username):
    c.execute('DELETE FROM login_attempts WHERE client_key=? AND username=?',(client_key,username))


def password_hash(password, salt=None, iterations=PASSWORD_ITERS):
    salt = salt or secrets.token_bytes(18)
    value = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f'pbkdf2_sha256${iterations}${salt.hex()}${value.hex()}'

def check_password(password, stored):
    try:
        if stored.startswith('pbkdf2_sha256$'):
            _, rounds, salt_hex, value_hex = stored.split('$',3)
            value=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),bytes.fromhex(salt_hex),int(rounds)).hex()
            return hmac.compare_digest(value,value_hex)
        # Backward-compatible verifier for older project copies.
        salt_hex,value_hex=stored.split(':',1)
        value=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),bytes.fromhex(salt_hex),310000).hex()
        return hmac.compare_digest(value,value_hex)
    except (ValueError,AttributeError,OverflowError):
        return False

def password_needs_rehash(stored):
    try:
        return not stored.startswith(f'pbkdf2_sha256${PASSWORD_ITERS}$')
    except AttributeError:
        return True

def validate_password_strength(password, username=''):
    if len(password) < 14:
        raise ValueError('كلمة المرور لازم تكون 14 حرفاً على الأقل')
    if len(password) > 250:
        raise ValueError('كلمة المرور طويلة جداً')
    if username and username.lower() in password.lower():
        raise ValueError('كلمة المرور لا يصير تحتوي اسم المستخدم')
    groups=sum(bool(re.search(p,password)) for p in (r'[a-z]',r'[A-Z]',r'\d',r'[^A-Za-z0-9]'))
    if groups < 3:
        raise ValueError('استخدم مزيج حروف كبيرة وصغيرة وأرقام أو رموز')
    if password.lower() in {'password123456!','admin123456789!','qwerty12345678!'}:
        raise ValueError('كلمة المرور ضعيفة جداً')



def initialize():
    first_install = not DB.exists()
    if not first_install: backup_database()
    with connection() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires_at INTEGER NOT NULL,issued_at INTEGER DEFAULT 0,last_seen INTEGER DEFAULT 0,ua_hash TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS subjects(id INTEGER PRIMARY KEY,title_ar TEXT NOT NULL,title_en TEXT DEFAULT '',description TEXT DEFAULT '',color TEXT DEFAULT '#7C66FF',sort_order INTEGER DEFAULT 0,is_published INTEGER NOT NULL DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS lectures(id INTEGER PRIMARY KEY,subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,title TEXT NOT NULL,section TEXT NOT NULL CHECK(section IN ('theory','practical')),number INTEGER DEFAULT 1,description TEXT DEFAULT '',file_path TEXT DEFAULT '',file_name TEXT DEFAULT '',file_size INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS explanations(id INTEGER PRIMARY KEY,subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,lecture_id INTEGER REFERENCES lectures(id) ON DELETE SET NULL,number INTEGER DEFAULT 1,title TEXT NOT NULL,summary TEXT DEFAULT '',content TEXT NOT NULL DEFAULT '',file_path TEXT DEFAULT '',file_name TEXT DEFAULT '',file_size INTEGER DEFAULT 0,file_mime TEXT DEFAULT '',is_published INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY,title TEXT NOT NULL,body TEXT NOT NULL,source TEXT DEFAULT '',pinned INTEGER DEFAULT 0,is_active INTEGER DEFAULT 1,expires_at TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY,subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,title TEXT NOT NULL,exam_date TEXT NOT NULL,notes TEXT DEFAULT '',is_active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY,name TEXT NOT NULL,topic TEXT NOT NULL,message TEXT NOT NULL,status TEXT DEFAULT 'new' CHECK(status IN ('new','done')),created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS login_attempts(client_key TEXT NOT NULL,username TEXT NOT NULL,failures INTEGER DEFAULT 0,last_at INTEGER DEFAULT 0,blocked_until INTEGER DEFAULT 0,PRIMARY KEY(client_key,username));
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,action TEXT NOT NULL,target TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS visits(id INTEGER PRIMARY KEY,visited_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS idx_lecture_subject ON lectures(subject_id);
        CREATE INDEX IF NOT EXISTS idx_exp_subject ON explanations(subject_id);
        CREATE INDEX IF NOT EXISTS idx_exam_subject ON exams(subject_id);
        CREATE INDEX IF NOT EXISTS idx_visits_time ON visits(visited_at);
        ''')
        existing_cols={r['name'] for r in c.execute("PRAGMA table_info(explanations)")}
        for col,decl in (
            ('number','INTEGER DEFAULT 1'),
            ('file_path',"TEXT DEFAULT ''"),
            ('file_name',"TEXT DEFAULT ''"),
            ('file_size','INTEGER DEFAULT 0'),
            ('file_mime',"TEXT DEFAULT ''"),
        ):
            if col not in existing_cols:
                c.execute(f'ALTER TABLE explanations ADD COLUMN {col} {decl}')
        session_cols={r['name'] for r in c.execute("PRAGMA table_info(sessions)")}
        for col,decl in (('issued_at','INTEGER DEFAULT 0'),('last_seen','INTEGER DEFAULT 0'),('ua_hash',"TEXT DEFAULT ''")):
            if col not in session_cols:
                c.execute(f'ALTER TABLE sessions ADD COLUMN {col} {decl}')
        admin_cols={r['name'] for r in c.execute("PRAGMA table_info(admins)")}
        if 'role' not in admin_cols:
            c.execute("ALTER TABLE admins ADD COLUMN role TEXT DEFAULT 'admin'")
            c.execute("UPDATE admins SET role='admin' WHERE role IS NULL OR role=''")
        c.execute('DELETE FROM sessions WHERE expires_at<=?',(int(time.time()),))
        c.execute('DELETE FROM login_attempts WHERE last_at<?',(int(time.time())-7*86400,))
        if c.execute('SELECT COUNT(*) FROM admins').fetchone()[0] == 0:
            preset=os.getenv('MIS_ADMIN_PASSWORD',os.getenv('DAFTNA_ADMIN_PASSWORD',''))
            try:
                if preset: validate_password_strength(preset,'admin')
                password=preset if preset else secrets.token_urlsafe(22)+'!Aa7'
            except ValueError:
                password=secrets.token_urlsafe(22)+'!Aa7'
            c.execute('INSERT INTO admins(username,password_hash) VALUES(?,?)',('admin',password_hash(password)))
            CREDS.write_text(f'Username: admin\nPassword: {password}\nChange this password immediately from the admin dashboard.\n',encoding='utf-8')
            try: os.chmod(CREDS,0o600)
            except OSError:pass
            print('\n'+'='*58+'\n FIRST RUN   ADMIN LOGIN\n Username: admin\n Password: '+password+'\n Credentials saved at data/initial_admin_credentials.txt\n'+'='*58+'\n',flush=True)
    try:
        if DB.exists(): os.chmod(DB,0o600)
        for f in UPLOADS.iterdir():
            if f.is_file(): os.chmod(f,0o600)
    except OSError: pass


def filtered_public(c):
    return {
      'subjects': items(c,'SELECT * FROM subjects WHERE is_published=1 ORDER BY sort_order,id'),
      'lectures': items(c,'SELECT l.* FROM lectures l JOIN subjects s ON s.id=l.subject_id WHERE s.is_published=1 ORDER BY l.number,l.id'),
      'explanations': items(c,'SELECT e.* FROM explanations e JOIN subjects s ON s.id=e.subject_id WHERE s.is_published=1 AND e.is_published=1 ORDER BY e.subject_id,e.number,e.id'),
      'announcements': items(c,"SELECT * FROM announcements WHERE is_active=1 AND (expires_at='' OR expires_at IS NULL OR expires_at>=date('now')) ORDER BY pinned DESC,id DESC"),
      'exams': items(c,'SELECT e.* FROM exams e JOIN subjects s ON s.id=e.subject_id WHERE e.is_active=1 AND s.is_published=1 ORDER BY e.exam_date'),
    }


def safe_text(obj, key, maxlen=2000, default=''):
    val=obj.get(key,default)
    if val is None:return default
    if not isinstance(val,(str,int,float)):raise ValueError(f'القيمة غير صحيحة: {key}')
    val=str(val).strip()
    if len(val)>maxlen:raise ValueError(f'القيمة طويلة جداً: {key}')
    return val


def number(obj,key,default=0):
    try:return int(obj.get(key,default) or 0)
    except (TypeError,ValueError):raise ValueError(f'رقم غير صحيح: {key}')


def validate_entity(c,entity,payload,editing=False):
    if not isinstance(payload,dict):raise ValueError('البيانات غير صالحة')
    d={}
    for key in FIELDS[entity]:
        if key not in payload:continue
        if key in ('subject_id','lecture_id','sort_order','is_published','pinned','is_active','number','correct_index'):
            d[key]=None if key=='lecture_id' and payload.get(key) in (None,'',0,'0') else number(payload,key)
        elif key=='options_json': d[key]=safe_text(payload,key,3000)
        else:d[key]=safe_text(payload,key,16000 if key=='content' else 3000)
    if not editing:
        for key in REQUIRED_FIELDS[entity]:
            if not str(d.get(key,'')).strip():raise ValueError(f'الحقل مطلوب: {key}')
    if entity=='lectures' and 'section' in d and d['section'] not in ('theory','practical'):raise ValueError('نوع المحاضرة غير صحيح')
    for field in ('subject_id','lecture_id'):
        if field in d and d[field]:
            table='subjects' if field=='subject_id' else 'lectures'
            if not c.execute(f'SELECT id FROM {table} WHERE id=?',(d[field],)).fetchone():raise ValueError(f'العنصر المرتبط غير موجود: {field}')
    if entity=='explanations' and d.get('lecture_id'):
        lecture=c.execute('SELECT subject_id FROM lectures WHERE id=?',(d['lecture_id'],)).fetchone()
        subject=d.get('subject_id')
        if lecture and subject and lecture['subject_id']!=subject:raise ValueError('المحاضرة لا تتبع المادة المختارة')
    if entity=='exams' and 'exam_date' in d:
        try:datetime.fromisoformat(d['exam_date'])
        except ValueError:raise ValueError('تاريخ الامتحان غير صحيح')
    if entity=='subjects' and 'color' in d and not re.fullmatch(r'#[0-9a-fA-F]{6}',d['color']):raise ValueError('لون المادة غير صحيح')
    if entity=='announcements' and d.get('expires_at'):
        try:datetime.strptime(d['expires_at'],'%Y-%m-%d')
        except ValueError:raise ValueError('تاريخ انتهاء التبليغ غير صحيح')
    return d


def store_file(payload):
    original=safe_text(payload,'file_name',220)
    data=payload.get('file_base64','')
    if not original or not data:raise ValueError('يرجى اختيار ملف')
    ext=Path(original).suffix.lower()
    if ext in DANGEROUS_EXTENSIONS:raise ValueError('صيغة الملف مرفوضة لأسباب أمنية')
    if len(data)>MAX_FILE*4//3+12:raise ValueError('الملف أكبر من 30 ميغابايت')
    try:raw=base64.b64decode(data,validate=True)
    except (binascii.Error,ValueError):raise ValueError('تعذر قراءة الملف')
    if not raw or len(raw)>MAX_FILE:raise ValueError('الملف فارغ أو أكبر من 30 ميغابايت')
    if raw.startswith((b'MZ',b'\x7fELF',b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xca\xfe\xba\xbe')):raise ValueError('الملف التنفيذي مرفوض لأسباب أمنية')
    if ext=='.pdf' and not raw.startswith(b'%PDF-'):raise ValueError('ملف PDF غير صالح')
    if ext in ('.png',) and not raw.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('ملف صورة غير صالح')
    if ext in ('.jpg','.jpeg') and not raw.startswith(b'\xff\xd8'):raise ValueError('ملف صورة غير صالح')
    stored=uuid.uuid4().hex+ext
    target=UPLOADS/stored
    target.write_bytes(raw)
    try: os.chmod(target,0o600)
    except OSError: pass
    return {'file_path':stored,'file_name':Path(original).name,'file_size':len(raw),'file_mime':mimetypes.guess_type(original)[0] or 'application/octet-stream'}


def rate_check(ip,key,limit,window):
    t=time.time()
    with RATE_LOCK:
        if len(RATE)>3000:
            for old in list(RATE):
                RATE[old]=[v for v in RATE[old] if t-v<3600]
                if not RATE[old]:RATE.pop(old,None)
        k=(ip,key);arr=[v for v in RATE.get(k,[]) if t-v<window]
        if len(arr)>=limit:return False
        arr.append(t);RATE[k]=arr
        return True

class Handler(BaseHTTPRequestHandler):
    server_version='MIS'
    sys_version=''
    def version_string(self): return 'MIS'
    def setup(self):
        super().setup()
        try: self.request.settimeout(20)
        except OSError: pass
    def is_https(self):
        return self.headers.get('X-Forwarded-Proto','').lower()=='https' or getattr(self.server,'force_secure',False)
    def log_message(self,format,*args):
        print('%s %s'%(self.address_string(),format%args),flush=True)
    def headers_common(self,content_type='application/json; charset=utf-8',length=None,csp=None,cache=None):
        self.send_header('Content-Type',content_type)
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Frame-Options','SAMEORIGIN')
        self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()')
        self.send_header('Cross-Origin-Opener-Policy','same-origin')
        self.send_header('Cross-Origin-Resource-Policy','same-origin')
        self.send_header('X-Permitted-Cross-Domain-Policies','none')
        self.send_header('X-DNS-Prefetch-Control','off')
        self.send_header('Origin-Agent-Cluster','?1')
        if cache:
            self.send_header('Cache-Control',cache)
            self.send_header('Expires','Thu, 31 Dec 2099 23:59:59 GMT')
        else:
            self.send_header('Cache-Control','no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Pragma','no-cache')
            self.send_header('Expires','0')
        self.send_header('Content-Security-Policy',csp or "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests")
        if self.is_https():self.send_header('Strict-Transport-Security','max-age=31536000; includeSubDomains')
        if length is not None:self.send_header('Content-Length',str(length))
    def send_json(self,obj,status=200,cookie=None):
        data=json.dumps(obj,ensure_ascii=False,default=str).encode('utf-8')
        self.send_response(status);self.headers_common(length=len(data))
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(data)
    def error_json(self,status,message):self.send_json({'error':message},status)
    def read_json(self):
        if self.headers.get('Transfer-Encoding'):raise ValueError('طريقة نقل الطلب غير مدعومة')
        if self.headers.get('Content-Type','').split(';')[0].strip()!='application/json':raise ValueError('يجب إرسال JSON')
        try:length=int(self.headers.get('Content-Length','0'))
        except ValueError:raise ValueError('حجم الطلب غير صحيح')
        if length<0 or length>MAX_JSON:raise ValueError('حجم الطلب كبير جداً')
        try:return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError,UnicodeDecodeError):raise ValueError('البيانات غير صالحة')
    def session(self,c):
        cookie=SimpleCookie()
        try:cookie.load(self.headers.get('Cookie',''))
        except Exception:return None
        token=cookie.get('mis_session') or cookie.get('daftna_session')
        if not token:return None
        token=token.value
        if not re.fullmatch(r'[a-f0-9]{64}',token):return None
        digest=hashlib.sha256(token.encode()).hexdigest(); t=int(time.time())
        row=c.execute('SELECT sessions.*,admins.username,admins.role FROM sessions JOIN admins ON admins.id=sessions.admin_id WHERE token_hash=? AND expires_at>?',(digest,t)).fetchone()
        if not row:return None
        current_ua=user_agent_hash(self.headers.get('User-Agent',''))
        if row['ua_hash'] and not hmac.compare_digest(row['ua_hash'],current_ua):
            c.execute('DELETE FROM sessions WHERE token_hash=?',(digest,));return None
        if row['last_seen'] and t-int(row['last_seen'])>SESSION_IDLE:
            c.execute('DELETE FROM sessions WHERE token_hash=?',(digest,));return None
        if not row['last_seen'] or t-int(row['last_seen'])>300:
            c.execute('UPDATE sessions SET last_seen=? WHERE token_hash=?',(t,digest))
        return row
    def require_admin(self,c):
        s=self.session(c)
        if not s:return None
        if not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),s['csrf']):return None
        return s
    def valid_origin(self):
        origin=self.headers.get('Origin')
        if not origin:return True # non-browser clients also need CSRF token for admin
        expected=self.headers.get('Host','')
        try:return urlsplit(origin).netloc==expected and urlsplit(origin).scheme in ('http','https')
        except ValueError:return False
    def serve_static(self,path,query=''):
        if path=='/':path='/index.html'
        name=path.lstrip('/')
        if name not in ('index.html','app.js','styles.css','favicon.svg','manifest.webmanifest','mis-logo.png','service-worker.js','icon-192.png','icon-512.png'):
            self.send_error(404);return
        p=WEB/name
        if not p.exists():self.send_error(404);return
        raw=p.read_bytes()
        ctype=mimetypes.guess_type(p.name)[0] or 'application/octet-stream'
        if p.name.endswith('.js'):ctype='application/javascript'
        versioned='v=' in query and name not in ('index.html','service-worker.js')
        cache='public, max-age=31536000, immutable' if versioned else None
        self.send_response(200);self.headers_common(ctype+'; charset=utf-8',len(raw),cache=cache);self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        parts=urlsplit(self.path)
        path=parts.path
        try:
            if path=='/api/public':
                with connection() as c:self.send_json(filtered_public(c))
            elif path=='/api/admin/data':
                with connection() as c:
                    s=self.session(c)
                    if not s:return self.error_json(401,'يرجى تسجيل الدخول')
                    data={e:items(c,f'SELECT * FROM {e} ORDER BY id DESC') for e in ALLOWED_ENTITIES}
                    data['requests']=items(c,'SELECT * FROM requests ORDER BY id DESC')
                    stats=c.execute("""SELECT
                        SUM(CASE WHEN visited_at >= datetime('now','-1 day') THEN 1 ELSE 0 END) AS daily,
                        SUM(CASE WHEN visited_at >= datetime('now','-7 day') THEN 1 ELSE 0 END) AS weekly,
                        SUM(CASE WHEN visited_at >= datetime('now','-30 day') THEN 1 ELSE 0 END) AS monthly
                        FROM visits""").fetchone()
                    data['visit_stats']={'daily':int(stats['daily'] or 0),'weekly':int(stats['weekly'] or 0),'monthly':int(stats['monthly'] or 0)}
                    data['users']=items(c,'SELECT id,username,role FROM admins ORDER BY id')
                    self.send_json({'username':s['username'],'role':row_role(s),'csrf':s['csrf'],'data':data})
            elif path=='/api/auth/me':
                with connection() as c:
                    s=self.session(c)
                    if not s:return self.error_json(401,'غير مسجل')
                    self.send_json({'username':s['username'],'role':row_role(s),'csrf':s['csrf']})
            elif re.fullmatch(r'/api/files/\d+',path):
                lecture_id=int(path.rsplit('/',1)[-1]);self.serve_file(lecture_id,parse_qs(urlsplit(self.path).query).get('download',['0'])[0]=='1')
            elif re.fullmatch(r'/api/explanation-files/\d+',path):
                explanation_id=int(path.rsplit('/',1)[-1]);self.serve_explanation_file(explanation_id,parse_qs(urlsplit(self.path).query).get('download',['0'])[0]=='1')
            elif re.fullmatch(r'/api/explanation-preview/\d+',path):
                explanation_id=int(path.rsplit('/',1)[-1]);pdf_mode=parse_qs(urlsplit(self.path).query).get('pdf',['0'])[0]=='1';self.serve_explanation_preview(explanation_id,pdf_mode)
            elif re.fullmatch(r'/api/explanation-pdf/\d+',path):
                explanation_id=int(path.rsplit('/',1)[-1]);self.serve_explanation_pdf(explanation_id)
            elif path.startswith('/api/'):
                self.error_json(404,'المسار غير موجود')
            else:self.serve_static(path,parts.query)
        except (sqlite3.Error,OSError) as exc:
            print('SERVER ERROR:',repr(exc),file=sys.stderr);self.error_json(500,'حصل خطأ بالخادم')
    def serve_file(self,lecture_id,download):
        with connection() as c:
            r=c.execute('SELECT l.* FROM lectures l JOIN subjects s ON s.id=l.subject_id WHERE l.id=? AND s.is_published=1',(lecture_id,)).fetchone()
        if not r or not r['file_path']:return self.error_json(404,'الملف غير موجود')
        p=UPLOADS/r['file_path']
        if not p.is_file():return self.error_json(404,'الملف غير موجود')
        raw=p.read_bytes();ctype=mimetypes.guess_type(r['file_name'])[0] or 'application/octet-stream'
        if p.suffix.lower()!='.pdf':download=True
        self.send_response(200);self.headers_common(ctype,len(raw))
        self.send_header('Content-Disposition',('attachment' if download else 'inline')+"; filename*=UTF-8''"+quote(r['file_name']))
        self.end_headers();self.wfile.write(raw)
    def explanation_row(self,explanation_id):
        with connection() as c:
            return c.execute('''SELECT e.* FROM explanations e
                JOIN subjects s ON s.id=e.subject_id
                WHERE e.id=? AND e.is_published=1 AND s.is_published=1''',(explanation_id,)).fetchone()

    def serve_explanation_file(self,explanation_id,download):
        r=self.explanation_row(explanation_id)
        if not r or not r['file_path']:return self.error_json(404,'ملف الشرح غير موجود')
        p=UPLOADS/r['file_path']
        if not p.is_file():return self.error_json(404,'ملف الشرح غير موجود')
        raw=p.read_bytes()
        ctype=r['file_mime'] or mimetypes.guess_type(r['file_name'])[0] or 'application/octet-stream'
        suffix='' if 'charset=' in ctype or not ctype.startswith('text/') else '; charset=utf-8'
        html_csp=None
        active_doc=ctype.startswith('text/html') or ctype in ('image/svg+xml','application/xhtml+xml','application/xml','text/xml')
        if active_doc:
            # Keep the uploaded explanation byte-for-byte, but isolate it from the parent app/session.
            html_csp="sandbox allow-scripts allow-forms allow-modals allow-downloads; default-src https: http: data: blob:; script-src https: http: 'unsafe-inline' 'unsafe-eval' data: blob:; style-src https: http: 'unsafe-inline' data: blob:; img-src https: http: data: blob:; font-src https: http: data: blob:; media-src https: http: data: blob:; connect-src https: http: data: blob:; frame-src https: http: data: blob:; object-src 'none'; base-uri 'none'; form-action 'none';"
        self.send_response(200);self.headers_common(ctype+suffix,len(raw),html_csp)
        self.send_header('Content-Disposition',('attachment' if download else 'inline')+"; filename*=UTF-8''"+quote(r['file_name']))
        self.end_headers();self.wfile.write(raw)

    def serve_explanation_preview(self,explanation_id,pdf_mode=False):
        r=self.explanation_row(explanation_id)
        if not r or not r['file_path']:return self.error_json(404,'ملف الشرح غير موجود')
        p=UPLOADS/r['file_path']
        if not p.is_file():return self.error_json(404,'ملف الشرح غير موجود')
        ext=p.suffix.lower()
        ctype=r['file_mime'] or mimetypes.guess_type(r['file_name'])[0] or 'application/octet-stream'

        if ext in ('.html','.htm') and pdf_mode:
            raw=inject_print_css(p.read_bytes())
            html_csp="sandbox allow-scripts allow-forms allow-modals allow-downloads; default-src https: http: data: blob:; script-src https: http: 'unsafe-inline' 'unsafe-eval' data: blob:; style-src https: http: 'unsafe-inline' data: blob:; img-src https: http: data: blob:; font-src https: http: data: blob:; media-src https: http: data: blob:; connect-src https: http: data: blob:; frame-src https: http: data: blob:; object-src 'none'; base-uri 'none'; form-action 'none';"
            self.send_response(200);self.headers_common('text/html; charset=utf-8',len(raw),html_csp)
            self.send_header('Content-Disposition',"inline; filename*=UTF-8''"+quote(r['file_name']))
            self.end_headers();self.wfile.write(raw);return

        # Explanation files are never transformed or text-extracted for the on-screen preview.
        # HTML is returned as uploaded so its own CSS and JavaScript keep working.
        browser_inline = (
            ext in ('.html','.htm','.pdf','.txt','.md','.css','.js','.json','.xml','.csv','.svg')
            or ctype.startswith(('image/','audio/','video/','text/'))
        )
        if browser_inline:
            return self.serve_explanation_file(explanation_id,False)

        page=(f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
              '<meta name="viewport" content="width=device-width,initial-scale=1">'
              '<style>html,body{margin:0;min-height:100%;background:#f5f6f4;color:#14202a;font-family:Arial,sans-serif}'
              'body{padding:18px;box-sizing:border-box}.fallback{max-width:650px;margin:12vh auto;background:white;border:1px solid #d6dcd8;padding:28px;text-align:center;line-height:2}'
              'a{display:inline-block;margin-top:12px;padding:10px 16px;background:#176d91;color:white;text-decoration:none;font-weight:700}</style>'
              '</head><body><div class="fallback"><h2>هذه الصيغة لا يعرضها المتصفح مباشرة</h2>'
              '<p>الملف الأصلي محفوظ بدون تحويل أو استخراج للنصوص. يمكنك تنزيله وفتحه بالبرنامج المخصص له.</p>'
              f'<a href="/api/explanation-files/{explanation_id}?download=1">تنزيل الملف الأصلي</a>'
              '</div></body></html>').encode('utf-8')
        self.send_response(200)
        self.headers_common('text/html; charset=utf-8',len(page),"default-src 'none'; style-src 'unsafe-inline';")
        self.end_headers();self.wfile.write(page)

    def serve_explanation_pdf(self,explanation_id):
        r=self.explanation_row(explanation_id)
        if not r or not r['file_path']:return self.error_json(404,'ملف الشرح غير موجود')
        source=UPLOADS/r['file_path']
        if not source.is_file():return self.error_json(404,'ملف الشرح غير موجود')
        ext=source.suffix.lower()
        if ext=='.pdf':
            raw=source.read_bytes();name=safe_pdf_name(r['file_name'])
            self.send_response(200);self.headers_common('application/pdf',len(raw))
            self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(name))
            self.end_headers();self.wfile.write(raw);return
        if ext not in ('.html','.htm'):
            return self.serve_explanation_file(explanation_id,True)
        browser=find_chromium_browser()
        if not browser:
            return self.error_json(503,'تحويل HTML إلى PDF يحتاج Microsoft Edge أو Google Chrome أو Chromium مثبت على الجهاز')
        stamp=str(source.stat().st_mtime_ns)
        cached=PDF_CACHE/f'explanation-{explanation_id}-{stamp}.pdf'
        if not cached.is_file() or cached.stat().st_size<1000:
            for old in PDF_CACHE.glob(f'explanation-{explanation_id}-*.pdf'):
                try:old.unlink()
                except OSError:pass
            port=self.server.server_address[1]
            url=f'http://127.0.0.1:{port}/api/explanation-preview/{explanation_id}?pdf=1'
            success=False
            profile_dir=Path(tempfile.mkdtemp(prefix='mis-pdf-profile-',dir=str(DATA)))
            try:
                common=[
                    '--disable-gpu','--disable-dev-shm-usage','--disable-extensions','--disable-sync',
                    '--disable-background-networking','--no-first-run','--no-default-browser-check',
                    '--hide-scrollbars','--no-pdf-header-footer','--run-all-compositor-stages-before-draw',
                    '--virtual-time-budget=5000','--window-size=1440,1800',
                    f'--user-data-dir={profile_dir}',f'--print-to-pdf={cached}',url
                ]
                if os.name!='nt':common.insert(0,'--no-sandbox')
                attempts=[['--headless=new',*common],['--headless',*common]]
                for args in attempts:
                    try:
                        proc=subprocess.run([browser,*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=28,check=False)
                        if proc.returncode==0 and cached.is_file() and cached.stat().st_size>1000:
                            success=True;break
                    except (OSError,subprocess.TimeoutExpired):
                        pass
            finally:
                shutil.rmtree(profile_dir,ignore_errors=True)
            if not success:
                try:cached.unlink(missing_ok=True)
                except OSError:pass
                return self.error_json(500,'تعذر إنشاء PDF من ملف HTML. تأكد من أن المتصفح مثبت ويعمل بصورة طبيعية')
        raw=cached.read_bytes();name=safe_pdf_name(r['file_name'])
        self.send_response(200);self.headers_common('application/pdf',len(raw))
        self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(name))
        self.end_headers();self.wfile.write(raw)
    def do_POST(self):self.mutate('POST')
    def do_PATCH(self):self.mutate('PATCH')
    def do_DELETE(self):self.mutate('DELETE')
    def mutate(self,method):
        path=urlsplit(self.path).path
        if not self.valid_origin():return self.error_json(403,'مصدر الطلب غير مسموح')
        try:
            with connection() as c:
                if path=='/api/visit' and method=='POST':
                    client_key=opaque_client_key(self.client_address[0])
                    if not rate_check(client_key,'visit',120,3600):return self.send_json({'ok':True})
                    c.execute('INSERT INTO visits DEFAULT VALUES');c.commit();return self.send_json({'ok':True},201)
                if path=='/api/auth/login' and method=='POST':
                    ip_key=opaque_client_key(self.client_address[0])
                    if not rate_check(ip_key,'login',12,900):return self.error_json(429,'محاولات كثيرة؛ جرّب لاحقاً')
                    body=self.read_json();user=safe_text(body,'username',50);pwd=safe_text(body,'password',250)
                    if not login_allowed(c,ip_key,user):return self.error_json(429,'تم إيقاف محاولات الدخول مؤقتاً؛ جرّب لاحقاً')
                    r=c.execute('SELECT * FROM admins WHERE username=?',(user,)).fetchone()
                    if not r or not check_password(pwd,r['password_hash']):
                        register_login_failure(c,ip_key,user);c.commit();time.sleep(0.35)
                        return self.error_json(401,'اسم المستخدم أو كلمة المرور غير صحيحة')
                    clear_login_failures(c,ip_key,user)
                    if password_needs_rehash(r['password_hash']):c.execute('UPDATE admins SET password_hash=? WHERE id=?',(password_hash(pwd),r['id']))
                    token=secrets.token_hex(32);csrf=secrets.token_hex(24);t=int(time.time());ua=user_agent_hash(self.headers.get('User-Agent',''))
                    c.execute('DELETE FROM sessions WHERE admin_id=? AND (expires_at<=? OR token_hash NOT IN (SELECT token_hash FROM sessions WHERE admin_id=? ORDER BY issued_at DESC LIMIT 2))',(r['id'],t,r['id']))
                    c.execute('INSERT INTO sessions(token_hash,admin_id,csrf,expires_at,issued_at,last_seen,ua_hash) VALUES(?,?,?,?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),r['id'],csrf,t+SESSION_TTL,t,t,ua))
                    audit(c,r['id'],'login_success','admin')
                    c.commit()
                    secure='; Secure' if self.is_https() else ''
                    self.send_json({'username':user,'role':row_role(r),'csrf':csrf},cookie=f'mis_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}; Priority=High{secure}');return
                if path=='/api/requests' and method=='POST':
                    client_key=opaque_client_key(self.client_address[0])
                    if not rate_check(client_key,'requests-hour',4,3600) or not rate_check(client_key,'requests-day',12,86400):return self.error_json(429,'وصلنا عدد كبير من الطلبات، جرّب بعدين')
                    body=self.read_json()
                    if body.get('website',''):return self.send_json({'ok':True})
                    name=safe_text(body,'name',70);topic=safe_text(body,'topic',140);msg=safe_text(body,'message',1200)
                    if min(len(name),len(topic),len(msg))<2:return self.error_json(400,'يرجى ملء جميع الحقول')
                    c.execute('INSERT INTO requests(name,topic,message) VALUES(?,?,?)',(name,topic,msg));c.commit();return self.send_json({'ok':True},201)
                s=self.require_admin(c)
                if not s:return self.error_json(401,'الجلسة غير صالحة؛ سجّل الدخول مجدداً')
                if path=='/api/auth/logout' and method=='POST':
                    audit(c,s['admin_id'],'logout','admin');c.execute('DELETE FROM sessions WHERE token_hash=?',(s['token_hash'],));c.commit()
                    self.send_json({'ok':True},cookie='mis_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return
                if path=='/api/auth/password' and method=='POST':
                    body=self.read_json();old=safe_text(body,'old_password',250);new=safe_text(body,'new_password',250)
                    admin=c.execute('SELECT * FROM admins WHERE id=?',(s['admin_id'],)).fetchone()
                    if not check_password(old,admin['password_hash']):return self.error_json(400,'كلمة المرور الحالية غير صحيحة')
                    validate_password_strength(new,admin['username'])
                    if hmac.compare_digest(old,new):return self.error_json(400,'كلمة المرور الجديدة لازم تختلف عن الحالية')
                    c.execute('UPDATE admins SET password_hash=? WHERE id=?',(password_hash(new),admin['id']))
                    c.execute('DELETE FROM sessions WHERE admin_id=? AND token_hash<>?',(admin['id'],s['token_hash']))
                    audit(c,admin['id'],'password_change','admin')
                    c.commit()
                    if CREDS.exists():CREDS.unlink()
                    return self.send_json({'ok':True})
                if path=='/api/admin/requests' and method=='PATCH':
                    body=self.read_json();rid=number(body,'id');status=safe_text(body,'status',20)
                    if status not in ('new','done'):raise ValueError('حالة الطلب غير صحيحة')
                    changed=c.execute('UPDATE requests SET status=? WHERE id=?',(status,rid)).rowcount;audit(c,s['admin_id'],'request_status',rid);c.commit()
                    return self.send_json({'ok':bool(changed)})
                if re.fullmatch(r'/api/admin/requests/\d+',path) and method=='DELETE':
                    rid=int(path.rsplit('/',1)[-1]);c.execute('DELETE FROM requests WHERE id=?',(rid,));audit(c,s['admin_id'],'request_delete',rid);c.commit();return self.send_json({'ok':True})
                if path=='/api/admin/users' and method=='POST':
                    if row_role(s)!='admin':return self.error_json(403,'فقط الأدمن الرئيسي يستطيع إضافة مستخدمين')
                    body=self.read_json()
                    username=safe_text(body,'username',50)
                    password=safe_text(body,'password',250)
                    role=safe_text(body,'role',20) or 'admin'
                    if role not in ('admin','user'):raise ValueError('الدور غير صحيح (admin أو user)')
                    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,50}',username):raise ValueError('اسم المستخدم: 3-50 حرف إنجليزي/رقم أو _ - .')
                    validate_password_strength(password,username)
                    if c.execute('SELECT 1 FROM admins WHERE username=?',(username,)).fetchone():raise ValueError('اسم المستخدم موجود مسبقاً')
                    c.execute('INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)',(username,password_hash(password),role))
                    audit(c,s['admin_id'],'user_create',username);c.commit()
                    return self.send_json({'ok':True},201)
                if path=='/api/admin/users' and method=='PATCH':
                    body=self.read_json();uid=number(body,'id')
                    target=c.execute('SELECT * FROM admins WHERE id=?',(uid,)).fetchone()
                    if not target:return self.error_json(404,'المستخدم غير موجود')
                    is_self=uid==s['admin_id']
                    is_root_admin=row_role(s)=='admin'
                    if not is_self and not is_root_admin:return self.error_json(403,'فقط الأدمن الرئيسي يستطيع تعديل مستخدمين آخرين')
                    updates={}
                    if body.get('role') not in (None,''):
                        role=safe_text(body,'role',20)
                        if role not in ('admin','user'):raise ValueError('الدور غير صحيح')
                        if not is_root_admin:return self.error_json(403,'فقط الأدمن الرئيسي يستطيع تغيير الأدوار')
                        if uid==s['admin_id'] and role!='admin':
                            admins_left=c.execute("SELECT COUNT(*) FROM admins WHERE role='admin' AND id<>?",(uid,)).fetchone()[0]
                            if admins_left<1:return self.error_json(400,'يجب أن يبقى أدمن رئيسي واحد على الأقل')
                        updates['role']=role
                    if body.get('password'):
                        new=safe_text(body,'password',250)
                        validate_password_strength(new,target['username'])
                        updates['password_hash']=password_hash(new)
                    if not updates:return self.error_json(400,'ماكو تغييرات')
                    assignments=','.join(f'{k}=?' for k in updates)
                    c.execute(f'UPDATE admins SET {assignments} WHERE id=?',(*updates.values(),uid))
                    if 'password_hash' in updates:
                        if is_self:
                            c.execute('DELETE FROM sessions WHERE admin_id=? AND token_hash<>?',(uid,s['token_hash']))
                        else:
                            c.execute('DELETE FROM sessions WHERE admin_id=?',(uid,))
                    audit(c,s['admin_id'],'user_update',target['username']);c.commit()
                    return self.send_json({'ok':True})
                if re.fullmatch(r'/api/admin/users/\d+',path) and method=='DELETE':
                    if row_role(s)!='admin':return self.error_json(403,'فقط الأدمن الرئيسي يستطيع حذف المستخدمين')
                    uid=int(path.rsplit('/',1)[-1])
                    if uid==s['admin_id']:return self.error_json(400,'ما تكدر تحذف حسابك الحالي')
                    target=c.execute('SELECT * FROM admins WHERE id=?',(uid,)).fetchone()
                    if not target:return self.error_json(404,'المستخدم غير موجود')
                    if row_role(target)=='admin':
                        admins_left=c.execute("SELECT COUNT(*) FROM admins WHERE role='admin' AND id<>?",(uid,)).fetchone()[0]
                        if admins_left<1:return self.error_json(400,'يجب أن يبقى أدمن رئيسي واحد على الأقل')
                    c.execute('DELETE FROM sessions WHERE admin_id=?',(uid,))
                    c.execute('DELETE FROM admins WHERE id=?',(uid,))
                    audit(c,s['admin_id'],'user_delete',target['username']);c.commit()
                    return self.send_json({'ok':True})
                m=re.fullmatch(r'/api/admin/(subjects|announcements|exams|lectures|explanations)(?:/(\d+))?',path)
                if not m:return self.error_json(404,'المسار غير موجود')
                entity,raw_id=m.groups();obj_id=int(raw_id) if raw_id else None
                if method=='DELETE' and obj_id:
                    oldfiles=[]
                    if entity=='lectures':oldfiles=[r['file_path'] for r in c.execute('SELECT file_path FROM lectures WHERE id=?',(obj_id,))]
                    if entity=='explanations':oldfiles=[r['file_path'] for r in c.execute('SELECT file_path FROM explanations WHERE id=?',(obj_id,))]
                    if entity=='subjects':
                        oldfiles=[r['file_path'] for r in c.execute('SELECT file_path FROM lectures WHERE subject_id=?',(obj_id,))]
                        oldfiles += [r['file_path'] for r in c.execute('SELECT file_path FROM explanations WHERE subject_id=?',(obj_id,))]
                    c.execute(f'DELETE FROM {entity} WHERE id=?',(obj_id,));audit(c,s['admin_id'],'delete_'+entity,obj_id);c.commit()
                    for filename in oldfiles:self.cleanup_file(filename)
                    return self.send_json({'ok':True})
                if method not in ('POST','PATCH') or (method=='PATCH' and not obj_id) or (method=='POST' and obj_id):return self.error_json(405,'عملية غير مسموحة')
                body=self.read_json();d=validate_entity(c,entity,body,editing=bool(obj_id));oldfile=None;newfile=None
                if entity in ('lectures','explanations'):
                    table=entity
                    if obj_id:
                        prev=c.execute(f'SELECT file_path FROM {table} WHERE id=?',(obj_id,)).fetchone()
                        if not prev:return self.error_json(404,'العنصر غير موجود')
                        oldfile=prev['file_path']
                    if body.get('file_base64'):
                        newfile=store_file(body);d.update(newfile if entity=='explanations' else {k:v for k,v in newfile.items() if k!='file_mime'})
                try:
                    if obj_id:
                        if not d:return self.error_json(400,'ماكو تغييرات')
                        assignments=','.join(f'{k}=?' for k in d)
                        changed=c.execute(f'UPDATE {entity} SET {assignments} WHERE id=?',(*d.values(),obj_id)).rowcount
                        if not changed:raise ValueError('العنصر غير موجود')
                        created=obj_id
                    else:
                        if not d:raise ValueError('البيانات فارغة')
                        keys=','.join(d);holders=','.join('?' for _ in d)
                        created=c.execute(f'INSERT INTO {entity}({keys}) VALUES({holders})',tuple(d.values())).lastrowid
                    audit(c,s['admin_id'],('update_' if obj_id else 'create_')+entity,created)
                    c.commit()
                except Exception:
                    if newfile:self.cleanup_file(newfile['file_path'])
                    raise
                if newfile and oldfile:self.cleanup_file(oldfile)
                return self.send_json({'ok':True,'id':created},201 if not obj_id else 200)
        except ValueError as exc:return self.error_json(400,str(exc))
        except sqlite3.IntegrityError:return self.error_json(400,'تعذر حفظ البيانات: تأكد من الحقول والعناصر المرتبطة')
        except (sqlite3.Error,OSError) as exc:
            print('SERVER ERROR:',repr(exc),file=sys.stderr);return self.error_json(500,'حصل خطأ بالخادم')
    def cleanup_file(self,filename):
        if not filename:return
        with connection() as c:
            if c.execute('SELECT 1 FROM lectures WHERE file_path=? LIMIT 1',(filename,)).fetchone():return
            if c.execute('SELECT 1 FROM explanations WHERE file_path=? LIMIT 1',(filename,)).fetchone():return
        try:(UPLOADS/filename).unlink(missing_ok=True)
        except OSError:pass

if __name__=='__main__':
    initialize()
    # يدعم متغيرات HOST أو IP وPORT عند النشر، ويستخدم 8127 محلياً.
    # على منصات السحابة (Render/Fly/Railway...) يُضبط HOST=0.0.0.0 عبر البيئة.
    default_host='0.0.0.0' if os.getenv('RENDER') or os.getenv('FLY_APP_NAME') or os.getenv('RAILWAY_ENVIRONMENT') or os.getenv('MIS_BIND_ALL')=='1' else '127.0.0.1'
    host=os.getenv('IP') or os.getenv('HOST',default_host)
    port=int(os.getenv('PORT','8127'))
    display_host=f'[{host}]' if ':' in host else host
    print(f'MIS 2027 running at http://{display_host}:{port} - Ctrl+C to stop',flush=True)
    class SecureThreadingHTTPServer(ThreadingHTTPServer):
        daemon_threads=True
        request_queue_size=128
        allow_reuse_address=True
        address_family=socket.AF_INET6 if ':' in host else socket.AF_INET
    server=SecureThreadingHTTPServer((host,port),Handler)
    server.force_secure=os.getenv('FORCE_HTTPS','0')=='1'
    try:server.serve_forever()
    except KeyboardInterrupt:print('\nStopped.')
    finally:server.server_close()
