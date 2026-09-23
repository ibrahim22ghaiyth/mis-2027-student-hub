CREATE TABLE IF NOT EXISTS admins(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'admin'
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  admin_id INTEGER NOT NULL,
  csrf TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  issued_at INTEGER DEFAULT 0,
  last_seen INTEGER DEFAULT 0,
  ua_hash TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS subjects(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title_ar TEXT NOT NULL,
  title_en TEXT DEFAULT '',
  description TEXT DEFAULT '',
  color TEXT DEFAULT '#7C66FF',
  sort_order INTEGER DEFAULT 0,
  is_published INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS lectures(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  section TEXT NOT NULL CHECK(section IN ('theory','practical')),
  number INTEGER DEFAULT 1,
  description TEXT DEFAULT '',
  file_path TEXT DEFAULT '',
  file_name TEXT DEFAULT '',
  file_size INTEGER DEFAULT 0,
  file_mime TEXT DEFAULT '',
  file_data TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS explanations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_id INTEGER NOT NULL,
  lecture_id INTEGER,
  number INTEGER DEFAULT 1,
  title TEXT NOT NULL,
  summary TEXT DEFAULT '',
  content TEXT NOT NULL DEFAULT '',
  file_path TEXT DEFAULT '',
  file_name TEXT DEFAULT '',
  file_size INTEGER DEFAULT 0,
  file_mime TEXT DEFAULT '',
  file_data TEXT DEFAULT '',
  is_published INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS announcements(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  source TEXT DEFAULT '',
  pinned INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  expires_at TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS exams(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  exam_date TEXT NOT NULL,
  notes TEXT DEFAULT '',
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  topic TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT DEFAULT 'new' CHECK(status IN ('new','done')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS visits(id INTEGER PRIMARY KEY AUTOINCREMENT, visited_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, action TEXT NOT NULL, target TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_subjects_pub ON subjects(is_published,sort_order,id);
CREATE INDEX IF NOT EXISTS idx_lectures_subject ON lectures(subject_id,number,id);
CREATE INDEX IF NOT EXISTS idx_explanations_subject ON explanations(subject_id,number,id);
CREATE INDEX IF NOT EXISTS idx_visits_time ON visits(visited_at);
