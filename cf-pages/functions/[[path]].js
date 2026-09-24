const SESSION_TTL = 8 * 3600;
const MAX_JSON = 34 * 1024 * 1024;
const MAX_FILE_BYTES = 24 * 1024 * 1024;
const ENTITIES = {
  subjects: ['title_ar','title_en','description','color','sort_order','is_published'],
  lectures: ['subject_id','title','section','number','description','file_path','file_name','file_size','file_mime','file_data'],
  explanations: ['subject_id','lecture_id','number','title','contributor','summary','content','file_path','file_name','file_size','file_mime','file_data','is_published'],
  announcements: ['title','body','source','pinned','is_active','expires_at'],
  exams: ['subject_id','title','exam_date','notes','is_active'],
};
const REQUIRED = {
  subjects: ['title_ar'],
  lectures: ['subject_id','title','section'],
  explanations: ['subject_id','title'],
  announcements: ['title','body'],
  exams: ['subject_id','title','exam_date'],
};

const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), {
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...headers,
  },
});
const err = (status, message) => json({ error: message }, status);
const escLike = s => String(s ?? '').slice(0, 3000).trim();
const cleanBase64 = s => String(s ?? '').replace(/^data:[^,]+,/, '').replace(/\s+/g, '');
const intVal = v => Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : 0;
const nowSec = () => Math.floor(Date.now() / 1000);
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
async function sha256(value) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}
function cookie(req, name) {
  const raw = req.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return '';
}
async function readJson(req) {
  const len = Number(req.headers.get('content-length') || 0);
  if (len > MAX_JSON) throw new Error('حجم الطلب كبير جداً');
  return await req.json();
}
async function all(db, sql, ...binds) {
  return (await db.prepare(sql).bind(...binds).all()).results || [];
}
async function first(db, sql, ...binds) {
  return await db.prepare(sql).bind(...binds).first();
}
async function run(db, sql, ...binds) {
  return await db.prepare(sql).bind(...binds).run();
}
function publicRow(row) {
  const copy = { ...row };
  delete copy.file_data;
  return copy;
}
async function publicData(db) {
  const subjects = await all(db, 'SELECT * FROM subjects WHERE is_published=1 ORDER BY sort_order,id');
  const lectures = await all(db, "SELECT l.* FROM lectures l JOIN subjects s ON s.id=l.subject_id WHERE s.is_published=1 ORDER BY l.number,l.id");
  const explanations = await all(db, "SELECT e.* FROM explanations e JOIN subjects s ON s.id=e.subject_id WHERE s.is_published=1 AND e.is_published=1 ORDER BY e.subject_id,e.number,e.id");
  const announcements = await all(db, "SELECT * FROM announcements WHERE is_active=1 AND (expires_at='' OR expires_at IS NULL OR expires_at>=date('now')) ORDER BY pinned DESC,id DESC");
  const exams = await all(db, "SELECT e.* FROM exams e JOIN subjects s ON s.id=e.subject_id WHERE e.is_active=1 AND s.is_published=1 ORDER BY e.exam_date");
  return {
    subjects, lectures: lectures.map(publicRow), explanations: explanations.map(publicRow),
    announcements, exams,
  };
}
async function checkPassword(password, stored) {
  if (!stored) return false;
  if (stored.startsWith('sha256$')) {
    const [, salt, digest] = stored.split('$');
    return await sha256(salt + password) === digest;
  }
  return false;
}
async function makePasswordHash(password) {
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  return `sha256$${salt}$${await sha256(salt + password)}`;
}
function validatePassword(password, username = '') {
  if (String(password || '').length < 8) throw new Error('كلمة المرور لازم تكون 8 أحرف على الأقل');
  if (username && String(password).toLowerCase().includes(String(username).toLowerCase())) throw new Error('كلمة المرور لا يصير تحتوي اسم المستخدم');
}
async function getSession(req, db) {
  const token = cookie(req, 'mis_session');
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const digest = await sha256(token);
  const row = await first(db, 'SELECT sessions.*,admins.username,admins.role FROM sessions JOIN admins ON admins.id=sessions.admin_id WHERE token_hash=? AND expires_at>?', digest, nowSec());
  if (!row) return null;
  return row;
}
async function requireAdmin(req, db) {
  const s = await getSession(req, db);
  if (!s) return null;
  if ((req.headers.get('x-csrf-token') || '') !== s.csrf) return null;
  return s;
}
function normalizeEntity(entity, body, editing = false) {
  if (!ENTITIES[entity]) throw new Error('نوع البيانات غير صحيح');
  const out = {};
  for (const key of ENTITIES[entity]) {
    if (!(key in body)) continue;
    if (['subject_id','lecture_id','sort_order','is_published','pinned','is_active','number','file_size'].includes(key)) {
      out[key] = key === 'lecture_id' && ['', null, 0, '0'].includes(body[key]) ? null : intVal(body[key]);
    } else {
      out[key] = escLike(body[key]);
    }
  }
  if (body.file_base64 && ['lectures','explanations'].includes(entity)) {
    const fileName = escLike(body.file_name || 'file');
    const mime = fileName.toLowerCase().endsWith('.pdf') ? 'application/pdf' : fileName.toLowerCase().match(/\.html?$/) ? 'text/html' : 'application/octet-stream';
    const data = cleanBase64(body.file_base64);
    const size = Math.floor((data.length * 3) / 4);
    if (!data || size > MAX_FILE_BYTES) throw new Error('حجم الملف أكبر من الحد المجاني المتاح حالياً: 24 MB');
    out.file_path = 'pending';
    out.file_name = fileName;
    out.file_mime = mime;
    out.file_data = data;
    out.file_size = size;
  }
  for (const key of REQUIRED[entity] || []) {
    if (!editing && !String(out[key] ?? '').trim()) throw new Error(`الحقل مطلوب: ${key}`);
  }
  if (entity === 'lectures' && out.section && !['theory','practical'].includes(out.section)) throw new Error('نوع المحاضرة غير صحيح');
  return out;
}
async function adminData(db, session) {
  const data = {};
  for (const entity of Object.keys(ENTITIES)) {
    data[entity] = (await all(db, `SELECT * FROM ${entity} ORDER BY id DESC`)).map(publicRow);
  }
  data.requests = await all(db, 'SELECT * FROM requests ORDER BY id DESC');
  const stats = await first(db, `SELECT
    SUM(CASE WHEN visited_at >= datetime('now','-1 day') THEN 1 ELSE 0 END) AS daily,
    SUM(CASE WHEN visited_at >= datetime('now','-7 day') THEN 1 ELSE 0 END) AS weekly,
    SUM(CASE WHEN visited_at >= datetime('now','-30 day') THEN 1 ELSE 0 END) AS monthly
    FROM visits`);
  data.visit_stats = { daily: Number(stats?.daily || 0), weekly: Number(stats?.weekly || 0), monthly: Number(stats?.monthly || 0) };
  data.users = await all(db, 'SELECT id,username,role FROM admins ORDER BY id');
  return { username: session.username, role: session.role || 'admin', csrf: session.csrf, data };
}
function base64Bytes(data) {
  const binary = atob(cleanBase64(data));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function storeUploadedFile(env, entity, id, out) {
  if (!out.file_data || !['lectures','explanations'].includes(entity)) return out;
  if (env.FILES) {
    const key = `${entity}/${id}/${crypto.randomUUID()}-${out.file_name || 'file'}`;
    await env.FILES.put(key, base64Bytes(out.file_data).buffer, {
      metadata: { file_name: out.file_name || 'file', file_mime: out.file_mime || 'application/octet-stream', file_size: String(out.file_size || 0) },
    });
    await run(env.DB, `UPDATE ${entity} SET file_path=?, file_data='' WHERE id=?`, `kv:${key}`, id);
    return { ...out, file_path: `kv:${key}`, file_data: '' };
  }
  await run(env.DB, `UPDATE ${entity} SET file_path=? WHERE id=?`, 'd1', id);
  return { ...out, file_path: 'd1' };
}
async function deleteStoredFile(env, row) {
  if (env.FILES && row?.file_path?.startsWith?.('kv:')) {
    await env.FILES.delete(row.file_path.slice(3));
  }
}
async function fileResponse(env, row, download = false, print = false) {
  if (!row || (!row.file_data && !row.file_path?.startsWith?.('kv:'))) return err(404, 'الملف غير موجود');
  let body = null;
  if (row.file_path?.startsWith?.('kv:') && env.FILES) {
    body = await env.FILES.get(row.file_path.slice(3), 'arrayBuffer');
  } else if (row.file_data) {
    body = base64Bytes(row.file_data);
  }
  if (!body) return err(404, 'الملف غير موجود');
  if (print && /^text\/html\b/i.test(row.file_mime || '')) {
    let html = new TextDecoder().decode(body instanceof ArrayBuffer ? body : body.buffer);
    const script = `<script>window.addEventListener('load',()=>setTimeout(()=>window.print(),450));</script>`;
    html = /<\/body>/i.test(html) ? html.replace(/<\/body>/i, `${script}</body>`) : `${html}${script}`;
    body = html;
  }
  const headers = {
    'content-type': row.file_mime || 'application/octet-stream',
    'content-disposition': `${download ? 'attachment' : 'inline'}; filename*=UTF-8''${encodeURIComponent(row.file_name || 'file')}`,
    'cache-control': 'public, max-age=3600',
    'x-content-type-options': 'nosniff',
  };
  return new Response(body, { headers });
}
async function handleApi(req, env, path) {
  const db = env.DB;
  if (req.method === 'GET' && path === '/api/public') return json(await publicData(db));
  if (req.method === 'POST' && path === '/api/visit') {
    await run(db, 'INSERT INTO visits DEFAULT VALUES');
    return json({ ok: true }, 201);
  }
  if (req.method === 'POST' && path === '/api/requests') {
    const body = await readJson(req);
    if (body.website) return json({ ok: true });
    const name = escLike(body.name).slice(0, 70), topic = escLike(body.topic).slice(0, 140), message = escLike(body.message).slice(0, 1200);
    if (Math.min(name.length, topic.length, message.length) < 2) return err(400, 'يرجى ملء جميع الحقول');
    await run(db, 'INSERT INTO requests(name,topic,message) VALUES(?,?,?)', name, topic, message);
    return json({ ok: true }, 201);
  }
  if (req.method === 'GET' && path.startsWith('/api/files/')) {
    const id = intVal(path.split('/').pop());
    const row = await first(db, 'SELECT l.* FROM lectures l JOIN subjects s ON s.id=l.subject_id WHERE l.id=? AND s.is_published=1', id);
    const url = new URL(req.url);
    return fileResponse(env, row, url.searchParams.get('download') === '1', url.searchParams.get('print') === '1');
  }
  if (req.method === 'GET' && (path.startsWith('/api/explanation-files/') || path.startsWith('/api/explanation-preview/'))) {
    const id = intVal(path.split('/').pop());
    const row = await first(db, 'SELECT e.* FROM explanations e JOIN subjects s ON s.id=e.subject_id WHERE e.id=? AND e.is_published=1 AND s.is_published=1', id);
    const url = new URL(req.url);
    return fileResponse(env, row, path.startsWith('/api/explanation-files/') && url.searchParams.get('download') === '1', url.searchParams.get('print') === '1');
  }
  if (req.method === 'GET' && path === '/api/admin/data') {
    const s = await getSession(req, db);
    if (!s) return err(401, 'يرجى تسجيل الدخول');
    return json(await adminData(db, s));
  }
  if (req.method === 'POST' && path === '/api/auth/login') {
    const body = await readJson(req);
    const username = escLike(body.username).slice(0, 50), password = escLike(body.password).slice(0, 250);
    const admin = await first(db, 'SELECT * FROM admins WHERE username=?', username);
    if (!admin || !(await checkPassword(password, admin.password_hash))) return err(401, 'اسم المستخدم أو كلمة المرور غير صحيحة');
    const token = hex(crypto.getRandomValues(new Uint8Array(32)));
    const csrf = hex(crypto.getRandomValues(new Uint8Array(24)));
    await run(db, 'INSERT INTO sessions(token_hash,admin_id,csrf,expires_at,issued_at,last_seen,ua_hash) VALUES(?,?,?,?,?,?,?)', await sha256(token), admin.id, csrf, nowSec() + SESSION_TTL, nowSec(), nowSec(), '');
    return json({ username, role: admin.role || 'admin', csrf }, 200, { 'set-cookie': `mis_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}` });
  }
  const session = await requireAdmin(req, db);
  if (!session) return err(401, 'الجلسة غير صالحة؛ سجّل الدخول مجدداً');
  if (req.method === 'POST' && path === '/api/auth/logout') {
    await run(db, 'DELETE FROM sessions WHERE token_hash=?', session.token_hash);
    return json({ ok: true }, 200, { 'set-cookie': 'mis_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' });
  }
  if (req.method === 'POST' && path === '/api/auth/password') {
    const body = await readJson(req);
    const admin = await first(db, 'SELECT * FROM admins WHERE id=?', session.admin_id);
    if (!admin || !(await checkPassword(escLike(body.old_password), admin.password_hash))) return err(400, 'كلمة المرور الحالية غير صحيحة');
    const nextPassword = escLike(body.new_password).slice(0, 250);
    validatePassword(nextPassword, admin.username);
    await run(db, 'UPDATE admins SET password_hash=? WHERE id=?', await makePasswordHash(nextPassword), admin.id);
    await run(db, 'DELETE FROM sessions WHERE admin_id=? AND token_hash<>?', admin.id, session.token_hash);
    return json({ ok: true });
  }
  if (req.method === 'POST' && path === '/api/admin/users') {
    if ((session.role || 'admin') !== 'admin') return err(403, 'فقط الأدمن الرئيسي يستطيع إضافة مستخدمين');
    const body = await readJson(req);
    const username = escLike(body.username).slice(0, 50);
    const password = escLike(body.password).slice(0, 250);
    const role = ['admin', 'user'].includes(body.role) ? body.role : 'user';
    if (!/^[A-Za-z0-9_.-]{3,50}$/.test(username)) return err(400, 'اسم المستخدم: 3-50 حرف إنجليزي/رقم أو _ - .');
    validatePassword(password, username);
    await run(db, 'INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)', username, await makePasswordHash(password), role);
    return json({ ok: true }, 201);
  }
  if (req.method === 'PATCH' && path === '/api/admin/users') {
    const body = await readJson(req);
    const uid = intVal(body.id);
    const target = await first(db, 'SELECT * FROM admins WHERE id=?', uid);
    if (!target) return err(404, 'المستخدم غير موجود');
    const isSelf = uid === session.admin_id;
    const isRoot = (session.role || 'admin') === 'admin';
    if (!isSelf && !isRoot) return err(403, 'فقط الأدمن الرئيسي يستطيع تعديل مستخدمين آخرين');
    const updates = {};
    if (body.role) {
      if (!isRoot) return err(403, 'فقط الأدمن الرئيسي يستطيع تغيير الأدوار');
      if (!['admin', 'user'].includes(body.role)) return err(400, 'الدور غير صحيح');
      updates.role = body.role;
    }
    if (body.password) {
      const nextPassword = escLike(body.password).slice(0, 250);
      validatePassword(nextPassword, target.username);
      updates.password_hash = await makePasswordHash(nextPassword);
    }
    const cols = Object.keys(updates);
    if (!cols.length) return err(400, 'ماكو تغييرات');
    await run(db, `UPDATE admins SET ${cols.map(c => `${c}=?`).join(',')} WHERE id=?`, ...cols.map(c => updates[c]), uid);
    if (updates.password_hash) await run(db, isSelf ? 'DELETE FROM sessions WHERE admin_id=? AND token_hash<>?' : 'DELETE FROM sessions WHERE admin_id=?', ...(isSelf ? [uid, session.token_hash] : [uid]));
    return json({ ok: true });
  }
  let userDelete = path.match(/^\/api\/admin\/users\/(\d+)$/);
  if (userDelete && req.method === 'DELETE') {
    if ((session.role || 'admin') !== 'admin') return err(403, 'فقط الأدمن الرئيسي يستطيع حذف المستخدمين');
    const uid = intVal(userDelete[1]);
    if (uid === session.admin_id) return err(400, 'ما تكدر تحذف حسابك الحالي');
    await run(db, 'DELETE FROM sessions WHERE admin_id=?', uid);
    await run(db, 'DELETE FROM admins WHERE id=?', uid);
    return json({ ok: true });
  }
  if (req.method === 'PATCH' && path === '/api/admin/requests') {
    const body = await readJson(req);
    const status = body.status === 'done' ? 'done' : 'new';
    await run(db, 'UPDATE requests SET status=? WHERE id=?', status, intVal(body.id));
    return json({ ok: true });
  }
  let match = path.match(/^\/api\/admin\/requests\/(\d+)$/);
  if (match && req.method === 'DELETE') {
    await run(db, 'DELETE FROM requests WHERE id=?', intVal(match[1]));
    return json({ ok: true });
  }
  match = path.match(/^\/api\/admin\/(subjects|announcements|exams|lectures|explanations)(?:\/(\d+))?$/);
  if (!match) return err(404, 'المسار غير موجود');
  const [, entity, rawId] = match;
  if (req.method === 'DELETE' && rawId) {
    if (['lectures','explanations'].includes(entity)) {
      const old = await first(db, `SELECT file_path FROM ${entity} WHERE id=?`, intVal(rawId));
      await deleteStoredFile(env, old);
    }
    await run(db, `DELETE FROM ${entity} WHERE id=?`, intVal(rawId));
    return json({ ok: true });
  }
  if (!['POST','PATCH'].includes(req.method)) return err(405, 'عملية غير مسموحة');
  const body = await readJson(req);
  const id = rawId ? intVal(rawId) : null;
  const data = normalizeEntity(entity, body, !!id);
  const uploadedFileData = data.file_data;
  if (uploadedFileData && env.FILES) data.file_data = '';
  const cols = Object.keys(data);
  if (!cols.length) return err(400, 'ماكو تغييرات');
  if (id) {
    if (uploadedFileData && ['lectures','explanations'].includes(entity)) {
      const old = await first(db, `SELECT file_path FROM ${entity} WHERE id=?`, id);
      await deleteStoredFile(env, old);
    }
    await run(db, `UPDATE ${entity} SET ${cols.map(c => `${c}=?`).join(',')} WHERE id=?`, ...cols.map(c => data[c]), id);
    if (uploadedFileData) await storeUploadedFile(env, entity, id, { ...data, file_data: uploadedFileData });
    return json({ ok: true, id });
  }
  const placeholders = cols.map(() => '?').join(',');
  const result = await run(db, `INSERT INTO ${entity}(${cols.join(',')}) VALUES(${placeholders})`, ...cols.map(c => data[c]));
  const newId = result.meta?.last_row_id;
  if (uploadedFileData) await storeUploadedFile(env, entity, newId, { ...data, file_data: uploadedFileData });
  return json({ ok: true, id: newId }, 201);
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/api/')) return next();
  try {
    return await handleApi(request, env, url.pathname);
  } catch (e) {
    return err(400, e.message || 'تعذر تنفيذ الطلب');
  }
}

