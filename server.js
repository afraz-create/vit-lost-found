const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs');
const crypto = require('crypto'), fs = require('fs'), path = require('path');

const db = new Database(process.env.DB || path.join(__dirname, 'lostfound.db'));
db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
{ // migrate databases created before OTP/lockout existed
  const cols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  if (!cols.includes('verified')) { db.exec('ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0'); db.exec('UPDATE users SET verified=1'); }
  if (!cols.includes('failed_logins')) db.exec('ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0');
  if (!cols.includes('locked_until')) db.exec('ALTER TABLE users ADD COLUMN locked_until TEXT');
}

const L = (p, a, b) => Array.from({ length: b.charCodeAt(0) - a.charCodeAt(0) + 1 }, (_, i) => p + String.fromCharCode(a.charCodeAt(0) + i));
const META = {
  venues: {
    'Academic Blocks': ['SJT', 'TT', 'PRP', 'SMV', 'MB', 'GDN', 'CDMM'],
    "Men's Hostel Blocks": L('MH-', 'A', 'T'),
    "Ladies' Hostel Blocks": L('LH-', 'A', 'J'),
    'Food Courts': ['Gazebo', 'Food Mall', 'DC'],
    'Other Landmarks': ['Central Library', 'Sports Complex']
  },
  categories: ['ID Cards', 'Room Keys', 'Calculators', 'Lab Equipment', 'Earphones', 'Wallets'],
  checkpoints: ['SJT Ground Floor Reception', 'TT Main Lobby Desk', 'Central Library Security Desk',
    'Gazebo Food Court Entrance', 'Food Mall Security Desk', 'Sports Complex Reception',
    'Men\'s Hostel Main Gate Security', 'Ladies\' Hostel Main Gate Security']
};
const ALL_VENUES = Object.values(META.venues).flat();

const PROD = process.env.NODE_ENV === 'production';
const ADMINS = new Set((process.env.ADMIN_REG_NOS ?? (PROD ? '' : '25BCE0000')).split(',').map(x => x.trim().toUpperCase()).filter(Boolean));
const { EventEmitter } = require('events');
const bus = new EventEmitter(); bus.setMaxListeners(0);
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' });
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const bad = (res, m, c = 400) => res.status(c).json({ error: m });
const cookie = (req, n) => { const f = (req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(x => x[0] === n); return f ? f[1] : null; };
app.use((req, res, next) => {
  const t = cookie(req, 'sid');
  req.user = t ? db.prepare('SELECT u.id,u.name,u.reg_no,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created_at > datetime(\'now\',\'-7 days\') AND u.verified=1').get(t) : null;
  next();
});
const auth = (req, res, next) => (req.user ? next() : bad(res, 'Please log in first.', 401));
const login = (res, uid) => {
  const t = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions(token,user_id) VALUES(?,?)').run(t, uid);
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800${PROD ? '; Secure' : ''}`);
};
const me = u => ({ id: u.id, name: u.name, regNo: u.reg_no, email: u.email, isAdmin: ADMINS.has(u.reg_no) });

app.get('/api/meta', (_, res) => res.json(META));
app.get('/api/me', (req, res) => res.json({ user: req.user ? me(req.user) : null }));

// ---------- Auth hardening: OTP, reset, rate limits, lockout ----------
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(err => { console.error(err); bad(res, 'Server error. Please try again shortly.', 500); });
const hits = new Map();
const limit = (name, max, winMs, keyFn = req => req.ip) => (req, res, next) => {
  const k = name + ':' + keyFn(req), now = Date.now();
  const h = (hits.get(k) || []).filter(t => now - t < winMs);
  if (h.length >= max) return bad(res, 'Too many attempts. Please wait a few minutes and try again.', 429);
  h.push(now); hits.set(k, h); next();
};
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (!v.some(t => n - t < 3600e3)) hits.delete(k); }, 600e3).unref();

let mailer = null;
if (process.env.SMTP_HOST) {
  try {
    mailer = require('nodemailer').createTransport({ host: process.env.SMTP_HOST, port: +(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === '1',
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined });
  } catch { console.warn('SMTP_HOST set but nodemailer is not installed. Run: npm install'); }
}
async function sendMail(to, subject, text) {
  if (!mailer) { console.log(`\n[DEV MAIL - set SMTP_* env vars to send real email]\n   To: ${to}\n   ${subject}\n   ${text}\n`); return; }
  await mailer.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to, subject, text });
}
const hashCode = (email, code) => crypto.createHash('sha256').update(email + ':' + code).digest('hex');
const OTP_WHERE = 'email=? AND purpose=?';
async function issueOtp(email, purpose) {
  const prev = db.prepare(`SELECT created_at FROM otps WHERE ${OTP_WHERE}`).get(email, purpose);
  if (prev && Date.now() - new Date(prev.created_at.replace(' ', 'T') + 'Z') < 60000) return false; // 60s cooldown
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  db.prepare("INSERT OR REPLACE INTO otps(email,purpose,code_hash,expires_at,attempts,created_at) VALUES(?,?,?,datetime('now','+10 minutes'),0,datetime('now'))").run(email, purpose, hashCode(email, code));
  await sendMail(email, purpose === 'verify' ? 'Verify your VIT Lost & Found account' : 'Reset your VIT Lost & Found password',
    `Your 6-digit code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`);
  return true;
}
function checkOtp(email, purpose, code) { // returns an error string, or null if the code is valid (and consumes it)
  const o = db.prepare(`SELECT *, expires_at < datetime('now') AS expired FROM otps WHERE ${OTP_WHERE}`).get(email, purpose);
  const drop = () => db.prepare(`DELETE FROM otps WHERE ${OTP_WHERE}`).run(email, purpose);
  if (!o) return 'No active code. Please request a new one.';
  if (o.expired) { drop(); return 'This code has expired. Please request a new one.'; }
  if (o.attempts >= 5) { drop(); return 'Too many wrong codes. Please request a new one.'; }
  if (!/^\d{6}$/.test(String(code || '').trim())) return 'Enter the 6-digit code.';
  if (!crypto.timingSafeEqual(Buffer.from(o.code_hash), Buffer.from(hashCode(email, String(code).trim())))) {
    db.prepare(`UPDATE otps SET attempts=attempts+1 WHERE ${OTP_WHERE}`).run(email, purpose);
    return 'Incorrect code. Please try again.';
  }
  drop(); return null;
}
const pwOk = p => typeof p === 'string' && p.length >= 8 && p.length <= 100 && /\d/.test(p) && /[A-Za-z]/.test(p);
const DUMMY_HASH = bcrypt.hashSync('timing-guard', 12);
const emailOf = req => String(req.body?.email || '').trim().toLowerCase();
const emailKey = req => emailOf(req) || req.ip;

app.post('/api/register', limit('register', 10, 3600e3), ah(async (req, res) => {
  const { name = '', regNo = '', email = '', phone = '', password = '' } = req.body || {};
  const n = name.trim(), r = regNo.trim().toUpperCase(), e = email.trim().toLowerCase();
  if (n.length < 2 || n.length > 60) return bad(res, 'Enter your full name (2-60 characters).');
  if (!/^\d{2}[A-Z]{3}\d{4}$/.test(r)) return bad(res, 'Registration number must look like 21BCE1234.');
  if (!/^[^@\s]+@(vitstudent|vit)\.ac\.in$/.test(e)) return bad(res, 'Use your VIT email (@vitstudent.ac.in).');
  if (!/^[6-9]\d{9}$/.test(phone.trim())) return bad(res, 'Enter a valid 10-digit mobile number.');
  if (!pwOk(password)) return bad(res, 'Password needs 8+ characters with letters and numbers.');
  const ex = db.prepare('SELECT * FROM users WHERE reg_no=? OR email=?').all(r, e);
  if (ex.some(u => u.verified || u.email !== e || u.reg_no !== r)) return bad(res, 'An account with this registration number or email already exists.', 409);
  const hash = bcrypt.hashSync(password, 12);
  if (ex.length) db.prepare('UPDATE users SET name=?,phone=?,password_hash=? WHERE id=?').run(n, phone.trim(), hash, ex[0].id); // retry of an unverified signup
  else db.prepare('INSERT INTO users(name,reg_no,email,phone,password_hash) VALUES(?,?,?,?,?)').run(n, r, e, phone.trim(), hash);
  await issueOtp(e, 'verify');
  res.json({ needsVerification: true, email: e });
}));

app.post('/api/verify', limit('verify', 15, 15 * 60e3, emailKey), (req, res) => {
  const e = emailOf(req), u = db.prepare('SELECT * FROM users WHERE email=?').get(e);
  if (!u) return bad(res, 'Account not found. Please sign up first.', 404);
  if (u.verified) return bad(res, 'This email is already verified. Please log in.');
  const err = checkOtp(e, 'verify', req.body?.code);
  if (err) return bad(res, err);
  db.prepare('UPDATE users SET verified=1 WHERE id=?').run(u.id);
  login(res, u.id);
  res.json({ user: me(u) });
});

app.post('/api/resend', limit('resend', 5, 3600e3, emailKey), ah(async (req, res) => {
  const e = emailOf(req), purpose = req.body?.purpose === 'reset' ? 'reset' : 'verify';
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(e);
  if (u && ((purpose === 'verify' && !u.verified) || (purpose === 'reset' && u.verified))) await issueOtp(e, purpose);
  res.json({ ok: true }); // identical response whether or not the account exists
}));

app.post('/api/login', limit('login', 20, 15 * 60e3), ah(async (req, res) => {
  const { id = '', password = '' } = req.body || {};
  if (!String(id).trim() || !password) return bad(res, 'Enter your registration number/email and password.');
  const k = String(id).trim();
  const u = db.prepare('SELECT * FROM users WHERE reg_no=? OR email=?').get(k.toUpperCase(), k.toLowerCase());
  if (u?.locked_until && new Date(u.locked_until.replace(' ', 'T') + 'Z') > Date.now())
    return bad(res, 'Too many failed attempts. This account is locked for 15 minutes. You can also reset your password.', 423);
  const ok = bcrypt.compareSync(password, u ? u.password_hash : DUMMY_HASH);
  if (!u || !ok) {
    if (u) {
      const f = u.failed_logins + 1;
      if (f >= 5) db.prepare("UPDATE users SET failed_logins=0, locked_until=datetime('now','+15 minutes') WHERE id=?").run(u.id);
      else db.prepare('UPDATE users SET failed_logins=? WHERE id=?').run(f, u.id);
    }
    return bad(res, 'Incorrect credentials. Please try again.', 401);
  }
  db.prepare('UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?').run(u.id);
  if (!u.verified) {
    await issueOtp(u.email, 'verify');
    return res.status(403).json({ error: 'Please verify your email first. We sent you a code.', needsVerification: true, email: u.email });
  }
  login(res, u.id);
  res.json({ user: me(u) });
}));

app.post('/api/forgot', limit('forgot', 5, 3600e3, emailKey), ah(async (req, res) => {
  const e = emailOf(req);
  if (!/^[^@\s]+@(vitstudent|vit)\.ac\.in$/.test(e)) return bad(res, 'Enter your VIT email address.');
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(e);
  if (u?.verified) await issueOtp(e, 'reset');
  res.json({ ok: true }); // never reveals whether the email is registered
}));

app.post('/api/reset', limit('reset', 10, 15 * 60e3, emailKey), (req, res) => {
  const e = emailOf(req), { code, password } = req.body || {};
  if (!pwOk(password)) return bad(res, 'Password needs 8+ characters with letters and numbers.');
  const u = db.prepare('SELECT * FROM users WHERE email=? AND verified=1').get(e);
  const err = u ? checkOtp(e, 'reset', code) : 'No active code. Please request a new one.';
  if (err) return bad(res, err);
  db.prepare('UPDATE users SET password_hash=?, failed_logins=0, locked_until=NULL WHERE id=?').run(bcrypt.hashSync(password, 12), u.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id); // sign out everywhere
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const t = cookie(req, 'sid');
  if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  res.json({ ok: true });
});

// Public item shape: never includes user_id, reg no, email or phone.
const pub = (i, uid) => {
  const mc = uid ? db.prepare('SELECT id,status FROM claims WHERE item_id=? AND claimant_id=?').get(i.id, uid) : null;
  return { id: i.id, type: i.type, title: i.title, description: i.description, category: i.category, venue: i.venue,
    challenge: i.challenge, image: i.image, status: i.status, createdAt: i.created_at, mine: !!uid && i.user_id === uid, myClaim: mc || null };
};

app.get('/api/items', (req, res) => {
  const { type, category, venue, q } = req.query;
  let sql = "SELECT * FROM items WHERE status='active'"; const a = [];
  if (['lost', 'found'].includes(type)) { sql += ' AND type=?'; a.push(type); }
  if (META.categories.includes(category)) { sql += ' AND category=?'; a.push(category); }
  if (ALL_VENUES.includes(venue)) { sql += ' AND venue=?'; a.push(venue); }
  if (q && q.trim()) { sql += ' AND (title LIKE ? OR description LIKE ?)'; a.push(`%${q.trim()}%`, `%${q.trim()}%`); }
  res.json({ items: db.prepare(sql + ' ORDER BY id DESC LIMIT 100').all(...a).map(i => pub(i, req.user?.id)) });
});

app.post('/api/items', auth, (req, res) => {
  const { type, title = '', description = '', category, venue, challenge = '', image } = req.body || {};
  if (!['lost', 'found'].includes(type)) return bad(res, 'Choose Lost or Found.');
  if (title.trim().length < 3 || title.length > 80) return bad(res, 'Title must be 3-80 characters.');
  if (description.trim().length < 10 || description.length > 500) return bad(res, 'Description must be 10-500 characters.');
  if (!META.categories.includes(category)) return bad(res, 'Pick a valid category.');
  if (!ALL_VENUES.includes(venue)) return bad(res, 'Pick an official VIT campus location.');
  if (challenge.trim().length < 8 || challenge.length > 200) return bad(res, 'Verification question must be 8-200 characters.');
  if (image && (!/^data:image\/(png|jpeg|webp);base64,/.test(image) || image.length > 600000)) return bad(res, 'Image must be a PNG/JPEG/WebP under ~400KB.');
  const id = db.prepare('INSERT INTO items(user_id,type,title,description,category,venue,challenge,image) VALUES(?,?,?,?,?,?,?,?)')
    .run(req.user.id, type, title.trim(), description.trim(), category, venue, challenge.trim(), image || null).lastInsertRowid;
  res.json({ item: pub(db.prepare('SELECT * FROM items WHERE id=?').get(id), req.user.id) });
});

const APP_URL = process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
const notify = (uid, subject, text) => {
  const u = db.prepare('SELECT email FROM users WHERE id=?').get(uid);
  if (u) sendMail(u.email, subject, `${text}\n\nOpen the portal: ${APP_URL}`).catch(e => console.warn('Mail failed:', e.message));
};

app.post('/api/items/:id/claims', auth, (req, res) => {
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!it || it.status !== 'active') return bad(res, 'This item is no longer available.', 404);
  if (it.user_id === req.user.id) return bad(res, 'You cannot claim your own listing.');
  const answer = (req.body?.answer || '').trim();
  if (answer.length < 3 || answer.length > 500) return bad(res, 'Answer must be 3-500 characters.');
  if (db.prepare('SELECT 1 FROM claims WHERE item_id=? AND claimant_id=?').get(it.id, req.user.id)) return bad(res, 'You already submitted a request for this item.', 409);
  db.prepare('INSERT INTO claims(item_id,claimant_id,answer) VALUES(?,?,?)').run(it.id, req.user.id, answer);
  notify(it.user_id, 'New claim request on your listing', `Someone submitted a Claim Verification Request for "${it.title}". Open My Dashboard > Claims to review to approve or reject it.`);
  res.json({ ok: true });
});

app.get('/api/dashboard', auth, (req, res) => {
  const uid = req.user.id;
  const myItems = db.prepare('SELECT * FROM items WHERE user_id=? ORDER BY id DESC').all(uid)
    .map(i => ({ ...pub(i, uid), pending: db.prepare("SELECT COUNT(*) n FROM claims WHERE item_id=? AND status='pending'").get(i.id).n }));
  const received = db.prepare(`SELECT c.id,c.answer,c.status,c.meetup,c.created_at createdAt,i.title,i.challenge,i.status itemStatus
    FROM claims c JOIN items i ON i.id=c.item_id WHERE i.user_id=? ORDER BY c.id DESC`).all(uid).map(c => ({ ...c, alias: 'Claimant #' + c.id }));
  const sent = db.prepare(`SELECT c.id,c.answer,c.status,c.meetup,i.title,i.challenge,i.type,i.venue,i.status itemStatus
    FROM claims c JOIN items i ON i.id=c.item_id WHERE c.claimant_id=? ORDER BY c.id DESC`).all(uid);
  res.json({ myItems, received, sent });
});

app.post('/api/claims/:id/decision', auth, (req, res) => {
  const c = db.prepare('SELECT c.*,i.user_id owner,i.status istatus FROM claims c JOIN items i ON i.id=c.item_id WHERE c.id=?').get(req.params.id);
  if (!c || c.owner !== req.user.id) return bad(res, 'Claim not found.', 404);
  if (c.istatus !== 'active') return bad(res, 'This item is already resolved.');
  if (c.status !== 'pending') return bad(res, 'This claim was already decided.');
  const d = req.body?.decision;
  if (!['approve', 'reject'].includes(d)) return bad(res, 'Decision must be approve or reject.');
  db.prepare('UPDATE claims SET status=? WHERE id=?').run(d === 'approve' ? 'approved' : 'rejected', c.id);
  const ti = db.prepare('SELECT title FROM items WHERE id=?').get(c.item_id).title;
  notify(c.claimant_id, d === 'approve' ? 'Your claim was approved' : 'Your claim was not approved', d === 'approve' ? `Your claim for "${ti}" was approved. Open My Dashboard > My requests to chat privately and agree on a campus checkpoint.` : `Your claim for "${ti}" was not approved.`);
  res.json({ ok: true });
});

const access = (cid, uid) => {
  const c = db.prepare('SELECT c.*,i.user_id owner,i.status istatus,i.id iid,i.title FROM claims c JOIN items i ON i.id=c.item_id WHERE c.id=?').get(cid);
  if (!c || c.status !== 'approved' || (c.owner !== uid && c.claimant_id !== uid)) return null;
  return c;
};

app.get('/api/claims/:id/thread', auth, (req, res) => {
  const c = access(req.params.id, req.user.id);
  if (!c) return bad(res, 'Thread not available.', 404);
  const msgs = db.prepare('SELECT id,sender_id,body,created_at createdAt FROM messages WHERE claim_id=? ORDER BY id').all(c.id)
    .map(m => ({ id: m.id, body: m.body, createdAt: m.createdAt, mine: m.sender_id === req.user.id, who: m.sender_id === c.owner ? 'Poster' : 'Claimant' }));
  res.json({ title: c.title, meetup: c.meetup, resolved: c.istatus === 'resolved', itemId: c.iid, role: c.owner === req.user.id ? 'Poster' : 'Claimant', messages: msgs });
});

app.post('/api/claims/:id/messages', auth, (req, res) => {
  const c = access(req.params.id, req.user.id);
  if (!c) return bad(res, 'Thread not available.', 404);
  const body = (req.body?.body || '').trim();
  if (!body || body.length > 500) return bad(res, 'Message must be 1-500 characters.');
  if (/\b[6-9]\d{9}\b/.test(body.replace(/[\s-]/g, ''))) return bad(res, 'For your safety, do not share phone numbers in chat. Agree on a campus checkpoint instead.');
  db.prepare('INSERT INTO messages(claim_id,sender_id,body) VALUES(?,?,?)').run(c.id, req.user.id, body);
  bus.emit('claim:' + c.id);
  res.json({ ok: true });
});

app.post('/api/claims/:id/meetup', auth, (req, res) => {
  const c = access(req.params.id, req.user.id);
  if (!c) return bad(res, 'Thread not available.', 404);
  if (!META.checkpoints.includes(req.body?.checkpoint)) return bad(res, 'Choose an official campus checkpoint.');
  db.prepare('UPDATE claims SET meetup=? WHERE id=?').run(req.body.checkpoint, c.id);
  db.prepare('INSERT INTO messages(claim_id,sender_id,body) VALUES(?,?,?)').run(c.id, req.user.id, `Proposed meetup: ${req.body.checkpoint}`);
  bus.emit('claim:' + c.id);
  res.json({ ok: true });
});

app.get('/api/claims/:id/stream', auth, (req, res) => {
  const c = access(req.params.id, req.user.id);
  if (!c) return bad(res, 'Thread not available.', 404);
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders(); res.write('retry: 3000\n\n');
  const k = 'claim:' + c.id, f = () => res.write('data: msg\n\n');
  bus.on(k, f);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { bus.off(k, f); clearInterval(ping); });
});

app.post('/api/items/:id/report', auth, (req, res) => {
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!it || it.status !== 'active') return bad(res, 'This item is no longer available.', 404);
  if (it.user_id === req.user.id) return bad(res, 'You cannot report your own listing.');
  const reason = (req.body?.reason || '').trim();
  if (reason.length < 5 || reason.length > 300) return bad(res, 'Please describe the problem (5-300 characters).');
  try { db.prepare('INSERT INTO reports(item_id,reporter_id,reason) VALUES(?,?,?)').run(it.id, req.user.id, reason); }
  catch { return bad(res, 'You already reported this listing.', 409); }
  res.json({ ok: true });
});

const admin = (req, res, next) => (ADMINS.has(req.user.reg_no) ? next() : bad(res, 'Admins only.', 403));
app.get('/api/admin/reports', auth, admin, (req, res) => res.json({ reports: db.prepare(`SELECT r.id,r.reason,r.created_at createdAt,i.id itemId,i.title,i.type,i.venue,i.description,
  (SELECT COUNT(*) FROM reports x WHERE x.item_id=i.id) n FROM reports r JOIN items i ON i.id=r.item_id WHERE r.status='open' ORDER BY r.id DESC`).all() }));
app.post('/api/admin/reports/:id/dismiss', auth, admin, (req, res) => { db.prepare("UPDATE reports SET status='dismissed' WHERE id=?").run(req.params.id); res.json({ ok: true }); });
app.post('/api/admin/items/:id/remove', auth, admin, (req, res) => { db.prepare('DELETE FROM items WHERE id=?').run(req.params.id); res.json({ ok: true }); });

app.post('/api/items/:id/resolve', auth, (req, res) => {
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!it) return bad(res, 'Item not found.', 404);
  const isParty = it.user_id === req.user.id || db.prepare("SELECT 1 FROM claims WHERE item_id=? AND claimant_id=? AND status='approved'").get(it.id, req.user.id);
  if (!isParty) return bad(res, 'Only the poster or an approved claimant can resolve this item.', 403);
  db.prepare("UPDATE items SET status='resolved' WHERE id=?").run(it.id);
  db.prepare('SELECT id FROM claims WHERE item_id=?').all(it.id).forEach(c => bus.emit('claim:' + c.id));
  db.prepare("UPDATE claims SET status='rejected' WHERE item_id=? AND status='pending'").run(it.id);
  res.json({ ok: true });
});

app.use('/api', (_, res) => bad(res, 'Not found.', 404));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`VIT Lost & Found running at http://localhost:${PORT}`));
