const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const http = require('http');

const JWT_SECRET = process.env.JWT_SECRET || 'tstore_dev_secret_change_me';
const PORT = process.env.PORT || 10000;
const DB_PATH = path.join(__dirname, 'db', 'tstore.sqlite');

if (!fs.existsSync(path.join(__dirname, 'db'))) {
  fs.mkdirSync(path.join(__dirname, 'db'));
}

const initSql = fs.readFileSync(path.join(__dirname, 'migrations', 'init.sql'), 'utf8');
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.exec(initSql);
  db.get("SELECT id FROM users WHERE login = ?", ['admin'], (err, row) => {
    if (err) console.error(err);
    if (!row) {
      const adminPass = '124856';
      bcrypt.hash(adminPass, 10, (e, hash) => {
        if (e) return console.error(e);
        db.run("INSERT INTO users (login, pass, name, isAdmin) VALUES (?,?,?,1)", ['admin', hash, 'Адмін']);
        console.log('Created admin (login: admin, pass: 124856)');
      });
    }
  });
});

const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(fileUpload({ limits: { fileSize: 5 * 1024 * 1024 }, abortOnLimit: true }));
app.use(express.static(path.join(__dirname, 'public')));

function runAsync(sql, params = []) {
  return new Promise((res, rej) => {
    db.run(sql, params, function (err) { if (err) rej(err); else res(this); });
  });
}
function allAsync(sql, params = []) {
  return new Promise((res, rej) => db.all(sql, params, (e, rows) => e ? rej(e) : res(rows)));
}
function getAsync(sql, params = []) {
  return new Promise((res, rej) => db.get(sql, params, (e, row) => e ? rej(e) : res(row)));
}

function genToken(user) {
  return jwt.sign({ id: user.id, login: user.login, isAdmin: !!user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'no token' });
  const token = auth.split(' ')[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (e) { res.status(401).json({ error: 'invalid token' }); }
}

app.post('/api/register', async (req, res) => {
  const { login, pass, name, phone } = req.body;
  if (!login || !pass) return res.status(400).json({ error: 'login+pass required' });
  try {
    const exists = await getAsync("SELECT id FROM users WHERE login = ?", [login]);
    if (exists) return res.status(400).json({ error: 'login exists' });
    const hash = await bcrypt.hash(pass, 10);
    const info = await runAsync("INSERT INTO users (login, pass, name, phone) VALUES (?,?,?,?)", [login, hash, name || login, phone || '']);
    const id = info.lastID;
    const user = await getAsync("SELECT id,login,name,isAdmin,blocked FROM users WHERE id = ?", [id]);
    const token = genToken(user);
    res.json({ token, user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server' }); }
});

app.post('/api/login', async (req, res) => {
  const { login, pass } = req.body;
  if (!login || !pass) return res.status(400).json({ error: 'login+pass required' });
  try {
    const user = await getAsync("SELECT * FROM users WHERE login = ?", [login]);
    if (!user) return res.status(400).json({ error: 'no user' });
    const ok = await bcrypt.compare(pass, user.pass);
    if (!ok) return res.status(400).json({ error: 'bad credentials' });
    if (user.blocked) return res.status(403).json({ error: 'blocked' });
    const token = genToken(user);
    res.json({ token, user: { id: user.id, login: user.login, name: user.name, isAdmin: user.isAdmin, blocked: user.blocked } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server' }); }
});

app.get('/api/listings', async (req, res) => {
  try {
    const rows = await allAsync("SELECT l.*, u.name as ownerName FROM listings l LEFT JOIN users u ON u.id = l.ownerId WHERE l.approved = 1 ORDER BY created_at DESC");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.get('/api/listings/:id', async (req, res) => {
  try {
    const row = await getAsync("SELECT l.*, u.name as ownerName, u.phone as ownerPhone FROM listings l LEFT JOIN users u ON u.id = l.ownerId WHERE l.id = ?", [req.params.id]);
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json(row);
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.post('/api/listings', authMiddleware, async (req, res) => {
  try {
    const user = await getAsync("SELECT * FROM users WHERE id = ?", [req.user.id]);
    if (!user) return res.status(401).json({ error: 'user not found' });
    if (user.blocked) return res.status(403).json({ error: 'blocked' });
    const cntRow = await getAsync("SELECT COUNT(*) as c FROM listings WHERE ownerId = ?", [user.id]);
    if (cntRow.c >= 5) return res.status(400).json({ error: 'limit 5 listings' });
    const { title, category, price, desc, phone } = req.body;
    let imgData = null;
    if (req.files && req.files.photo) {
      imgData = req.files.photo.data.toString('base64');
    }
    const info = await runAsync("INSERT INTO listings (title, category, price, desc, img, ownerId, approved, fromStore, phone) VALUES (?,?,?,?,?,?,?,?,?)",
      [title, category, price || 0, desc || '', imgData, user.id, user.isAdmin ? 1 : 0, 0, phone || '']);
    res.json({ id: info.lastID, message: 'created' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server' }); }
});

app.delete('/api/listings/:id', authMiddleware, async (req, res) => {
  try {
    const listing = await getAsync("SELECT * FROM listings WHERE id = ?", [req.params.id]);
    if (!listing) return res.status(404).json({ error: 'not found' });
    if (req.user.isAdmin || req.user.id == listing.ownerId) {
      await runAsync("DELETE FROM listings WHERE id = ?", [req.params.id]);
      return res.json({ ok: true });
    }
    return res.status(403).json({ error: 'forbidden' });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.post('/api/listings/:id/approve', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  try {
    await runAsync("UPDATE listings SET approved = 1 WHERE id = ?", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.post('/api/reports', authMiddleware, async (req, res) => {
  try {
    const { type, text, targetListingId, targetUserId } = req.body;
    await runAsync("INSERT INTO reports (type,text,fromId,targetListingId,targetUserId) VALUES (?,?,?,?,?)", [type, text, req.user.id || null, targetListingId || null, targetUserId || null]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.get('/api/reports', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  try {
    const rows = await allAsync("SELECT r.*, u.name as fromName FROM reports r LEFT JOIN users u ON u.id = r.fromId ORDER BY created_at DESC");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.delete('/api/reports/:id', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  try { await runAsync("DELETE FROM reports WHERE id = ?", [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.get('/api/users', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  try { const rows = await allAsync("SELECT id,login,name,phone,isAdmin,blocked FROM users ORDER BY id DESC"); res.json(rows); } catch (e) { res.status(500).json({ error: 'server' }); }
});
app.post('/api/users/:id/block', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  try { await runAsync("UPDATE users SET blocked = 1 WHERE id = ?", [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: 'server' }); }
});
app.post('/api/users/:id/unblock', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  try { await runAsync("UPDATE users SET blocked = 0 WHERE id = ?", [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: 'server' }); }
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error("Auth error"));
  try {
    const data = jwt.verify(token, JWT_SECRET);
    socket.user = data;
    return next();
  } catch (e) { return next(new Error("Auth error")); }
});

io.on('connection', async (socket) => {
  console.log('socket connected', socket.user && socket.user.login);
  socket.on('join', async (payload) => {
    try {
      const { listingId, sellerId, buyerId } = payload;
      let chat = await getAsync("SELECT * FROM chats WHERE listingId = ? AND sellerId = ? AND buyerId = ?", [listingId, sellerId, buyerId]);
      if (!chat) {
        const info = await runAsync("INSERT INTO chats (listingId, buyerId, sellerId) VALUES (?,?,?)", [listingId, buyerId, sellerId]);
        chat = { id: info.lastID, listingId, buyerId, sellerId };
      }
      const room = 'chat_' + chat.id;
      socket.join(room);
      const msgs = await allAsync("SELECT * FROM messages WHERE chatId = ? ORDER BY created_at ASC", [chat.id]);
      socket.emit('chat_history', { chatId: chat.id, messages: msgs });
    } catch (e) { console.error(e); }
  });

  socket.on('msg', async (payload) => {
    try {
      const chatId = payload.chatId;
      const text = payload.text;
      const fromId = socket.user.id;
      const fromName = socket.user.login;
      const info = await runAsync("INSERT INTO messages (chatId, fromId, fromName, text) VALUES (?,?,?,?)", [chatId, fromId, fromName, text]);
      const msg = { id: info.lastID, chatId, fromId, fromName, text, created_at: Math.floor(Date.now() / 1000) };
      io.to('chat_' + chatId).emit('msg', msg);
    } catch (e) { console.error(e); }
  });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await getAsync("SELECT id,login,name,isAdmin,blocked FROM users WHERE id = ?", [req.user.id]);
  res.json(user);
});

server.listen(PORT, () => console.log(`TStore API running on port ${PORT}`));
