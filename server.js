const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
// Renderが指定するポート番号を使うように修正。なければ3001を使う。
const PORT = process.env.PORT || 3001; 
const JWT_SECRET = 'your-super-secret-key-for-this-app';

const db = new sqlite3.Database("./database.db", (err) => {
  if (err) console.error(err.message);
  else console.log("データベースに接続しました。");
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, type TEXT, specialty TEXT, location TEXT, details TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS interests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, target_id INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (target_id) REFERENCES users(id), UNIQUE(user_id, target_id))`);
    db.run(`CREATE TABLE IF NOT EXISTS matches (id INTEGER PRIMARY KEY AUTOINCREMENT, user1_id INTEGER NOT NULL, user2_id INTEGER NOT NULL, FOREIGN KEY (user1_id) REFERENCES users(id), FOREIGN KEY (user2_id) REFERENCES users(id), UNIQUE(user1_id, user2_id))`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches(id),
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )`);
});

app.use(cors());
app.use(express.json());

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- API Endpoints ---
// (Register, Login, Users, Profile APIs are unchanged)
app.post("/api/register", (req, res) => {
  const { name, email, password, type } = req.body;
  if (!name || !email || !password || !type) return res.status(400).json({ error: "すべての項目を入力してください。" });
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: "サーバーエラーが発生しました。" });
    const sql = 'INSERT INTO users (name, email, password, type) VALUES (?, ?, ?, ?)';
    db.run(sql, [name, email, hashedPassword, type], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) return res.status(409).json({ error: "このメールアドレスは既に使用されています。" });
        return res.status(500).json({ error: "データベースへの保存に失敗しました。" });
      }
      res.status(201).json({ message: "ユーザー登録が成功しました。", userId: this.lastID });
    });
  });
});
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "メールアドレスとパスワードを入力してください。" });
  const sql = "SELECT * FROM users WHERE email = ?";
  db.get(sql, [email], (err, user) => {
    if (err || !user) return res.status(401).json({ error: "メールアドレスまたはパスワードが正しくありません。" });
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) return res.status(401).json({ error: "メールアドレスまたはパスワードが正しくありません。" });
      const payload = { id: user.id, name: user.name, type: user.type };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
      res.json({ message: "ログインに成功しました。", token, user: { id: user.id, name: user.name, email: user.email, type: user.type }});
    });
  });
});
app.get("/api/users", (req, res) => {
  const sql = "SELECT id, name, type, specialty, location, details FROM users";
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(400).json({ "error": err.message });
    res.json(rows);
  });
});
app.get('/api/profile', verifyToken, (req, res) => {
    const sql = "SELECT id, name, email, type, specialty, location, details FROM users WHERE id = ?";
    db.get(sql, [req.user.id], (err, row) => {
        if (err) return res.status(400).json({ "error": err.message });
        res.json(row);
    });
});
app.put('/api/profile', verifyToken, (req, res) => {
    const { name, specialty, location, details } = req.body;
    const sql = `UPDATE users SET name = ?, specialty = ?, location = ?, details = ? WHERE id = ?`;
    db.run(sql, [name, specialty, location, details, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: "データベースの更新に失敗しました。" });
        res.json({ message: "プロフィールが更新されました。" });
    });
});
app.get('/api/interests', verifyToken, (req, res) => {
    const sql = "SELECT target_id FROM interests WHERE user_id = ?";
    db.all(sql, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: "データベースエラーが発生しました。" });
        const interestedIds = rows.map(row => row.target_id);
        res.json(interestedIds);
    });
});
app.post('/api/interests', verifyToken, (req, res) => {
    const { target_id } = req.body;
    const user_id = req.user.id;
    if (!target_id) return res.status(400).json({ error: "対象ユーザーIDが必要です。" });

    const insertInterestSql = 'INSERT INTO interests (user_id, target_id) VALUES (?, ?)';
    db.run(insertInterestSql, [user_id, target_id], function(err) {
        if (err && !err.message.includes('UNIQUE constraint failed')) return res.status(500).json({ error: "関心の保存に失敗しました。" });
        
        const checkMatchSql = 'SELECT * FROM interests WHERE user_id = ? AND target_id = ?';
        db.get(checkMatchSql, [target_id, user_id], (err, row) => {
            if (err) return res.status(201).json({ message: "関心を保存しました。", matched: false });

            if (row) {
                const user1 = Math.min(user_id, target_id);
                const user2 = Math.max(user_id, target_id);
                const insertMatchSql = 'INSERT INTO matches (user1_id, user2_id) VALUES (?, ?)';
                db.run(insertMatchSql, [user1, user2], (matchErr) => {
                    if (matchErr && !matchErr.message.includes('UNIQUE constraint failed')) {
                         console.error("マッチの保存に失敗:", matchErr);
                    }
                    return res.status(201).json({ message: "関心を保存しました。マッチング成立です！", matched: true });
                });
            } else {
                return res.status(201).json({ message: "関心を保存しました。", matched: false });
            }
        });
    });
});
app.get('/api/matches', verifyToken, (req, res) => {
    const userId = req.user.id;
    const sql = `
        SELECT 
            m.id as match_id, 
            u.*,
            (SELECT content FROM messages WHERE match_id = m.id ORDER BY timestamp DESC LIMIT 1) as latest_message,
            (SELECT COUNT(*) FROM messages WHERE match_id = m.id AND sender_id != ? AND is_read = 0) as unread_count
        FROM matches m
        JOIN users u ON (m.user1_id = u.id OR m.user2_id = u.id)
        WHERE (m.user1_id = ? OR m.user2_id = ?) AND u.id != ?
    `;
    db.all(sql, [userId, userId, userId, userId], (err, rows) => {
        if (err) return res.status(500).json({ error: "データベースエラーが発生しました。" });
        res.json(rows);
    });
});
app.get('/api/messages/:matchId', verifyToken, (req, res) => {
    const { matchId } = req.params;
    const sql = `SELECT * FROM messages WHERE match_id = ? ORDER BY timestamp ASC`;
    db.all(sql, [matchId], (err, rows) => {
        if (err) return res.status(500).json({ error: "メッセージの取得に失敗しました。" });
        res.json(rows);
    });
});
app.post('/api/messages', verifyToken, (req, res) => {
    const { match_id, content } = req.body;
    const sender_id = req.user.id;
    if (!match_id || !content) return res.status(400).json({ error: "必要な情報が不足しています。" });
    const sql = 'INSERT INTO messages (match_id, sender_id, content) VALUES (?, ?, ?)';
    db.run(sql, [match_id, sender_id, content], function(err) {
        if (err) return res.status(500).json({ error: "メッセージの送信に失敗しました。" });
        res.status(201).json({ message: "メッセージを送信しました。", messageId: this.lastID });
    });
});
app.put('/api/messages/read/:matchId', verifyToken, (req, res) => {
    const { matchId } = req.params;
    const userId = req.user.id;
    const sql = `UPDATE messages SET is_read = 1 WHERE match_id = ? AND sender_id != ?`;
    db.run(sql, [matchId, userId], function(err) {
        if (err) return res.status(500).json({ error: "メッセージの既読処理に失敗しました。" });
        res.json({ message: "メッセージを既読にしました。" });
    });
});

app.listen(PORT, () => {
  console.log(`サーバーがポート${PORT}で起動しました。`);
});

