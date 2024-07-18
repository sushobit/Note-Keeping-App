const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 5000;

app.use(cors());
app.use(bodyParser.json());

// Connect to SQLite database
const db = new sqlite3.Database('./database.sqlite');

// Create tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    title TEXT,
    content TEXT,
    tags TEXT,
    color TEXT,
    archived INTEGER,
    deletedAt DATETIME
  )`);
});

// User authentication endpoints
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
    if (err) return res.status(500).send("Error registering user.");

    const token = jwt.sign({ id: this.lastID }, 'secret', { expiresIn: 86400 });
    res.status(200).send({ auth: true, token });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send({ auth: false, token: null });
    }

    const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: 86400 });
    res.status(200).send({ auth: true, token });
  });
});

// Middleware to verify JWT
function verifyJWT(req, res, next) {
  const token = req.headers['x-access-token'];
  if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });

  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

    req.userId = decoded.id;
    next();
  });
}

// CRUD operations for notes
app.post('/notes', verifyJWT, (req, res) => {
  const { title, content, tags, color } = req.body;
  db.run('INSERT INTO notes (userId, title, content, tags, color, archived, deletedAt) VALUES (?, ?, ?, ?, ?, 0, NULL)',
    [req.userId, title, content, tags, color], function (err) {
      if (err) return res.status(500).send("Error creating note.");

      res.status(200).send({ id: this.lastID });
    });
});

app.get('/notes', verifyJWT, (req, res) => {
  db.all('SELECT * FROM notes WHERE userId = ? AND deletedAt IS NULL', [req.userId], (err, rows) => {
    if (err) return res.status(500).send("Error fetching notes.");

    res.status(200).send(rows);
  });
});

// Edit note
app.put('/notes/:id', verifyJWT, (req, res) => {
  const { title, content, tags, color } = req.body;
  console.log(`Updating note ID: ${req.params.id}`);
  db.run('UPDATE notes SET title = ?, content = ?, tags = ?, color = ? WHERE id = ? AND userId = ?',
    [title, content, tags, color, req.params.id, req.userId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send("Error updating note.");
      }

      res.status(200).send("Note updated successfully.");
    });
});

// Delete note
app.delete('/notes/:id', verifyJWT, (req, res) => {
  console.log(`Deleting note ID: ${req.params.id}`);
  db.run('UPDATE notes SET deletedAt = CURRENT_TIMESTAMP WHERE id = ? AND userId = ?', [req.params.id, req.userId], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).send("Error deleting note.");
    }

    res.status(200).send("Note deleted successfully.");
  });
});


// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
