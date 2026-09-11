// Example: the same routes, written safely — used to verify the scanner
// doesn't just flag everything indiscriminately.

const express = require('express');
const crypto = require('crypto');
const app = express();

const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;

function authMiddleware(req, res, next) {
  next();
}

app.get('/api/users/:id', authMiddleware, (req, res) => {
  const userId = req.params.id;
  db.query('SELECT * FROM users WHERE id = ?', [userId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(rows);
  });
});

app.get('/api/users/:id/orders', authMiddleware, (req, res) => {
  const userId = req.params.id;
  res.json({ userId });
});

app.get('/api/session-token', authMiddleware, (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.json({ token });
});

module.exports = app;
