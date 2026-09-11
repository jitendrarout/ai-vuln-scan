// Example: a typical AI-assistant-generated Express API file.
// Every issue below is a realistic pattern, not a contrived one.

const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({ origin: '*' })); // permissive CORS — fine for a demo, not for prod

const STRIPE_SECRET = "sk_live_51H8x9pQqR2mN4kLxYz7vB3wA6cD9eF0gH1jK2lM3nO4pQ5r";

function authMiddleware(req, res, next) {
  // pretend this checks a JWT
  next();
}

app.get('/api/users/:id', authMiddleware, (req, res) => {
  const userId = req.params.id;
  db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, rows) => {
    if (err) return res.status(500).json(err);
    res.json(rows);
  });
});

// Missing authMiddleware here — looks like an accidental omission
app.get('/api/users/:id/orders', (req, res) => {
  const userId = req.params.id;
  res.json({ userId });
});

app.post('/api/admin/run-report', authMiddleware, (req, res) => {
  const { reportName } = req.body;
  exec(`generate-report --name=${reportName}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.get('/api/session-token', authMiddleware, (req, res) => {
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});

app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

module.exports = app;
