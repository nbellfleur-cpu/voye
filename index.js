require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Railway Postgres SSL config
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        role VARCHAR(50) DEFAULT 'rider',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS driver_profiles (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        full_name VARCHAR(255),
        phone VARCHAR(50),
        license_number VARCHAR(100),
        license_expiry DATE,
        vehicle_make VARCHAR(100),
        vehicle_model VARCHAR(100),
        vehicle_year INTEGER,
        vehicle_color VARCHAR(50),
        plate_number VARCHAR(50),
        status VARCHAR(50) DEFAULT 'pending',
        submitted_at TIMESTAMP DEFAULT NOW(),
        reviewed_at TIMESTAMP
      )
    `);
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('DB init error:', err.message);
  }
}

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', app: 'Voye', version: '1.0.0' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'Voye' });
});

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const hashed = await bcrypt.hash(password, 10);
    const userRole = role === 'driver' ? 'driver' : 'rider';
    const result = await pool.query(
      'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, name, role',
      [email, hashed, name, userRole]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ user, token });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/register (alias)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const hashed = await bcrypt.hash(password, 10);
    const userRole = role === 'driver' ? 'driver' : 'rider';
    const result = await pool.query(
      'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, name, role',
      [email, hashed, name, userRole]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ user, token });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role }, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/profile
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, name, role, created_at FROM users WHERE id = $1', [req.user.id]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/driver/onboarding
app.post('/api/driver/onboarding', authMiddleware, async (req, res) => {
  try {
    const {
      full_name, phone, license_number, license_expiry,
      vehicle_make, vehicle_model, vehicle_year, vehicle_color, plate_number
    } = req.body;
    const existing = await pool.query('SELECT id FROM driver_profiles WHERE user_id = $1', [req.user.id]);
    if (existing.rows.length > 0) {
      const result = await pool.query(
        `UPDATE driver_profiles SET full_name=$1, phone=$2, license_number=$3, license_expiry=$4,
         vehicle_make=$5, vehicle_model=$6, vehicle_year=$7, vehicle_color=$8, plate_number=$9,
         status='pending', submitted_at=NOW()
         WHERE user_id=$10 RETURNING *`,
        [full_name, phone, license_number, license_expiry, vehicle_make, vehicle_model, vehicle_year, vehicle_color, plate_number, req.user.id]
      );
      return res.json({ message: 'Driver profile updated', profile: result.rows[0] });
    }
    const result = await pool.query(
      `INSERT INTO driver_profiles (user_id, full_name, phone, license_number, license_expiry,
       vehicle_make, vehicle_model, vehicle_year, vehicle_color, plate_number)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.user.id, full_name, phone, license_number, license_expiry, vehicle_make, vehicle_model, vehicle_year, vehicle_color, plate_number]
    );
    await pool.query("UPDATE users SET role='driver' WHERE id=$1", [req.user.id]);
    res.status(201).json({ message: 'Driver profile submitted', profile: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/driver/onboarding
app.get('/api/driver/onboarding', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM driver_profiles WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'No driver profile found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log('Voye API running on port ' + PORT);
  });
});
