import express from 'express';
import pg from 'pg';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'miff-secret-key-change-in-prod';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Database Connection
// ideally this comes from process.env.DATABASE_URL
const connectionString = "postgresql://neondb_owner:npg_Q8fsqMRcVW9m@ep-billowing-boat-a4hs75o2-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

const pool = new pg.Pool({
  connectionString,
});

// --- Database Initialization ---
const initDb = async () => {
  console.log("🔄 Connecting to Neon Database...");
  const client = await pool.connect();
  try {
    console.log("✅ Connected to DB. Starting initialization...");
    await client.query('BEGIN');

    // Enable pgcrypto for gen_random_uuid()
    await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
    console.log("✅ Extension pgcrypto enabled.");

    // 1. Users Table
    console.log("🔄 Creating users table...");
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'member', -- 'ADMIN', 'STAFF', 'ORGANISATION'
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    console.log("✅ Users table ensured.");

    // 2. Groups Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS groups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        institution_name TEXT NOT NULL,
        responsible_name TEXT NOT NULL,
        students_count INTEGER NOT NULL,
        participation_type TEXT NOT NULL,
        morning_location TEXT,
        afternoon_location TEXT,
        festival_date TEXT NOT NULL,
        first_receiver_id TEXT,
        guide_id TEXT,
        created_by TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 3. Invitations Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS invitations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        invitations_count INTEGER DEFAULT 1,
        invitation_type TEXT,
        status TEXT DEFAULT 'PENDING',
        festival_date TEXT NOT NULL,
        assigned_to TEXT NOT NULL,
        sent_by TEXT,
        sent_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 4. Badges Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS badges (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        type TEXT NOT NULL,
        holder_name TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_data TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 5. Contacts Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        phone TEXT NOT NULL,
        category TEXT NOT NULL,
        notes TEXT,
        created_by TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 6. Notes Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS notes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        festival_date TEXT NOT NULL,
        author_id TEXT NOT NULL,
        title TEXT,
        content TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 7. Reminders Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS reminders (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        festival_date TEXT NOT NULL,
        title TEXT NOT NULL,
        time TEXT NOT NULL,
        details TEXT,
        created_by TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 8. Drive Files Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS drive_files (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        uploader_id TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_data TEXT NOT NULL,
        file_type TEXT,
        size BIGINT,
        visibility TEXT NOT NULL,
        target_user_id TEXT,
        description TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 9. Team Status Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS team_status (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id TEXT NOT NULL,
        festival_date TEXT NOT NULL,
        status_text TEXT NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 10. Categories Table
    await client.query(`
        CREATE TABLE IF NOT EXISTS categories (
            name TEXT PRIMARY KEY
        );
    `);
    await client.query(`INSERT INTO categories (name) VALUES ('Institution'), ('Transport'), ('Security'), ('Tech') ON CONFLICT DO NOTHING;`);

    // 11. Logs Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target TEXT,
        festival_date TEXT,
        timestamp TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // --- SEED / RESET ADMIN ---
    console.log("Checking for admin user...");

    // DEBUG: Check columns & Auto-fix Schema
    const columnsRes = await client.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'users';
    `);
    const columns = columnsRes.rows.map(r => r.column_name);
    console.log("🔎 Current columns:", columns.join(', '));

    if (!columns.includes('password_hash')) {
      console.log("⚠️ 'password_hash' column missing!");
      if (columns.includes('password')) {
        console.log("🔄 Renaming 'password' to 'password_hash'...");
        await client.query('ALTER TABLE users RENAME COLUMN password TO password_hash');
      } else {
        console.log("➕ Adding 'password_hash' column...");
        await client.query('ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT \'\'');
      }
    }

    // Ensure other critical columns exist
    if (!columns.includes('role')) {
      console.log("➕ Adding 'role' column...");
      await client.query("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member'");
    }
    if (!columns.includes('is_active')) {
      console.log("➕ Adding 'is_active' column...");
      await client.query("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE");
    }

    const adminRes = await client.query("SELECT * FROM users WHERE username = 'admin'");
    const defaultPassword = 'admin123';
    const hash = await bcrypt.hash(defaultPassword, 10);

    if (adminRes.rows.length === 0) {
      console.log('🌱 Admin user not found. Creating...');
      await client.query(`
        INSERT INTO users (name, username, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4, $5)
      `, ['Super Admin', 'admin', hash, 'ADMIN', true]);
      console.log("✅ Admin user created.");
    } else {
      console.log('🔄 Admin user exists. Updating password to ensure access...');
      await client.query(`
        UPDATE users SET password_hash = $1, is_active = TRUE, role = 'ADMIN' WHERE username = 'admin'
      `, [hash]);
      console.log("✅ Admin password reset to 'admin123'.");
    }

    console.log(`
    ------------------------------------------------
    ✅ LOGIN CREDENTIALS (GUARANTEED):
    Username: admin
    Password: admin123
    ------------------------------------------------
    `);

    await client.query('COMMIT');
    console.log("✅ Database initialized successfully.");
  } catch (e) {
    await client.query('ROLLBACK');
    console.error("❌ Error initializing database:", e);
  } finally {
    client.release();
  }
};

// Initialize DB on startup
initDb();

// --- Auth Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(401); // Changed from 403 to 401
    req.user = user;
    next();
  });
};

// --- Routes ---

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  console.log(`🔐 Login attempt for: ${username}`);

  try {
    // 1. Find user by username
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      console.log(`❌ User not found: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      console.log(`❌ User inactive: ${username}`);
      return res.status(401).json({ error: 'Account disabled' });
    }

    // 2. Check password
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (isValid) {
      console.log(`✅ Login successful for: ${username}`);
      // 3. Generate Token
      const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

      // Remove sensitive data
      delete user.password_hash;

      res.json({ token, user });
    } else {
      console.log(`❌ Invalid password for: ${username}`);
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get Current User (Me)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, name, role, is_active, created_at, updated_at FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.sendStatus(404);
    }
  } catch (e) {
    res.sendStatus(500);
  }
});

// --- API Endpoints for Entities ---

// Users (Admin only)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, name, role, is_active, created_at FROM users ORDER BY name');
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.sendStatus(403);

  const { username, password, name, role, isActive } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, name, role, is_active) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, username, name, role, is_active`,
      [username, hash, name, role, isActive]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(400).json({ error: e.message }); // likely unique constraint violation
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, username, password, role, isActive } = req.body;

  // Security check
  if (req.user.id !== id && req.user.role !== 'ADMIN') return res.sendStatus(403);

  try {
    let query = 'UPDATE users SET name = $1, username = $2, updated_at = NOW()';
    let params = [name, username];
    let idx = 3;

    if (password) {
      const hash = await bcrypt.hash(password, 10);
      query += `, password_hash = $${idx++}`;
      params.push(hash);
    }

    // Only admin updates role/active
    if (req.user.role === 'ADMIN') {
      if (role) { query += `, role = $${idx++}`; params.push(role); }
      if (typeof isActive === 'boolean') { query += `, is_active = $${idx++}`; params.push(isActive); }
    }

    query += ` WHERE id = $${idx} RETURNING id, username, name, role, is_active`;
    params.push(id);

    const result = await pool.query(query, params);
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.sendStatus(403);
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.sendStatus(204);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Groups
app.get('/api/groups', authenticateToken, async (req, res) => {
  const { date } = req.query;
  try {
    let query = 'SELECT * FROM groups';
    let params = [];
    if (date) {
      query += ' WHERE festival_date = $1';
      params.push(date);
    }
    const result = await pool.query(query, params);
    const mapped = result.rows.map(r => ({
      id: r.id,
      institutionName: r.institution_name,
      responsibleName: r.responsible_name,
      studentsCount: r.students_count,
      participationType: r.participation_type,
      morningLocation: r.morning_location,
      afternoonLocation: r.afternoon_location,
      festivalDate: r.festival_date,
      firstReceiverId: r.first_receiver_id,
      guideId: r.guide_id,
      createdBy: r.created_by,
      createdAt: r.created_at
    }));
    res.json(mapped);
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
  const { institutionName, responsibleName, studentsCount, participationType, morningLocation, afternoonLocation, festivalDate, firstReceiverId, guideId, createdBy } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO groups (institution_name, responsible_name, students_count, participation_type, morning_location, afternoon_location, festival_date, first_receiver_id, guide_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [institutionName, responsibleName, studentsCount, participationType, morningLocation, afternoonLocation, festivalDate, firstReceiverId, guideId, createdBy]
    );
    res.json(result.rows[0]);
  } catch (e) { res.status(500).send(e.message); }
});

app.put('/api/groups/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { institutionName, responsibleName, studentsCount, participationType, morningLocation, afternoonLocation, firstReceiverId, guideId } = req.body;
  await pool.query(
    `UPDATE groups SET institution_name=$1, responsible_name=$2, students_count=$3, participation_type=$4, morning_location=$5, afternoon_location=$6, first_receiver_id=$7, guide_id=$8, updated_at=NOW() 
         WHERE id=$9`,
    [institutionName, responsibleName, studentsCount, participationType, morningLocation, afternoonLocation, firstReceiverId, guideId, id]
  );
  res.sendStatus(200);
});

app.delete('/api/groups/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM groups WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// Invitations
app.get('/api/invitations', authenticateToken, async (req, res) => {
  const { date } = req.query;
  try {
    let query = 'SELECT * FROM invitations';
    let params = [];
    if (date) {
      query += ' WHERE festival_date = $1';
      params.push(date);
    }
    const result = await pool.query(query, params);
    const mapped = result.rows.map(r => ({
      id: r.id,
      name: r.name,
      phone: r.phone,
      invitationsCount: r.invitations_count,
      invitationType: r.invitation_type,
      status: r.status,
      festivalDate: r.festival_date,
      assignedTo: r.assigned_to,
      sentBy: r.sent_by,
      sentAt: r.sent_at
    }));
    res.json(mapped);
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/invitations', authenticateToken, async (req, res) => {
  const { name, phone, invitationsCount, invitationType, status, festivalDate, assignedTo } = req.body;
  const result = await pool.query(
    `INSERT INTO invitations (name, phone, invitations_count, invitation_type, status, festival_date, assigned_to)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
    [name, phone, invitationsCount, invitationType, status, festivalDate, assignedTo]
  );
  res.json(result.rows[0]);
});

app.post('/api/invitations/batch', authenticateToken, async (req, res) => {
  const invites = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const i of invites) {
      await client.query(
        `INSERT INTO invitations (name, phone, invitations_count, invitation_type, status, festival_date, assigned_to)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [i.name, i.phone, i.invitationsCount, i.invitationType, i.status, i.festivalDate, i.assignedTo]
      );
    }
    await client.query('COMMIT');
    res.sendStatus(201);
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.put('/api/invitations/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, phone, invitationsCount, invitationType, status, sentBy } = req.body;

  if (status === 'SENT' || status === 'FAILED') {
    await pool.query(
      `UPDATE invitations SET status=$1, sent_by=$2, sent_at=NOW(), updated_at=NOW() WHERE id=$3`,
      [status, sentBy, id]
    );
  } else {
    await pool.query(
      `UPDATE invitations SET name=$1, phone=$2, invitations_count=$3, invitation_type=$4, updated_at=NOW() WHERE id=$5`,
      [name, phone, invitationsCount, invitationType, id]
    );
  }
  res.sendStatus(200);
});

app.delete('/api/invitations/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM invitations WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// Drive
app.get('/api/drive', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM drive_files ORDER BY created_at DESC');
    const mapped = result.rows.map(r => ({
      id: r.id,
      uploaderId: r.uploader_id,
      fileName: r.file_name,
      fileData: r.file_data,
      fileType: r.file_type,
      size: parseInt(r.size),
      visibility: r.visibility,
      targetUserId: r.target_user_id,
      description: r.description,
      createdAt: r.created_at
    }));
    res.json(mapped);
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/drive', authenticateToken, async (req, res) => {
  const { uploaderId, fileName, fileData, fileType, size, visibility, targetUserId, description } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO drive_files (uploader_id, file_name, file_data, file_type, size, visibility, target_user_id, description)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [uploaderId, fileName, fileData, fileType, size, visibility, targetUserId, description]
    );
    res.json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "File upload failed" });
  }
});

app.delete('/api/drive/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM drive_files WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// Status
app.get('/api/status', authenticateToken, async (req, res) => {
  const { date } = req.query;
  try {
    const result = await pool.query('SELECT * FROM team_status WHERE festival_date = $1', [date]);
    const mapped = result.rows.map(r => ({
      id: r.id,
      userId: r.user_id,
      festivalDate: r.festival_date,
      statusText: r.status_text,
      updatedAt: r.updated_at
    }));
    res.json(mapped);
  } catch (e) { res.status(500).send(e.message); }
});

app.put('/api/status', authenticateToken, async (req, res) => {
  const { userId, festivalDate, statusText } = req.body;
  try {
    const existing = await pool.query('SELECT id FROM team_status WHERE user_id=$1 AND festival_date=$2', [userId, festivalDate]);
    if (existing.rows.length > 0) {
      await pool.query('UPDATE team_status SET status_text=$1, updated_at=NOW() WHERE id=$2', [statusText, existing.rows[0].id]);
    } else {
      await pool.query('INSERT INTO team_status (user_id, festival_date, status_text) VALUES ($1, $2, $3)', [userId, festivalDate, statusText]);
    }
    res.sendStatus(200);
  } catch (e) { res.status(500).send(e.message); }
});

// Badges
app.get('/api/badges', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM badges');
    const mapped = result.rows.map(r => ({
      id: r.id,
      type: r.type,
      holderName: r.holder_name,
      fileName: r.file_name,
      fileData: r.file_data,
      createdBy: r.created_by,
      createdAt: r.created_at
    }));
    res.json(mapped);
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/badges', authenticateToken, async (req, res) => {
  const { type, holderName, fileName, fileData, createdBy } = req.body;
  await pool.query(
    `INSERT INTO badges (type, holder_name, file_name, file_data, created_by) VALUES ($1, $2, $3, $4, $5)`,
    [type, holderName, fileName, fileData, createdBy]
  );
  res.sendStatus(201);
});

app.delete('/api/badges/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM badges WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// Contacts
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM contacts');
    res.json(result.rows.map(r => ({
      id: r.id,
      name: r.name,
      role: r.role,
      phone: r.phone,
      category: r.category,
      notes: r.notes,
      createdBy: r.created_by
    })));
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
  const { name, role, phone, category, notes, createdBy } = req.body;
  await pool.query(
    `INSERT INTO contacts (name, role, phone, category, notes, created_by) VALUES ($1, $2, $3, $4, $5, $6)`,
    [name, role, phone, category, notes, createdBy]
  );
  res.sendStatus(201);
});

app.put('/api/contacts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, role, phone, category, notes } = req.body;
  await pool.query(
    `UPDATE contacts SET name=$1, role=$2, phone=$3, category=$4, notes=$5 WHERE id=$6`,
    [name, role, phone, category, notes, id]
  );
  res.sendStatus(200);
});

app.delete('/api/contacts/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM contacts WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// Categories
app.get('/api/categories', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT name FROM categories');
  res.json(result.rows.map(r => r.name));
});

app.post('/api/categories', authenticateToken, async (req, res) => {
  const { name } = req.body;
  await pool.query('INSERT INTO categories (name) VALUES ($1) ON CONFLICT DO NOTHING', [name]);
  res.sendStatus(201);
});

// Notes
app.get('/api/notes', authenticateToken, async (req, res) => {
  const { date } = req.query;
  try {
    const result = await pool.query('SELECT * FROM notes WHERE festival_date = $1', [date]);
    res.json(result.rows.map(r => ({
      id: r.id,
      festivalDate: r.festival_date,
      authorId: r.author_id,
      title: r.title,
      content: r.content,
      createdAt: r.created_at
    })));
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/notes', authenticateToken, async (req, res) => {
  const { festivalDate, authorId, title, content } = req.body;
  await pool.query(
    `INSERT INTO notes (festival_date, author_id, title, content) VALUES ($1, $2, $3, $4)`,
    [festivalDate, authorId, title, content]
  );
  res.sendStatus(201);
});

app.put('/api/notes/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;
  await pool.query(
    `UPDATE notes SET title=$1, content=$2 WHERE id=$3`,
    [title, content, id]
  );
  res.sendStatus(200);
});

app.delete('/api/notes/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM notes WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// Reminders
app.get('/api/reminders', authenticateToken, async (req, res) => {
  const { date } = req.query;
  try {
    const result = await pool.query('SELECT * FROM reminders WHERE festival_date = $1', [date]);
    res.json(result.rows.map(r => ({
      id: r.id,
      festivalDate: r.festival_date,
      title: r.title,
      time: r.time,
      details: r.details,
      createdBy: r.created_by,
      createdAt: r.created_at
    })));
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/reminders', authenticateToken, async (req, res) => {
  const { festivalDate, title, time, details, createdBy } = req.body;
  await pool.query(
    `INSERT INTO reminders (festival_date, title, time, details, created_by) VALUES ($1, $2, $3, $4, $5)`,
    [festivalDate, title, time, details, createdBy]
  );
  res.sendStatus(201);
});

app.delete('/api/reminders/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM reminders WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// Logs
app.get('/api/logs', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100');
    res.json(result.rows.map(r => ({
      id: r.id,
      userId: r.user_id,
      actionType: r.action_type,
      target: r.target,
      festivalDate: r.festival_date,
      timestamp: r.timestamp
    })));
  } catch (e) { res.status(500).send(e.message); }
});

app.post('/api/logs', authenticateToken, async (req, res) => {
  const { userId, actionType, target, festivalDate } = req.body;
  await pool.query(
    `INSERT INTO logs (user_id, action_type, target, festival_date) VALUES ($1, $2, $3, $4)`,
    [userId, actionType, target, festivalDate]
  );
  res.sendStatus(201);
});

// Health Check
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM users');
    res.json({
      status: 'ok',
      database: 'connected',
      userCount: result.rows[0].count
    });
  } catch (e) {
    res.status(500).json({
      status: 'error',
      database: 'disconnected',
      error: e.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
