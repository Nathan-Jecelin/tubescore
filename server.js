require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { extractVideoId, getVideoData, getChannelData } = require('./services/youtube');
const { analyzeVideo } = require('./services/analyzer');
const { stripe, createCheckoutSession, verifyProStatus, createBillingPortalSession } = require('./services/stripe');

const app = express();
const PORT = process.env.PORT || 3000;

// ── SQLite setup ──
const db = new Database(path.join(__dirname, 'tubescore.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    ip TEXT NOT NULL,
    month INTEGER NOT NULL,
    year INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, month, year)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT,
    video_id TEXT NOT NULL,
    video_title TEXT NOT NULL,
    channel_title TEXT NOT NULL,
    thumbnail_url TEXT,
    overall_grade TEXT,
    analysis_json TEXT NOT NULL,
    video_stats_json TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

const FREE_LIMIT = 3;
const SALT_ROUNDS = 10;
const SESSION_MAX_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days

// ── IP-based scan tracking (anonymous users) ──
const getStmt = db.prepare('SELECT count FROM scans WHERE ip = ? AND month = ? AND year = ?');
const upsertStmt = db.prepare(`
  INSERT INTO scans (ip, month, year, count) VALUES (?, ?, ?, 1)
  ON CONFLICT(ip, month, year) DO UPDATE SET count = count + 1
`);

function getScanCount(ip) {
  const now = new Date();
  const row = getStmt.get(ip, now.getMonth(), now.getFullYear());
  return row ? row.count : 0;
}

function incrementScanCount(ip) {
  const now = new Date();
  upsertStmt.run(ip, now.getMonth(), now.getFullYear());
}

// ── User scan count (logged-in free users) ──
function getUserScanCountThisMonth(userId) {
  const now = new Date();
  const firstOfMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01 00:00:00`;
  const row = db.prepare('SELECT COUNT(*) as count FROM scan_history WHERE user_id = ? AND created_at >= ?').get(userId, firstOfMonth);
  return row ? row.count : 0;
}

// ── Session helpers ──
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_MAX_AGE);
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expires.toISOString());
  return { token, expires };
}

function getUserFromSession(token) {
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.* FROM users u
    JOIN sessions s ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > datetime('now')
  `).get(token);
  return row || null;
}

function setSessionCookie(res, token, expires) {
  res.cookie('session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    expires,
    path: '/',
  });
}

// ── Auth middleware ──
function requireAuth(req, res, next) {
  const token = req.cookies?.session;
  const user = getUserFromSession(token);
  if (!user) return res.status(401).json({ error: 'Please log in.' });
  req.user = user;
  next();
}

function softAuth(req, res, next) {
  const token = req.cookies?.session;
  req.user = getUserFromSession(token);
  next();
}

// ── Stripe webhook (raw body — must be before express.json) ──
app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    console.log('Payment successful for:', session.customer_details?.email);

    const userId = session.metadata?.user_id;
    if (userId) {
      const amount = session.amount_total;
      const plan = amount >= 2900 ? 'agency' : 'pro';
      db.prepare(`
        UPDATE users SET plan = ?, stripe_customer_id = ?, stripe_subscription_id = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(plan, session.customer, session.subscription, userId);
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    const customerId = subscription.customer;
    db.prepare(`
      UPDATE users SET plan = 'free', stripe_subscription_id = NULL, updated_at = CURRENT_TIMESTAMP
      WHERE stripe_customer_id = ?
    `).run(customerId);
  }

  res.json({ received: true });
});

// ── Security headers ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "https://i.ytimg.com", "data:"],
      connectSrc: ["'self'"],
      frameSrc: ["https://checkout.stripe.com"],
    },
  },
}));

// ── CORS ──
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || true,
  credentials: true,
}));

// ── Rate limiting on API routes ──
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api/', apiLimiter);

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// ── Auth Routes ──
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'An account with this email already exists.' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, passwordHash);
    const userId = result.lastInsertRowid;

    const { token, expires } = createSession(userId);
    setSessionCookie(res, token, expires);

    res.json({ user: { id: userId, email, plan: 'free' } });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Failed to create account.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password.' });

    const { token, expires } = createSession(user.id);
    setSessionCookie(res, token, expires);

    res.json({ user: { id: user.id, email: user.email, plan: user.plan } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Failed to log in.' });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.cookies?.session;
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.clearCookie('session', { path: '/' });
  res.json({ success: true });
});

app.get('/api/auth/me', softAuth, (req, res) => {
  if (!req.user) return res.json({ user: null });
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      plan: req.user.plan,
    },
  });
});

// ── Main analysis endpoint ──
app.post('/api/analyze', softAuth, async (req, res) => {
  try {
    const { url, proToken } = req.body;
    if (!url) return res.status(400).json({ error: 'YouTube URL is required.' });

    const videoId = extractVideoId(url);
    if (!videoId) return res.status(400).json({ error: 'Invalid YouTube URL. Please paste a valid video link.' });

    // Check access
    let isPro = false;
    if (req.user) {
      isPro = req.user.plan === 'pro' || req.user.plan === 'agency';
      if (!isPro) {
        const count = getUserScanCountThisMonth(req.user.id);
        if (count >= FREE_LIMIT) {
          return res.status(429).json({
            error: 'Free scan limit reached. Upgrade to TubeScore Pro for unlimited scans.',
            limitReached: true,
          });
        }
      }
    } else if (proToken) {
      const status = await verifyProStatus(proToken);
      isPro = status.isPro;
      if (!isPro) {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const count = getScanCount(ip);
        if (count >= FREE_LIMIT) {
          return res.status(429).json({
            error: 'Free scan limit reached. Upgrade to TubeScore Pro for unlimited scans.',
            limitReached: true,
          });
        }
      }
    } else {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const count = getScanCount(ip);
      if (count >= FREE_LIMIT) {
        return res.status(429).json({
          error: 'Free scan limit reached. Upgrade to TubeScore Pro for unlimited scans.',
          limitReached: true,
        });
      }
    }

    // Fetch video and channel data
    const videoData = await getVideoData(videoId);
    const channelData = await getChannelData(videoData.channelId);

    // Run AI analysis
    const analysis = await analyzeVideo(videoData, channelData);

    const videoInfo = {
      id: videoData.id,
      title: videoData.title,
      channelTitle: videoData.channelTitle,
      thumbnail: videoData.thumbnails.high?.url || videoData.thumbnails.default?.url,
      viewCount: videoData.viewCount,
      likeCount: videoData.likeCount,
      commentCount: videoData.commentCount,
      subscriberCount: channelData.subscriberCount,
    };

    // Save to scan history
    db.prepare(`
      INSERT INTO scan_history (user_id, ip, video_id, video_title, channel_title, thumbnail_url, overall_grade, analysis_json, video_stats_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user?.id || null,
      req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      videoData.id,
      videoData.title,
      videoData.channelTitle,
      videoInfo.thumbnail,
      analysis.overall_grade,
      JSON.stringify(analysis),
      JSON.stringify(videoInfo)
    );

    // Increment anonymous scan count if not logged in and not pro
    if (!req.user && !isPro) {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      incrementScanCount(ip);
    }

    res.json({ video: videoInfo, analysis });
  } catch (err) {
    console.error('Analysis error:', err);
    res.status(500).json({ error: err.message || 'Something went wrong. Please try again.' });
  }
});

// ── Stripe checkout ──
app.post('/api/checkout', softAuth, async (req, res) => {
  try {
    const { plan } = req.body || {};
    const origin = req.headers.origin || `http://localhost:${PORT}`;

    const opts = {};
    if (req.user) {
      opts.metadata = { user_id: String(req.user.id) };
      if (req.user.stripe_customer_id) {
        opts.customer = req.user.stripe_customer_id;
      } else {
        opts.customer_email = req.user.email;
      }
    }

    const session = await createCheckoutSession(origin, plan || 'pro', opts);
    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session.' });
  }
});

// ── Verify pro status ──
app.get('/api/verify/:sessionId', async (req, res) => {
  try {
    const status = await verifyProStatus(req.params.sessionId);
    res.json(status);
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Failed to verify payment status.' });
  }
});

// ── History routes ──
app.get('/api/history', requireAuth, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;

  const rows = db.prepare(`
    SELECT id, video_id, video_title, channel_title, thumbnail_url, overall_grade, created_at
    FROM scan_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(req.user.id, limit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM scan_history WHERE user_id = ?').get(req.user.id);

  res.json({
    scans: rows,
    page,
    totalPages: Math.ceil(total.count / limit),
    total: total.count,
  });
});

app.get('/api/history/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM scan_history WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'Scan not found.' });

  res.json({
    ...row,
    analysis: JSON.parse(row.analysis_json),
    video: JSON.parse(row.video_stats_json),
  });
});

// ── Account routes ──
app.get('/api/account', requireAuth, (req, res) => {
  const scansUsed = getUserScanCountThisMonth(req.user.id);
  res.json({
    email: req.user.email,
    plan: req.user.plan,
    created_at: req.user.created_at,
    scans_used: scansUsed,
    scan_limit: req.user.plan === 'free' ? FREE_LIMIT : null,
  });
});

app.post('/api/account/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both current and new password are required.' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect.' });

    const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    db.prepare("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(newHash, req.user.id);

    res.json({ success: true });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ error: 'Failed to change password.' });
  }
});

app.post('/api/billing-portal', requireAuth, async (req, res) => {
  try {
    if (!req.user.stripe_customer_id) {
      return res.status(400).json({ error: 'No billing information found. Please subscribe first.' });
    }
    const origin = req.headers.origin || `http://localhost:${PORT}`;
    const session = await createBillingPortalSession(req.user.stripe_customer_id, origin);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Billing portal error:', err);
    res.status(500).json({ error: 'Failed to open billing portal.' });
  }
});

app.listen(PORT, () => {
  console.log(`TubeScore running at http://localhost:${PORT}`);
});
