const express = require('express');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

dotenv.config();

const app = express();
app.use(helmet());
app.use(cors({ 
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true 
}));
app.use(express.json());
app.set('trust proxy', 1);

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const AES_KEY_HEX = process.env.AES_KEY || '';
const AES_KEY = Buffer.from(AES_KEY_HEX, 'hex');
const SESSION_SECRET = process.env.SESSION_SECRET || '';

if (!JWT_SECRET || AES_KEY.length !== 32 || !SESSION_SECRET) {
  console.error('Missing or invalid JWT_SECRET, AES_KEY, or SESSION_SECRET in .env');
  process.exit(1);
}

app.use(rateLimit({ windowMs: 60_000, max: 100 }));

// Session middleware for Passport
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set to true in production with HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());

// In-memory stores (replace with real DB in production)
const users = new Map(); // key = email
const vault = new Map(); // key = userId -> array of encrypted records

// AES-GCM encryption/decryption
function encryptAES(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    cipher: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    timestamp: Date.now()
  };
}

function decryptAES(record) {
  try {
    const iv = Buffer.from(record.iv, 'hex');
    const tag = Buffer.from(record.tag, 'hex');
    const encrypted = Buffer.from(record.cipher, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

// Auth helpers
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'missing_token' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.auth = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// ====== GOOGLE OAUTH2 SSO CONFIGURATION ======
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value;
      const name = profile.displayName;
      
      // Check if user exists
      let user = users.get(email);
      
      if (!user) {
        // Create new user from Google profile
        const id = `google_${Date.now()}`;
        user = {
          id,
          name,
          email,
          passwordHash: 'google-sso-managed',
          provider: 'google',
          googleId: profile.id
        };
        users.set(email, user);
        console.log(`New Google SSO user created: ${email}`);
      }
      
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser((email, done) => {
  const user = users.get(email);
  done(null, user);
});

// ====== GOOGLE SSO ROUTES ======
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${process.env.FRONTEND_URL}/login` }),
  (req, res) => {
    // Successful authentication, generate JWT
    const token = signToken(req.user);
    // Redirect back to frontend with token
    res.redirect(`${process.env.FRONTEND_URL}?token=${token}&email=${req.user.email}&name=${encodeURIComponent(req.user.name)}`);
  }
);

// ====== EXISTING ENDPOINTS ======
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!email || !password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'invalid_input' });
  }
  if (users.has(email)) return res.status(409).json({ error: 'user_exists' });

  const salt = await bcrypt.genSalt(12);
  const hash = await bcrypt.hash(password, salt);
  const id = `u_${Date.now()}`;
  users.set(email, { id, name: name || '', email, passwordHash: hash, provider: 'local' });
  return res.status(201).json({ ok: true });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = users.get(email);
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  
  // Check if user uses SSO
  if (user.provider === 'google') {
    return res.status(401).json({ error: 'use_google_sso' });
  }
  
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'invalid_credentials' });
  const token = signToken(user);
  return res.json({ token });
});

// Store encrypted data
app.post('/api/data', requireAuth, (req, res) => {
  const userId = req.auth.sub;
  const { title, content } = req.body || {};
  if (!title || !content) return res.status(400).json({ error: 'invalid_input' });

  const record = encryptAES({ title, content, userId });
  const entry = { id: `d_${Date.now()}`, ...record, owner: userId };
  const list = vault.get(userId) || [];
  list.push(entry);
  vault.set(userId, list);
  return res.status(201).json({ ok: true, id: entry.id });
});

// List encrypted data for user
app.get('/api/data', requireAuth, (req, res) => {
  const userId = req.auth.sub;
  const list = vault.get(userId) || [];
  return res.json(list);
});

// Decrypt single item (authenticated)
app.post('/api/data/:id/decrypt', requireAuth, (req, res) => {
  const userId = req.auth.sub;
  const id = req.params.id;
  const list = vault.get(userId) || [];
  const item = list.find(i => i.id === id);
  if (!item) return res.status(404).json({ error: 'not_found' });
  const plain = decryptAES(item);
  if (!plain) return res.status(500).json({ error: 'decrypt_failed' });
  return res.json({ data: plain });
});

app.listen(PORT, () => console.log(`✅ Auth server with Google SSO running on http://localhost:${PORT}`));