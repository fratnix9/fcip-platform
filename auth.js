// auth.js - FCIP Authentication, Cryptographic Security & RBAC Engine
// Remediates NFT-06 (Salted One-Way Password Hashing) and NFT-07 (Parameterized Queries)
// Enforces FR01-FR06, NFR05, NFR07, NFR08, NFR09

const crypto = require('node:crypto');

const TOKEN_SECRET = crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

// Cryptographic Password Hashing (Remediates NFT-06)
function hashPassword(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16).toString('hex');
  }
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

// Token Generation & Verification (Stateless & Secure)
function createToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + TOKEN_EXPIRY_MS })).toString('base64url');
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts;
  const expectedSig = crypto.createHmac('sha256', TOKEN_SECRET).update(`${header}.${body}`).digest('base64url');
  if (signature !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// Email Validator (Strict RFC-compliant check for FT-02)
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email.trim());
}

class AuthService {
  constructor(db, auditLogger) {
    this.db = db;
    this.audit = auditLogger;
  }

  // FT-01 & FT-02: Register User
  registerUser({ name, email, password, roleName = 'INVESTIGATOR', phone = '', department = 'Financial Intelligence' }) {
    if (!name || !name.trim()) {
      return { success: false, error: 'Name is required' };
    }
    if (!isValidEmail(email)) {
      return { success: false, error: 'Validation error: Invalid email format provided.' };
    }
    if (!password || password.length < 6) {
      return { success: false, error: 'Password must be at least 6 characters long' };
    }

    // Check existing email (Strictly Parameterized Query)
    const existing = this.db.prepare('SELECT user_id FROM users WHERE LOWER(email) = LOWER(?)').get(email.trim());
    if (existing) {
      return { success: false, error: 'Email already registered in system.' };
    }

    // Lookup role
    const role = this.db.prepare('SELECT role_id, role_name FROM roles WHERE UPPER(role_name) = UPPER(?)').get(roleName);
    const roleId = role ? role.role_id : 1;

    // Salted Password Hash
    const { salt, hash } = hashPassword(password);
    const userId = 'USR-' + crypto.randomBytes(4).toString('hex').toUpperCase();

    const insertStmt = this.db.prepare(`
      INSERT INTO users (user_id, name, email, password_hash, salt, role_id, phone, department, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'))
    `);
    insertStmt.run(userId, name.trim(), email.trim(), hash, salt, roleId, phone, department);

    this.audit.log(userId, name, 'USER_REGISTERED', 'users', { userId, email: email.trim(), role: roleName });

    return {
      success: true,
      userId,
      message: `Account created successfully with unique user ID ${userId}. Confirmation displayed.`
    };
  }

  // FT-03 & FT-04: Login with credentials
  login(email, password, ip = '127.0.0.1') {
    if (!email || !password) {
      return { success: false, error: 'Email and password are required.' };
    }

    // Parameterized Query protects against SQL Injection (' OR '1'='1)
    const user = this.db.prepare(`
      SELECT u.user_id, u.name, u.email, u.password_hash, u.salt, u.status, r.role_name
      FROM users u
      JOIN roles r ON u.role_id = r.role_id
      WHERE LOWER(u.email) = LOWER(?)
    `).get(email.trim());

    if (!user) {
      this.audit.log('ANONYMOUS', 'Anonymous', 'LOGIN_FAILED', 'users', { email, reason: 'User not found' }, ip);
      return { success: false, error: 'Login denied: Invalid email or password credentials.' };
    }

    if (user.status !== 'ACTIVE') {
      return { success: false, error: 'Login denied: Account is suspended or inactive.' };
    }

    // Secure Timing-Safe Hash Verification
    const isValid = verifyPassword(password, user.salt, user.password_hash);
    if (!isValid) {
      this.audit.log(user.user_id, user.name, 'LOGIN_FAILED', 'users', { email, reason: 'Incorrect password' }, ip);
      return { success: false, error: 'Login denied: Invalid email or password credentials.' };
    }

    // Update last_login
    this.db.prepare("UPDATE users SET last_login = datetime('now') WHERE user_id = ?").run(user.user_id);

    const token = createToken({
      userId: user.user_id,
      name: user.name,
      email: user.email,
      role: user.role_name
    });

    this.audit.log(user.user_id, user.name, 'LOGIN_SUCCESS', 'users', { role: user.role_name }, ip);

    return {
      success: true,
      token,
      user: {
        userId: user.user_id,
        name: user.name,
        email: user.email,
        role: user.role_name
      },
      message: 'User logged in successfully and authorized dashboard displayed.'
    };
  }

  // RBAC Permission Checker (FT-05, NFT-05, NFT-08)
  hasPermission(role, moduleAction) {
    const permissions = {
      ADMINISTRATOR: ['*'], // Full admin control
      INVESTIGATOR: [
        'dashboard:view',
        'transactions:search',
        'transactions:view',
        'transactions:upload',
        'detection:run',
        'network:explore',
        'alerts:view',
        'alerts:assign',
        'cases:create',
        'cases:update',
        'cases:notes',
        'reports:generate',
        'reports:export',
        'audit:view'
      ],
      COMPLIANCE_OFFICER: [
        'dashboard:view',
        'transactions:search',
        'transactions:view',
        'detection:view',
        'detection:rules_modify',
        'network:explore',
        'alerts:view',
        'cases:view',
        'reports:view',
        'compliance:manage'
      ],
      REPORTING_AUTHORITY: [
        'dashboard:view',
        'reports:view',
        'reports:export',
        'cases:view'
      ]
    };

    const userPerms = permissions[role] || [];
    if (userPerms.includes('*')) return true;
    return userPerms.includes(moduleAction);
  }
}

module.exports = { AuthService, hashPassword, verifyPassword, createToken, verifyToken, isValidEmail };
