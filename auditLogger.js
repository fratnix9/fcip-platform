// auditLogger.js - FCIP Secure Activity and Audit Logging Subsystem
// Enforces NFR18 (Auditability), NFR19 (Logging & Monitoring), and NFT-15 (Secret Masking)

const SENSITIVE_KEYS = ['password', 'password_hash', 'salt', 'token', 'secret', 'authorization', 'credential'];

function sanitizeDetails(data) {
  if (!data) return '';
  if (typeof data === 'string') {
    let sanitized = data;
    for (const key of SENSITIVE_KEYS) {
      const regex = new RegExp(`("${key}"\\s*:\\s*")[^"]*(")`, 'gi');
      sanitized = sanitized.replace(regex, `$1[REDACTED]$2`);
      const kvRegex = new RegExp(`(${key}\\s*=\\s*)[^&,\\s]+`, 'gi');
      sanitized = sanitized.replace(kvRegex, `$1[REDACTED]`);
    }
    return sanitized;
  }
  if (typeof data === 'object') {
    const copy = Array.isArray(data) ? [...data] : { ...data };
    for (const k of Object.keys(copy)) {
      if (SENSITIVE_KEYS.some(sk => k.toLowerCase().includes(sk))) {
        copy[k] = '[REDACTED]';
      } else if (typeof copy[k] === 'object' && copy[k] !== null) {
        copy[k] = JSON.parse(sanitizeDetails(JSON.stringify(copy[k])));
      }
    }
    return JSON.stringify(copy);
  }
  return String(data);
}

class AuditLogger {
  constructor(db) {
    this.db = db;
  }

  log(userId, userName, action, targetEntity, details = {}, ip = '127.0.0.1') {
    try {
      const sanitized = typeof details === 'string' ? sanitizeDetails(details) : sanitizeDetails(details);
      const stmt = this.db.prepare(`
        INSERT INTO audit_logs (user_id, user_name, action, target_entity, details, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
      `);
      stmt.run(userId || 'SYSTEM', userName || 'System', action, targetEntity, sanitized, ip);
      console.log(`[AUDIT] [${new Date().toISOString()}] ${action} on ${targetEntity} by ${userName || 'SYSTEM'}`);
    } catch (err) {
      console.error('[AUDIT_ERROR] Failed to record audit log:', err.message);
    }
  }

  getRecentLogs(limit = 100) {
    try {
      const stmt = this.db.prepare(`
        SELECT log_id, user_id, user_name, action, target_entity, details, ip_address, timestamp
        FROM audit_logs
        ORDER BY log_id DESC
        LIMIT ?
      `);
      return stmt.all(limit);
    } catch (err) {
      console.error('[AUDIT_ERROR] Failed to fetch logs:', err.message);
      return [];
    }
  }
}

module.exports = { AuditLogger, sanitizeDetails };
