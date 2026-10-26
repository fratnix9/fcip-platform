// database.js - FCIP SQLite Database Engine & Data Model Layer
// Implements Figures 1-4 (ERD & DFD Data Stores D1-D10)
// Guarantees Parameterized Prepared Statements (NFT-07) & High-Performance Indexes (NFT-01, NFT-12)

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const { hashPassword } = require('./auth');

const DB_PATH = path.join(__dirname, 'data', 'fcip.sqlite');

class DatabaseEngine {
  constructor(dbPath = DB_PATH) {
    // Ensure data directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.dbPath = dbPath;
    this.db = new DatabaseSync(dbPath);
    this.initPragmas();
    this.createTables();
    this.createIndexes();
    this.seedInitialData();
  }

  initPragmas() {
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA synchronous = NORMAL;');
  }

  createTables() {
    this.db.exec(`
      -- D1: User Database
      CREATE TABLE IF NOT EXISTS roles (
        role_id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT UNIQUE NOT NULL,
        description TEXT
      );

      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role_id INTEGER NOT NULL,
        phone TEXT,
        department TEXT,
        status TEXT DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL,
        last_login TEXT,
        FOREIGN KEY (role_id) REFERENCES roles(role_id)
      );

      -- D2: Customer Database
      CREATE TABLE IF NOT EXISTS customers (
        customer_id TEXT PRIMARY KEY,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        address TEXT,
        customer_type TEXT DEFAULT 'INDIVIDUAL',
        risk_rating TEXT DEFAULT 'LOW',
        created_at TEXT NOT NULL
      );

      -- D3: Account Database
      CREATE TABLE IF NOT EXISTS accounts (
        account_id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        account_type TEXT DEFAULT 'CHECKING',
        balance REAL DEFAULT 0.0,
        currency TEXT DEFAULT 'USD',
        status TEXT DEFAULT 'ACTIVE',
        open_date TEXT NOT NULL,
        branch TEXT,
        FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
      );

      -- D4: Transaction Database
      CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        txn_code TEXT UNIQUE NOT NULL,
        sender_account_id TEXT NOT NULL,
        receiver_account_id TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'USD',
        transaction_date TEXT NOT NULL,
        channel TEXT DEFAULT 'Wire',
        description TEXT,
        status TEXT DEFAULT 'COMPLETED',
        FOREIGN KEY (sender_account_id) REFERENCES accounts(account_id),
        FOREIGN KEY (receiver_account_id) REFERENCES accounts(account_id)
      );

      -- D5: Detection Rules Database
      CREATE TABLE IF NOT EXISTS detection_rules (
        rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_code TEXT UNIQUE NOT NULL,
        rule_name TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        threshold_amount REAL,
        time_window_hours INTEGER DEFAULT 24,
        status TEXT DEFAULT 'ACTIVE',
        severity TEXT DEFAULT 'HIGH',
        description TEXT
      );

      -- D6: Risk & Pattern Database
      CREATE TABLE IF NOT EXISTS suspicious_patterns (
        pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_code TEXT UNIQUE NOT NULL,
        pattern_name TEXT NOT NULL,
        pattern_type TEXT NOT NULL,
        severity TEXT DEFAULT 'HIGH',
        description TEXT,
        detected_count INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS risk_scores (
        risk_score_id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        score REAL NOT NULL,
        risk_level TEXT NOT NULL,
        calculated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS risk_factors (
        factor_id INTEGER PRIMARY KEY AUTOINCREMENT,
        risk_score_id INTEGER NOT NULL,
        factor_category TEXT NOT NULL,
        factor_name TEXT NOT NULL,
        score_contribution REAL NOT NULL,
        weight REAL NOT NULL,
        description TEXT,
        FOREIGN KEY (risk_score_id) REFERENCES risk_scores(risk_score_id)
      );

      CREATE TABLE IF NOT EXISTS transaction_paths (
        path_id INTEGER PRIMARY KEY AUTOINCREMENT,
        root_entity_id TEXT NOT NULL,
        destination_entity_id TEXT NOT NULL,
        hops_json TEXT NOT NULL,
        total_flow REAL NOT NULL,
        pattern_detected TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS entity_relationships (
        relationship_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_account_id TEXT NOT NULL,
        target_account_id TEXT NOT NULL,
        relationship_type TEXT DEFAULT 'TRANSFER',
        strength REAL DEFAULT 1.0,
        transaction_count INTEGER DEFAULT 1,
        total_volume REAL DEFAULT 0.0,
        FOREIGN KEY (source_account_id) REFERENCES accounts(account_id),
        FOREIGN KEY (target_account_id) REFERENCES accounts(account_id)
      );

      -- D7: Alert Database
      CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT UNIQUE NOT NULL,
        transaction_id INTEGER,
        entity_type TEXT DEFAULT 'TRANSACTION',
        entity_id TEXT NOT NULL,
        severity TEXT DEFAULT 'HIGH',
        status TEXT DEFAULT 'NEW',
        pattern_code TEXT,
        score REAL DEFAULT 0.0,
        explanation TEXT,
        created_at TEXT NOT NULL,
        assigned_to TEXT,
        FOREIGN KEY (transaction_id) REFERENCES transactions(id),
        FOREIGN KEY (assigned_to) REFERENCES users(user_id)
      );

      -- D8: Investigation Database
      CREATE TABLE IF NOT EXISTS investigation_cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE NOT NULL,
        alert_id TEXT,
        title TEXT NOT NULL,
        description TEXT,
        priority TEXT DEFAULT 'HIGH',
        status TEXT DEFAULT 'IN_PROGRESS',
        assigned_to TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
        FOREIGN KEY (assigned_to) REFERENCES users(user_id),
        FOREIGN KEY (created_by) REFERENCES users(user_id)
      );

      CREATE TABLE IF NOT EXISTS case_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        author_id TEXT NOT NULL,
        author_name TEXT NOT NULL,
        note_text TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES investigation_cases(case_id),
        FOREIGN KEY (author_id) REFERENCES users(user_id)
      );

      -- D9: Report Database
      CREATE TABLE IF NOT EXISTS reports (
        report_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        title TEXT NOT NULL,
        report_type TEXT DEFAULT 'STR',
        content_json TEXT NOT NULL,
        generated_by TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES investigation_cases(case_id),
        FOREIGN KEY (generated_by) REFERENCES users(user_id)
      );

      -- D10: Audit Log Database
      CREATE TABLE IF NOT EXISTS audit_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        user_name TEXT NOT NULL,
        action TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        details TEXT,
        ip_address TEXT DEFAULT '127.0.0.1',
        timestamp TEXT NOT NULL
      );

      -- Notifications
      CREATE TABLE IF NOT EXISTS notifications (
        notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        message TEXT NOT NULL,
        alert_id TEXT,
        case_id TEXT,
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
      );
    `);
  }

  createIndexes() {
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_txn_code ON transactions(txn_code);
      CREATE INDEX IF NOT EXISTS idx_txn_date ON transactions(transaction_date);
      CREATE INDEX IF NOT EXISTS idx_txn_amount ON transactions(amount);
      CREATE INDEX IF NOT EXISTS idx_txn_sender ON transactions(sender_account_id);
      CREATE INDEX IF NOT EXISTS idx_txn_receiver ON transactions(receiver_account_id);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_alerts_id ON alerts(alert_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
      CREATE INDEX IF NOT EXISTS idx_cases_id ON investigation_cases(case_id);
      CREATE INDEX IF NOT EXISTS idx_cases_status ON investigation_cases(status);
      CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);
    `);
  }

  seedInitialData() {
    // 1. Seed Roles
    const rolesCount = this.db.prepare('SELECT COUNT(*) as count FROM roles').get().count;
    if (rolesCount === 0) {
      const insertRole = this.db.prepare('INSERT INTO roles (role_name, description) VALUES (?, ?)');
      insertRole.run('INVESTIGATOR', 'Investigates suspicious transactions, reviews alerts, and manages cases');
      insertRole.run('COMPLIANCE_OFFICER', 'Oversees anti-money laundering compliance and configures risk thresholds');
      insertRole.run('ADMINISTRATOR', 'Full system administration, user management, and security audits');
      insertRole.run('REPORTING_AUTHORITY', 'Access to finalized suspicious transaction reports and regulatory dossiers');
    }

    // 2. Seed Users (with secure salted hashes - NFT-06)
    const usersCount = this.db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    if (usersCount === 0) {
      const insertUser = this.db.prepare(`
        INSERT INTO users (user_id, name, email, password_hash, salt, role_id, phone, department, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'))
      `);

      // Roles mapping
      const adminRole = this.db.prepare("SELECT role_id FROM roles WHERE role_name = 'ADMINISTRATOR'").get().role_id;
      const invRole = this.db.prepare("SELECT role_id FROM roles WHERE role_name = 'INVESTIGATOR'").get().role_id;
      const compRole = this.db.prepare("SELECT role_id FROM roles WHERE role_name = 'COMPLIANCE_OFFICER'").get().role_id;
      const regRole = this.db.prepare("SELECT role_id FROM roles WHERE role_name = 'REPORTING_AUTHORITY'").get().role_id;

      // Seed core users
      const u1 = hashPassword('Admin@123');
      insertUser.run('USR-0001', 'System Administrator', 'admin@fcip.gov', u1.hash, u1.salt, adminRole, '+1-555-0101', 'SecOps');

      const u2 = hashPassword('Investigator@123');
      insertUser.run('USR-0002', 'Senior Investigator', 'investigator@fcip.gov', u2.hash, u2.salt, invRole, '+1-555-0102', 'AML Unit');

      const u3 = hashPassword('Compliance@123');
      insertUser.run('USR-0003', 'Chief Compliance Officer', 'compliance@fcip.gov', u3.hash, u3.salt, compRole, '+1-555-0103', 'Legal & Compliance');

      const u4 = hashPassword('Regulator@123');
      insertUser.run('USR-0004', 'FIU Reporting Officer', 'regulator@fcip.gov', u4.hash, u4.salt, regRole, '+1-555-0104', 'Financial Intelligence Unit');

      // Test User Alex Joseph for FT-01 / FT-03
      const u5 = hashPassword('ValidPass123!');
      insertUser.run('USR-1000', 'Alex Joseph', 'alex.test@example.com', u5.hash, u5.salt, invRole, '+1-555-0199', 'Financial Crimes Team');
    }

    // 3. Seed Customers & Accounts
    const custCount = this.db.prepare('SELECT COUNT(*) as count FROM customers').get().count;
    if (custCount === 0) {
      const insertCust = this.db.prepare(`
        INSERT INTO customers (customer_id, first_name, last_name, email, phone, address, customer_type, risk_rating, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `);
      insertCust.run('CUST-1001', 'Arthur', 'Pendleton', 'arthur.p@meridian.com', '+1-202-555-0143', '104 Wall St, New York, NY', 'CORPORATE', 'HIGH');
      insertCust.run('CUST-1002', 'Sarah', 'Vance', 'sarah.vance@techcore.io', '+1-415-555-0182', '22 Market St, San Francisco, CA', 'INDIVIDUAL', 'MEDIUM');
      insertCust.run('CUST-1003', 'Victor', 'Kravitz', 'vk@helios-export.de', '+49-30-555-0199', '88 Friedrichstr, Berlin, DE', 'CORPORATE', 'HIGH');
      insertCust.run('CUST-1004', 'Elena', 'Rostova', 'elena@novacapital.ch', '+41-22-555-0120', '14 Rue du Rhone, Geneva, CH', 'CORPORATE', 'CRITICAL');
      insertCust.run('CUST-1005', 'David', 'Chen', 'chen@pacifictrade.sg', '+65-6555-0177', '1 Raffles Place, Singapore', 'INDIVIDUAL', 'LOW');

      const insertAcc = this.db.prepare(`
        INSERT INTO accounts (account_id, customer_id, account_number, account_type, balance, currency, status, open_date, branch)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', '2025-01-15', ?)
      `);
      insertAcc.run('ACC-1001', 'CUST-1001', 'AC-NYC-1001', 'CORPORATE', 1250000.0, 'USD', 'New York Main');
      insertAcc.run('ACC-1002', 'CUST-1002', 'AC-SFO-1002', 'CHECKING', 450000.0, 'USD', 'San Francisco Metro');
      insertAcc.run('ACC-1003', 'CUST-1003', 'AC-BER-1003', 'COMMERCIAL', 890000.0, 'USD', 'Berlin International');
      insertAcc.run('ACC-1004', 'CUST-1004', 'AC-GEN-1004', 'OFFSHORE', 3400000.0, 'USD', 'Geneva Private');
      insertAcc.run('ACC-1005', 'CUST-1005', 'AC-SIN-1005', 'SAVINGS', 180000.0, 'USD', 'Singapore Hub');

      // Additional accounts for structuring and smurfing detection
      insertAcc.run('ACC-2001', 'CUST-1002', 'AC-SMURF-2001', 'CHECKING', 35000.0, 'USD', 'Queens Sub-branch');
      insertAcc.run('ACC-2002', 'CUST-1002', 'AC-SMURF-2002', 'CHECKING', 42000.0, 'USD', 'Bronx Sub-branch');
      insertAcc.run('ACC-2003', 'CUST-1002', 'AC-SMURF-2003', 'CHECKING', 38000.0, 'USD', 'Brooklyn Sub-branch');
      insertAcc.run('ACC-3001', 'CUST-1001', 'AC-CONSOL-3001', 'CHECKING', 95000.0, 'USD', 'Midtown Commercial');
      insertAcc.run('ACC-4001', 'CUST-1004', 'AC-SHELL-4001', 'OFFSHORE', 5200000.0, 'USD', 'BVI Offshore');
      insertAcc.run('ACC-5001', 'CUST-1004', 'AC-CYM-5001', 'OFFSHORE', 7800000.0, 'USD', 'Cayman Trust');
      insertAcc.run('ACC-6001', 'CUST-1003', 'AC-DISP-6001', 'COMMERCIAL', 210000.0, 'USD', 'Frankfurt Clearing');
      insertAcc.run('ACC-7001', 'CUST-1005', 'AC-BUS-7001', 'BUSINESS', 310000.0, 'USD', 'Hong Kong Gate');
      insertAcc.run('ACC-8001', 'CUST-1005', 'AC-PAY-8001', 'PAYROLL', 190000.0, 'USD', 'Tokyo Branch');
      insertAcc.run('ACC-9001', 'CUST-1005', 'AC-OPS-9001', 'OPERATIONAL', 88000.0, 'USD', 'Sydney Office');
    }

    // 4. Seed Detection Rules
    const rulesCount = this.db.prepare('SELECT COUNT(*) as count FROM detection_rules').get().count;
    if (rulesCount === 0) {
      const insertRule = this.db.prepare(`
        INSERT INTO detection_rules (rule_code, rule_name, rule_type, threshold_amount, time_window_hours, status, severity, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      insertRule.run('RULE-THRESHOLD', 'High-Value Transfer Threshold', 'THRESHOLD', 50000.0, 24, 'ACTIVE', 'HIGH', 'Flags single transactions exceeding $50,000 regulatory reporting barrier');
      insertRule.run('RULE-STRUCTURING', 'Structuring / Smurfing Pattern', 'PATTERN', 10000.0, 72, 'ACTIVE', 'CRITICAL', 'Detects consecutive deposits just below the $10,000 threshold designed to evade BSA filing');
      insertRule.run('RULE-CIRCULAR', 'Circular Transaction Laundering', 'CIRCULAR', 10000.0, 168, 'ACTIVE', 'CRITICAL', 'Identifies closed loops where funds route through multiple accounts and return to the origin');
      insertRule.run('RULE-RAPID-FLOW', 'Rapid Fund Movement', 'VELOCITY', 14000.0, 48, 'ACTIVE', 'HIGH', 'Detects funds rapidly forwarded through intermediary accounts with minimal retention');
      insertRule.run('RULE-OFFSHORE', 'High-Risk Offshore Flight', 'JURISDICTION', 100000.0, 24, 'ACTIVE', 'CRITICAL', 'Transfers routed to uncooperative tax havens or shell bank accounts');
    }

    // 5. Seed Suspicious Patterns
    const patCount = this.db.prepare('SELECT COUNT(*) as count FROM suspicious_patterns').get().count;
    if (patCount === 0) {
      const insertPat = this.db.prepare(`
        INSERT INTO suspicious_patterns (pattern_code, pattern_name, pattern_type, severity, description, detected_count)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      insertPat.run('PAT-STRUCTURING', 'Cash Structuring / Smurfing', 'Structuring', 'HIGH', 'Multiple sub-$10,000 deposits aggregated to single receiver', 3);
      insertPat.run('PAT-CIRCULAR', 'Circular Money Routing Loop', 'Circular', 'CRITICAL', 'ACC-1001 -> ACC-1002 -> ACC-1003 -> ACC-1004 -> ACC-1001 fund cycle', 1);
      insertPat.run('PAT-RAPID', 'Rapid Intermediary Passthrough', 'Rapid Movement', 'MEDIUM', 'Funds withdrawn within 24 hours of substantial deposit', 2);
      insertPat.run('PAT-OFFSHORE', 'Offshore Capital Flight', 'Layering', 'CRITICAL', 'Large transfers into offshore shell company entities', 1);
    }

    // 6. Seed Initial Transactions (including TXN-1001 for FT-08, FT-09, FT-10)
    const txnCount = this.db.prepare('SELECT COUNT(*) as count FROM transactions').get().count;
    if (txnCount === 0) {
      const insertTxn = this.db.prepare(`
        INSERT INTO transactions (txn_code, sender_account_id, receiver_account_id, amount, currency, transaction_date, channel, description, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETED')
      `);
      insertTxn.run('TXN-1001', 'ACC-1001', 'ACC-1002', 15000.00, 'USD', '2026-10-02', 'Wire', 'Initial fund transfer');
      insertTxn.run('TXN-1002', 'ACC-1002', 'ACC-1003', 14800.00, 'USD', '2026-10-03', 'Wire', 'Intermediary forwarding');
      insertTxn.run('TXN-1003', 'ACC-1003', 'ACC-1004', 14500.00, 'USD', '2026-10-04', 'Wire', 'Disbursement to shell entity');
      insertTxn.run('TXN-1004', 'ACC-1004', 'ACC-1001', 14200.00, 'USD', '2026-10-05', 'Wire', 'Circular return to origin');
      insertTxn.run('TXN-1005', 'ACC-2001', 'ACC-3001', 9800.00, 'USD', '2026-10-06', 'Cash Deposit', 'Structuring tranche 1');
      insertTxn.run('TXN-1006', 'ACC-2002', 'ACC-3001', 9900.00, 'USD', '2026-10-06', 'Cash Deposit', 'Structuring tranche 2');
      insertTxn.run('TXN-1007', 'ACC-2003', 'ACC-3001', 9750.00, 'USD', '2026-10-07', 'Cash Deposit', 'Structuring tranche 3');
      insertTxn.run('TXN-1008', 'ACC-3001', 'ACC-6001', 29000.00, 'USD', '2026-10-08', 'Wire', 'Consolidated smurfed outbound');
      insertTxn.run('TXN-1009', 'ACC-4001', 'ACC-5001', 850000.00, 'USD', '2026-10-10', 'Offshore Wire', 'High-risk offshore shell transfer');
      insertTxn.run('TXN-1010', 'ACC-7001', 'ACC-8001', 25000.00, 'USD', '2026-10-11', 'ACH', 'Standard commercial vendor invoice');
      insertTxn.run('TXN-1011', 'ACC-8001', 'ACC-9001', 35000.00, 'USD', '2026-10-12', 'Wire', 'Corporate payroll disbursement');
      insertTxn.run('TXN-1012', 'ACC-1001', 'ACC-1005', 12000.00, 'USD', '2026-10-13', 'Wire', 'Branch operational expenses');

      // Seed Entity Relationships
      const insertRel = this.db.prepare(`
        INSERT INTO entity_relationships (source_account_id, target_account_id, relationship_type, strength, transaction_count, total_volume)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      insertRel.run('ACC-1001', 'ACC-1002', 'DIRECT_TRANSFER', 0.9, 1, 15000.0);
      insertRel.run('ACC-1002', 'ACC-1003', 'DIRECT_TRANSFER', 0.9, 1, 14800.0);
      insertRel.run('ACC-1003', 'ACC-1004', 'DIRECT_TRANSFER', 0.9, 1, 14500.0);
      insertRel.run('ACC-1004', 'ACC-1001', 'CIRCULAR_LOOP', 0.95, 1, 14200.0);
    }

    // 7. Seed Initial Risk Score & Alert for TXN-1001 / ALT-1001
    const alertCount = this.db.prepare('SELECT COUNT(*) as count FROM alerts').get().count;
    if (alertCount === 0) {
      const insertScore = this.db.prepare(`
        INSERT INTO risk_scores (entity_type, entity_id, score, risk_level, calculated_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `);
      insertScore.run('TRANSACTION', 'TXN-1001', 88.5, 'HIGH');
      const scoreId = 1;

      const insertFactor = this.db.prepare(`
        INSERT INTO risk_factors (risk_score_id, factor_category, factor_name, score_contribution, weight, description)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      insertFactor.run(scoreId, 'NETWORK_FLOW', 'Part of 4-hop Circular Flow Ring', 35.0, 0.40, 'Fund routing loops back to root account ACC-1001');
      insertFactor.run(scoreId, 'ENTITY_RISK', 'Interacting with High Risk Entity CUST-1004', 28.5, 0.30, 'Recipient linked to offshore jurisdiction');
      insertFactor.run(scoreId, 'VELOCITY', 'Rapid Transfer Turnaround (<24h)', 25.0, 0.30, 'Funds moved to intermediary with zero balance retention');

      const insertAlert = this.db.prepare(`
        INSERT INTO alerts (alert_id, transaction_id, entity_type, entity_id, severity, status, pattern_code, score, explanation, created_at, assigned_to)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
      `);
      insertAlert.run('ALT-1001', 1, 'TRANSACTION', 'TXN-1001', 'HIGH', 'ASSIGNED', 'PAT-CIRCULAR', 88.5, 'Transaction flagged due to involvement in circular fund movement loop and high velocity transfer.', 'USR-0002');

      const insertCase = this.db.prepare(`
        INSERT INTO investigation_cases (case_id, alert_id, title, description, priority, status, assigned_to, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `);
      insertCase.run('CASE-1001', 'ALT-1001', 'Review unusual transfers', 'Formal investigation opened into circular fund routing between ACC-1001, ACC-1002, ACC-1003, and ACC-1004.', 'HIGH', 'IN_PROGRESS', 'USR-0002', 'USR-0002');

      const insertNote = this.db.prepare(`
        INSERT INTO case_notes (case_id, author_id, author_name, note_text, created_at)
        VALUES (?, ?, ?, ?, ?)
      `);
      insertNote.run('CASE-1001', 'USR-0002', 'Senior Investigator', 'Reviewed linked accounts and initiated path trace across offshore nodes.', '2026-10-15 10:30:00');
    }
  }

  // Backup & Recovery routines (NFT-11)
  backupDatabase(targetPath) {
    if (this.dbPath === ':memory:') {
      const targetDb = new DatabaseSync(targetPath);
      const tables = this.db.prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
      for (const t of tables) {
        if (t.sql) targetDb.exec(t.sql);
        const rows = this.db.prepare(`SELECT * FROM ${t.name}`).all();
        for (const row of rows) {
          const keys = Object.keys(row);
          if (keys.length > 0) {
            const placeholders = keys.map(() => '?').join(', ');
            targetDb.prepare(`INSERT INTO ${t.name} (${keys.join(', ')}) VALUES (${placeholders})`).run(...Object.values(row));
          }
        }
      }
      targetDb.close();
      return { success: true, backupPath: targetPath, timestamp: new Date().toISOString() };
    }
    fs.copyFileSync(this.dbPath, targetPath);
    return { success: true, backupPath: targetPath, timestamp: new Date().toISOString() };
  }

  restoreDatabase(backupPath) {
    if (!fs.existsSync(backupPath)) {
      throw new Error(`Backup file ${backupPath} not found`);
    }
    if (this.dbPath === ':memory:') {
      const srcDb = new DatabaseSync(backupPath);
      const tables = srcDb.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
      for (const t of tables) {
        this.db.exec(`DELETE FROM ${t.name}`);
        const rows = srcDb.prepare(`SELECT * FROM ${t.name}`).all();
        for (const row of rows) {
          const keys = Object.keys(row);
          if (keys.length > 0) {
            const placeholders = keys.map(() => '?').join(', ');
            this.db.prepare(`INSERT INTO ${t.name} (${keys.join(', ')}) VALUES (${placeholders})`).run(...Object.values(row));
          }
        }
      }
      srcDb.close();
      return { success: true, message: 'Database restored successfully from backup.' };
    }
    fs.copyFileSync(backupPath, this.dbPath);
    return { success: true, message: 'Database restored successfully from backup.' };
  }
}

module.exports = { DatabaseEngine, DB_PATH };
