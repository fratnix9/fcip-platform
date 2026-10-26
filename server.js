// server.js - Financial Crime Intelligence Platform (FCIP) Core Web & API Server
// Built with pure Node.js standard library (Zero third-party npm dependencies required)
// Fulfills WBS Geographic Server-Side, Component Diagram, and Deployment Node architecture.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const url = require('node:url');

const { DatabaseEngine, DB_PATH } = require('./database');
const { AuditLogger } = require('./auditLogger');
const { AuthService, verifyToken } = require('./auth');
const { FraudEngine } = require('./fraudEngine');
const { NetworkGraphEngine } = require('./networkGraph');
const { runAllTests } = require('./testSuite');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// Initialize Singletons
const dbEngine = new DatabaseEngine(DB_PATH);
const audit = new AuditLogger(dbEngine.db);
const auth = new AuthService(dbEngine.db, audit);
const fraud = new FraudEngine(dbEngine.db, audit);
const network = new NetworkGraphEngine(dbEngine.db);

// Helper: send JSON response with standard CORS & Security Headers
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block'
  });
  res.end(JSON.stringify(data));
}

// Helper: parse request body
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1e7) { // 10MB limit
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        // Fallback for raw text/CSV
        resolve({ raw: body });
      }
    });
    req.on('error', reject);
  });
}

// Helper: extract auth user from header
function getAuthUser(req) {
  const header = req.headers['authorization'];
  if (!header) return null;
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  return verifyToken(token);
}

// CSV Parser Helper
function parseCSV(content) {
  const lines = content.trim().split(/\r?\n/);
  if (lines.length < 2) return { valid: false, error: 'CSV file is empty or missing data rows.' };
  const headers = lines[0].split(',').map(h => h.trim());
  const required = ['TransactionID', 'SenderAccount', 'ReceiverAccount', 'Amount', 'Currency', 'TransactionDate'];
  const missing = required.filter(r => !headers.includes(r));
  if (missing.length > 0) {
    return { valid: false, error: `Dataset missing required column(s): ${missing.join(', ')}` };
  }
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const values = line.split(',').map(v => v.trim());
    const row = {};
    headers.forEach((h, idx) => { row[h] = values[idx] || ''; });
    rows.push(row);
  }
  return { valid: true, rows };
}

// MIME Types for Static File Serving
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  const clientIp = req.socket.remoteAddress || '127.0.0.1';

  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const query = Object.fromEntries(parsedUrl.searchParams.entries());
  const method = req.method;

  // ----------------------------------------------------------------
  // REST API ROUTES (/api/...)
  // ----------------------------------------------------------------
  if (pathname.startsWith('/api/')) {
    try {
      // 1. Health Probe (NFT-10)
      if (pathname === '/api/health' && method === 'GET') {
        return sendJSON(res, 200, {
          status: 'UP',
          uptime: process.uptime(),
          timestamp: new Date().toISOString(),
          database: 'ONLINE',
          version: '1.0.0-PROD'
        });
      }

      // 2. Authentication: Register (FT-01, FT-02)
      if (pathname === '/api/auth/register' && method === 'POST') {
        const body = await parseBody(req);
        const result = auth.registerUser(body);
        return sendJSON(res, result.success ? 201 : 400, result);
      }

      // 3. Authentication: Login (FT-03, FT-04, NFT-06, NFT-07)
      if (pathname === '/api/auth/login' && method === 'POST') {
        const body = await parseBody(req);
        const result = auth.login(body.email, body.password, clientIp);
        return sendJSON(res, result.success ? 200 : 401, result);
      }

      // 4. Current User Session
      if (pathname === '/api/auth/me' && method === 'GET') {
        const user = getAuthUser(req);
        if (!user) return sendJSON(res, 401, { error: 'Unauthenticated' });
        return sendJSON(res, 200, { user });
      }

      // 5. Dashboard KPI Stats (FR37, FR38)
      if (pathname === '/api/dashboard/stats' && method === 'GET') {
        const totalTxns = dbEngine.db.prepare('SELECT COUNT(*) as c FROM transactions').get().c;
        const totalVolume = dbEngine.db.prepare('SELECT SUM(amount) as s FROM transactions').get().s || 0;
        const totalAlerts = dbEngine.db.prepare('SELECT COUNT(*) as c FROM alerts').get().c;
        const activeAlerts = dbEngine.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE status != 'CLOSED'").get().c;
        const totalCases = dbEngine.db.prepare('SELECT COUNT(*) as c FROM investigation_cases').get().c;
        const highRiskScores = dbEngine.db.prepare("SELECT COUNT(*) as c FROM risk_scores WHERE risk_level = 'HIGH'").get().c;
        const recentAlerts = dbEngine.db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 5').all();
        const flaggedTxns = dbEngine.db.prepare(`
          SELECT t.*, a.severity, a.score, a.alert_id
          FROM transactions t
          JOIN alerts a ON t.id = a.transaction_id
          ORDER BY a.score DESC LIMIT 6
        `).all();

        return sendJSON(res, 200, {
          stats: {
            totalTxns,
            totalVolume,
            totalAlerts,
            activeAlerts,
            totalCases,
            highRiskScores
          },
          recentAlerts,
          flaggedTxns
        });
      }

      // 6. Transactions Search & Filter (FT-09, FT-10, NFT-01)
      if (pathname === '/api/transactions' && method === 'GET') {
        const { startDate, endDate, minAmount, maxAmount, search, accountId } = query;
        let sql = `
          SELECT t.*, a1.account_number as sender_acc, a2.account_number as receiver_acc
          FROM transactions t
          LEFT JOIN accounts a1 ON t.sender_account_id = a1.account_id
          LEFT JOIN accounts a2 ON t.receiver_account_id = a2.account_id
          WHERE 1=1
        `;
        const params = [];

        if (startDate) {
          sql += ' AND t.transaction_date >= ?';
          params.push(startDate);
        }
        if (endDate) {
          sql += ' AND t.transaction_date <= ?';
          params.push(endDate);
        }
        if (minAmount) {
          sql += ' AND t.amount >= ?';
          params.push(Number(minAmount));
        }
        if (maxAmount) {
          sql += ' AND t.amount <= ?';
          params.push(Number(maxAmount));
        }
        if (accountId) {
          sql += ' AND (t.sender_account_id = ? OR t.receiver_account_id = ?)';
          params.push(accountId, accountId);
        }
        if (search) {
          sql += ' AND (t.txn_code LIKE ? OR t.description LIKE ? OR t.channel LIKE ?)';
          params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }

        sql += ' ORDER BY t.transaction_date DESC LIMIT 200';
        const rows = dbEngine.db.prepare(sql).all(...params);
        return sendJSON(res, 200, { count: rows.length, transactions: rows });
      }

      // 7. Transaction Details (FT-10)
      if (pathname.startsWith('/api/transactions/') && method === 'GET') {
        const txnCode = pathname.replace('/api/transactions/', '');
        const txn = dbEngine.db.prepare(`
          SELECT t.*, 
                 a1.account_number as sender_number, a1.account_type as sender_type, c1.first_name || ' ' || c1.last_name as sender_name,
                 a2.account_number as receiver_number, a2.account_type as receiver_type, c2.first_name || ' ' || c2.last_name as receiver_name
          FROM transactions t
          LEFT JOIN accounts a1 ON t.sender_account_id = a1.account_id
          LEFT JOIN customers c1 ON a1.customer_id = c1.customer_id
          LEFT JOIN accounts a2 ON t.receiver_account_id = a2.account_id
          LEFT JOIN customers c2 ON a2.customer_id = c2.customer_id
          WHERE t.txn_code = ?
        `).get(txnCode);

        if (!txn) return sendJSON(res, 404, { error: 'Transaction not found' });
        return sendJSON(res, 200, { transaction: txn });
      }

      // 8. Upload Transaction Dataset (FT-06, FT-07, FT-08)
      if (pathname === '/api/transactions/upload' && method === 'POST') {
        const user = getAuthUser(req);
        const body = await parseBody(req);
        const csvText = body.csvData || body.raw;

        if (!csvText) {
          return sendJSON(res, 400, { error: 'No CSV payload supplied' });
        }

        const parsed = parseCSV(csvText);
        if (!parsed.valid) {
          return sendJSON(res, 400, { error: parsed.error });
        }

        let imported = 0;
        let duplicates = 0;
        const insertStmt = dbEngine.db.prepare(`
          INSERT INTO transactions (txn_code, sender_account_id, receiver_account_id, amount, currency, transaction_date, channel, description, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETED')
        `);

        for (const row of parsed.rows) {
          const existing = dbEngine.db.prepare('SELECT txn_code FROM transactions WHERE txn_code = ?').get(row.TransactionID);
          if (existing) {
            duplicates++;
            continue; // Handle duplicate according to policy (FT-08)
          }

          try {
            insertStmt.run(
              row.TransactionID,
              row.SenderAccount,
              row.ReceiverAccount,
              parseFloat(row.Amount) || 0,
              row.Currency || 'USD',
              row.TransactionDate,
              row.Channel || 'Wire',
              row.Description || 'Imported dataset transfer'
            );
            imported++;
          } catch (e) {
            // Error handling
          }
        }

        audit.log(
          user ? user.userId : 'SYSTEM',
          user ? user.name : 'System',
          'DATASET_UPLOAD',
          'transactions',
          { imported, duplicates, total: parsed.rows.length }
        );

        return sendJSON(res, 200, {
          success: true,
          imported,
          duplicates,
          total: parsed.rows.length,
          message: `Dataset accepted. Import summary: ${imported} imported, ${duplicates} duplicates rejected.`
        });
      }

      // 9. Fraud Detection: Active Rules & Run Detection (FT-11, FT-12, FT-15, FR14)
      if (pathname === '/api/detection/rules' && method === 'GET') {
        const rules = dbEngine.db.prepare('SELECT * FROM detection_rules ORDER BY rule_id ASC').all();
        return sendJSON(res, 200, { rules });
      }

      if (pathname.startsWith('/api/detection/rules/') && method === 'PUT') {
        const user = getAuthUser(req);
        if (user && !auth.hasPermission(user.role, 'detection:rules_modify')) {
          return sendJSON(res, 403, { error: 'Access denied: insufficient permission to modify detection rules.' });
        }
        const ruleId = pathname.replace('/api/detection/rules/', '');
        const body = await parseBody(req);
        dbEngine.db.prepare('UPDATE detection_rules SET status = ? WHERE rule_id = ?').run(body.status, ruleId);
        audit.log(user?.userId || 'SYSTEM', user?.name || 'User', 'UPDATE_RULE', 'detection_rules', { ruleId, status: body.status });
        return sendJSON(res, 200, { success: true, message: `Rule #${ruleId} status set to ${body.status}` });
      }

      if (pathname === '/api/detection/run' && method === 'POST') {
        const newAlerts = fraud.evaluateAndGenerateAlerts();
        const patterns = fraud.detectPatterns();
        return sendJSON(res, 200, {
          success: true,
          alertsGenerated: newAlerts.length,
          alerts: newAlerts,
          patternsDetected: patterns.length,
          patterns
        });
      }

      // 10. Risk Assessment & Explanation (FT-13, FT-14, FR18, FR19)
      if (pathname.startsWith('/api/risk/assess/') && method === 'GET') {
        const parts = pathname.replace('/api/risk/assess/', '').split('/');
        const entityType = parts[0];
        const entityId = parts[1];
        const assessment = fraud.saveAndExplainRiskScore(entityType, entityId);
        if (!assessment) return sendJSON(res, 404, { error: 'Entity not found' });
        return sendJSON(res, 200, { assessment });
      }

      // 11. Alerts Management (FT-15, FR21, FR22)
      if (pathname === '/api/alerts' && method === 'GET') {
        const alerts = dbEngine.db.prepare(`
          SELECT a.*, t.amount, t.currency, t.transaction_date, t.sender_account_id, t.receiver_account_id,
                 u.name as assigned_name
          FROM alerts a
          LEFT JOIN transactions t ON a.transaction_id = t.id
          LEFT JOIN users u ON a.assigned_to = u.user_id
          ORDER BY a.id DESC
        `).all();
        return sendJSON(res, 200, { alerts });
      }

      if (pathname.startsWith('/api/alerts/') && method === 'PUT') {
        const alertId = pathname.replace('/api/alerts/', '');
        const body = await parseBody(req);
        const user = getAuthUser(req);

        if (body.status) {
          dbEngine.db.prepare('UPDATE alerts SET status = ? WHERE alert_id = ?').run(body.status, alertId);
        }
        if (body.assignedTo) {
          dbEngine.db.prepare('UPDATE alerts SET assigned_to = ? WHERE alert_id = ?').run(body.assignedTo, alertId);
        }

        audit.log(user?.userId || 'USR-0002', user?.name || 'Investigator', 'UPDATE_ALERT', 'alerts', { alertId, ...body });
        return sendJSON(res, 200, { success: true, message: `Alert ${alertId} updated successfully.` });
      }

      // 12. Case Management (FT-16, FT-17, FR31-FR36)
      if (pathname === '/api/cases' && method === 'GET') {
        const cases = dbEngine.db.prepare(`
          SELECT c.*, u.name as assigned_name, creator.name as creator_name
          FROM investigation_cases c
          LEFT JOIN users u ON c.assigned_to = u.user_id
          LEFT JOIN users creator ON c.created_by = creator.user_id
          ORDER BY c.id DESC
        `).all();
        return sendJSON(res, 200, { cases });
      }

      if (pathname === '/api/cases' && method === 'POST') {
        const body = await parseBody(req);
        const user = getAuthUser(req);
        const caseId = 'CASE-' + (1000 + Math.floor(Math.random() * 9000));
        const authorId = user ? user.userId : 'USR-0002';

        dbEngine.db.prepare(`
          INSERT INTO investigation_cases (case_id, alert_id, title, description, priority, status, assigned_to, created_by, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, datetime('now'), datetime('now'))
        `).run(
          caseId,
          body.alertId || null,
          body.title || 'Untitled Investigation Case',
          body.description || '',
          body.priority || 'HIGH',
          body.assignedTo || authorId,
          authorId
        );

        if (body.alertId) {
          dbEngine.db.prepare("UPDATE alerts SET status = 'IN_CASE' WHERE alert_id = ?").run(body.alertId);
        }

        audit.log(authorId, user?.name || 'Investigator', 'CREATE_CASE', 'investigation_cases', { caseId, alertId: body.alertId });
        return sendJSON(res, 201, {
          success: true,
          caseId,
          message: `Case ${caseId} created, linked to alert, and assigned.`
        });
      }

      if (pathname.startsWith('/api/cases/') && method === 'GET') {
        const caseId = pathname.replace('/api/cases/', '');
        const c = dbEngine.db.prepare(`
          SELECT c.*, u.name as assigned_name, a.explanation as alert_explanation, a.score as alert_score
          FROM investigation_cases c
          LEFT JOIN users u ON c.assigned_to = u.user_id
          LEFT JOIN alerts a ON c.alert_id = a.alert_id
          WHERE c.case_id = ?
        `).get(caseId);

        if (!c) return sendJSON(res, 404, { error: 'Case not found' });

        const notes = dbEngine.db.prepare(`
          SELECT * FROM case_notes WHERE case_id = ? ORDER BY note_id DESC
        `).all(caseId);

        return sendJSON(res, 200, { caseData: c, notes });
      }

      // Add Case Note (FT-17)
      if (pathname.endsWith('/notes') && method === 'POST') {
        const caseId = pathname.split('/')[3];
        const body = await parseBody(req);
        const user = getAuthUser(req);
        const authorId = user ? user.userId : 'USR-0002';
        const authorName = user ? user.name : 'Senior Investigator';

        dbEngine.db.prepare(`
          INSERT INTO case_notes (case_id, author_id, author_name, note_text, created_at)
          VALUES (?, ?, ?, ?, datetime('now'))
        `).run(caseId, authorId, authorName, body.noteText);

        dbEngine.db.prepare("UPDATE investigation_cases SET updated_at = datetime('now') WHERE case_id = ?").run(caseId);

        audit.log(authorId, authorName, 'ADD_CASE_NOTE', 'case_notes', { caseId, noteLength: body.noteText.length });
        return sendJSON(res, 201, { success: true, message: 'Case note saved and added to case history.' });
      }

      // Update Case Status (FT-17)
      if (pathname.endsWith('/status') && method === 'PUT') {
        const caseId = pathname.split('/')[3];
        const body = await parseBody(req);
        const user = getAuthUser(req);

        dbEngine.db.prepare(`
          UPDATE investigation_cases SET status = ?, updated_at = datetime('now')
          WHERE case_id = ?
        `).run(body.status, caseId);

        audit.log(user?.userId || 'USR-0002', user?.name || 'Investigator', 'UPDATE_CASE_STATUS', 'investigation_cases', { caseId, status: body.status });
        return sendJSON(res, 200, { success: true, message: `Case status updated to ${body.status}.` });
      }

      // 13. Network Graph & Money Flow Tracing (FT-18, FR25, FR28, FR29)
      if (pathname === '/api/network/graph' && method === 'GET') {
        const graphData = network.getNetworkGraph();
        return sendJSON(res, 200, graphData);
      }

      if (pathname === '/api/network/trace' && method === 'GET') {
        const rootAccount = query.root || 'ACC-1001';
        const destAccount = query.destination || 'ACC-1004';
        const trace = network.traceMoneyFlow(rootAccount, destAccount);
        return sendJSON(res, 200, trace);
      }

      // 14. Report Generation & Export (FT-19, FR39, FR40)
      if (pathname === '/api/reports/generate' && method === 'POST') {
        const body = await parseBody(req);
        const user = getAuthUser(req);
        const caseId = body.caseId || 'CASE-1001';
        const reportId = 'REP-' + (1000 + Math.floor(Math.random() * 9000));

        const caseData = dbEngine.db.prepare('SELECT * FROM investigation_cases WHERE case_id = ?').get(caseId);
        const notes = dbEngine.db.prepare('SELECT * FROM case_notes WHERE case_id = ?').all(caseId);
        const alert = caseData?.alert_id ? dbEngine.db.prepare('SELECT * FROM alerts WHERE alert_id = ?').get(caseData.alert_id) : null;

        const reportDossier = {
          reportId,
          caseId,
          title: `Financial Intelligence Investigation Report: ${caseData?.title || 'Case ' + caseId}`,
          caseDetails: caseData,
          alertDetails: alert,
          notesTimeline: notes,
          generatedBy: user?.name || 'Senior Investigator',
          classification: 'CONFIDENTIAL // LAW ENFORCEMENT & FIU ONLY',
          generatedAt: new Date().toISOString()
        };

        dbEngine.db.prepare(`
          INSERT INTO reports (report_id, case_id, title, report_type, content_json, generated_by, generated_at)
          VALUES (?, ?, ?, 'STR', ?, ?, datetime('now'))
        `).run(reportId, caseId, reportDossier.title, JSON.stringify(reportDossier), user?.userId || 'USR-0002');

        audit.log(user?.userId || 'USR-0002', user?.name || 'Senior Investigator', 'GENERATE_REPORT', 'reports', { reportId, caseId });

        return sendJSON(res, 201, {
          success: true,
          reportId,
          report: reportDossier,
          message: 'Investigation report generated with selected case details and exported.'
        });
      }

      // 15. Audit Logs (FT-20, FR42)
      if (pathname === '/api/audit/logs' && method === 'GET') {
        const logs = audit.getRecentLogs(100);
        return sendJSON(res, 200, { logs });
      }

      // 16. Comprehensive Test Suite Execution Endpoint
      if (pathname === '/api/test-suite/run' && (method === 'GET' || method === 'POST')) {
        const testResults = await runAllTests();
        return sendJSON(res, 200, testResults);
      }

      // Unmatched API endpoint
      return sendJSON(res, 404, { error: 'API endpoint not found' });
    } catch (err) {
      console.error('[API_ERROR]', err);
      return sendJSON(res, 500, { error: 'Internal Server Error', message: err.message });
    }
  }

  // ----------------------------------------------------------------
  // STATIC FILE SERVING (/public/...)
  // ----------------------------------------------------------------
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        // Fallback to index.html for Single Page App routing
        fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, spaContent) => {
          if (err2) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
          } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(spaContent);
          }
        });
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache'
      });
      res.end(content);
    }
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`   FINANCIAL CRIME INTELLIGENCE PLATFORM (FCIP)      `);
    console.log(`   Software Engineering - Lab Assessment System      `);
    console.log(`   Server running at: http://localhost:${PORT}        `);
    console.log(`======================================================\n`);
  });
}

module.exports = { server, dbEngine, auth, fraud, network, audit };
