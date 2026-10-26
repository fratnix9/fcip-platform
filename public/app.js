// app.js - FCIP Frontend Controller & Interactive Workstation
// Implements full client-side behavior and verification suite

let currentUser = {
  userId: 'USR-1000',
  name: 'Alex Joseph',
  email: 'alex.test@example.com',
  role: 'INVESTIGATOR'
};

let currentToken = null;
let networkData = { nodes: [], edges: [] };
let activePathHops = [];
let selectedNode = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initModals();
  initRoleSelector();
  loadDashboardData();
  setupEventListeners();
});

// -------------------------------------------------------------
// NAVIGATION & TABS
// -------------------------------------------------------------
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-tab') === tabId);
  });
  document.querySelectorAll('.tab-pane').forEach(el => {
    el.classList.toggle('active', el.id === `tab-${tabId}`);
  });

  // Lazy tab data loaders
  if (tabId === 'dashboard') loadDashboardData();
  if (tabId === 'transactions') loadTransactions();
  if (tabId === 'detection') loadDetectionRules();
  if (tabId === 'network') initNetworkGraph();
  if (tabId === 'alerts') loadAlerts();
  if (tabId === 'cases') loadCases();
  if (tabId === 'audit') loadAuditLogs();
}

// -------------------------------------------------------------
// ROLE SELECTOR & AUTH
// -------------------------------------------------------------
function initRoleSelector() {
  const selector = document.getElementById('roleSelector');
  selector.addEventListener('change', (e) => {
    const role = e.target.value;
    const roleMap = {
      INVESTIGATOR: { userId: 'USR-1000', name: 'Alex Joseph', email: 'alex.test@example.com' },
      COMPLIANCE_OFFICER: { userId: 'USR-0003', name: 'Chief Compliance Officer', email: 'compliance@fcip.gov' },
      ADMINISTRATOR: { userId: 'USR-0001', name: 'System Administrator', email: 'admin@fcip.gov' },
      REPORTING_AUTHORITY: { userId: 'USR-0004', name: 'FIU Reporting Officer', email: 'regulator@fcip.gov' }
    };
    currentUser = { ...roleMap[role], role };
    console.log(`[FCIP] Switched active role to: ${role}`);
  });
}

// -------------------------------------------------------------
// DASHBOARD DATA
// -------------------------------------------------------------
async function loadDashboardData() {
  try {
    const res = await fetch('/api/dashboard/stats');
    const data = await res.json();
    if (!data.stats) return;

    document.getElementById('kpiTotalTxns').textContent = data.stats.totalTxns;
    document.getElementById('kpiTotalVolume').textContent = '$' + Number(data.stats.totalVolume).toLocaleString(undefined, { minimumFractionDigits: 2 });
    document.getElementById('kpiActiveAlerts').textContent = data.stats.activeAlerts;
    document.getElementById('kpiTotalCases').textContent = data.stats.totalCases;
    document.getElementById('sidebarAlertBadge').textContent = data.stats.activeAlerts;

    // Render flagged transactions table
    const tableBody = document.querySelector('#dashboardFlaggedTable tbody');
    if (data.flaggedTxns && data.flaggedTxns.length > 0) {
      tableBody.innerHTML = data.flaggedTxns.map(t => `
        <tr>
          <td><strong class="font-mono">${t.txn_code}</strong></td>
          <td>${t.sender_account_id}</td>
          <td>${t.receiver_account_id}</td>
          <td class="font-mono">$${Number(t.amount).toLocaleString()}</td>
          <td><span class="badge ${t.score >= 70 ? 'badge-danger' : 'badge-warning'}">${t.score} / 100</span></td>
          <td><button class="btn btn-secondary btn-xs" onclick="inspectRisk('TRANSACTION', '${t.txn_code}')">Explain Risk</button></td>
        </tr>
      `).join('');
    } else {
      tableBody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No high-risk transactions flagged.</td></tr>';
    }

    // Render recent alerts
    const alertList = document.getElementById('dashboardAlertList');
    if (data.recentAlerts && data.recentAlerts.length > 0) {
      alertList.innerHTML = data.recentAlerts.map(a => `
        <div class="timeline-item">
          <div class="timeline-header">
            <strong>${a.alert_id} (${a.severity})</strong>
            <span>${a.created_at}</span>
          </div>
          <div class="timeline-text">${a.explanation}</div>
        </div>
      `).join('');
    } else {
      alertList.innerHTML = '<div class="text-center text-muted">No active alerts.</div>';
    }
  } catch (err) {
    console.error('Failed to load dashboard stats:', err);
  }
}

// -------------------------------------------------------------
// TRANSACTIONS & INGESTION
// -------------------------------------------------------------
async function loadTransactions() {
  const startDate = document.getElementById('filterStartDate').value;
  const endDate = document.getElementById('filterEndDate').value;
  const minAmount = document.getElementById('filterMinAmount').value;
  const maxAmount = document.getElementById('filterMaxAmount').value;
  const search = document.getElementById('filterSearch').value;

  const params = new URLSearchParams();
  if (startDate) params.append('startDate', startDate);
  if (endDate) params.append('endDate', endDate);
  if (minAmount) params.append('minAmount', minAmount);
  if (maxAmount) params.append('maxAmount', maxAmount);
  if (search) params.append('search', search);

  try {
    const res = await fetch(`/api/transactions?${params.toString()}`);
    const data = await res.json();
    const rows = data.transactions || [];

    document.getElementById('txnCounter').textContent = `${rows.length} records`;
    const tbody = document.querySelector('#transactionsTable tbody');

    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No transactions match current filters.</td></tr>';
      return;
    }

    tbody.innerHTML = rows.map(t => `
      <tr>
        <td><strong class="font-mono text-cyan">${t.txn_code}</strong></td>
        <td>${t.sender_acc || t.sender_account_id}</td>
        <td>${t.receiver_acc || t.receiver_account_id}</td>
        <td class="font-mono font-bold">$${Number(t.amount).toLocaleString(undefined, { minimumFractionDigits: 2 })}</td>
        <td>${t.transaction_date}</td>
        <td><span class="badge badge-info">${t.channel}</span></td>
        <td class="text-muted text-sm">${t.description || '-'}</td>
        <td>
          <button class="btn btn-secondary btn-xs" onclick="inspectRisk('TRANSACTION', '${t.txn_code}')">Risk</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load transactions:', err);
  }
}

// -------------------------------------------------------------
// FRAUD DETECTION & RULES
// -------------------------------------------------------------
async function loadDetectionRules() {
  try {
    const res = await fetch('/api/detection/rules');
    const data = await res.json();
    const list = document.getElementById('detectionRulesList');

    if (!data.rules) return;

    list.innerHTML = data.rules.map(r => `
      <div class="timeline-item">
        <div class="timeline-header">
          <strong>${r.rule_code}: ${r.rule_name}</strong>
          <span class="badge ${r.status === 'ACTIVE' ? 'badge-success' : 'badge-outline'}">${r.status}</span>
        </div>
        <div class="timeline-text text-muted">${r.description}</div>
        <div class="text-xs text-dim mt-2 font-mono">Type: ${r.rule_type} | Threshold: $${Number(r.threshold_amount).toLocaleString()} | Severity: ${r.severity}</div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load rules:', err);
  }
}

async function runFraudEngineScan() {
  try {
    const res = await fetch('/api/detection/run', { method: 'POST' });
    const data = await res.json();
    const list = document.getElementById('detectedPatternsList');
    document.getElementById('patternCounterBadge').textContent = `${data.patternsDetected} Patterns`;

    if (data.patterns && data.patterns.length > 0) {
      list.innerHTML = data.patterns.map(p => `
        <div class="timeline-item">
          <div class="timeline-header">
            <strong class="text-amber">${p.patternName} (${p.patternCode})</strong>
            <span class="badge badge-danger">${p.severity}</span>
          </div>
          <div class="timeline-text">${p.explanation}</div>
          <div class="text-xs font-mono mt-2 text-cyan">Related Txns: ${p.relatedTransactions.join(', ')}</div>
        </div>
      `).join('');
    } else {
      list.innerHTML = '<div class="text-center text-muted">No suspicious patterns detected.</div>';
    }

    loadDashboardData();
  } catch (err) {
    console.error('Failed to run pattern scan:', err);
  }
}

// -------------------------------------------------------------
// RISK EXPLAINABILITY MODAL (FT-14)
// -------------------------------------------------------------
async function inspectRisk(entityType, entityId) {
  try {
    const res = await fetch(`/api/risk/assess/${entityType}/${entityId}`);
    const data = await res.json();
    const a = data.assessment;

    if (!a) return alert('Failed to compute risk assessment');

    document.getElementById('riskModalTitle').textContent = `Risk Assessment: ${a.entityId} (${a.entityType})`;
    const content = document.getElementById('riskModalContent');

    content.innerHTML = `
      <div class="kpi-card mb-3">
        <div class="kpi-data">
          <span class="kpi-value ${a.riskLevel === 'HIGH' ? 'text-red' : 'text-amber'}">${a.overallScore} / 100</span>
          <span class="kpi-label">Classified Risk Level: <strong>${a.riskLevel}</strong></span>
        </div>
      </div>
      <h4 class="mt-3">Contributing Risk Factors & Evidence Breakdown:</h4>
      <div class="factors-list mt-2">
        ${a.factors.map(f => `
          <div class="timeline-item">
            <div class="timeline-header">
              <strong>${f.name}</strong>
              <span class="badge badge-warning">+${f.points} pts (weight ${(f.weight * 100).toFixed(0)}%)</span>
            </div>
            <div class="timeline-text text-muted">${f.desc}</div>
          </div>
        `).join('')}
      </div>
    `;

    openModal('riskModal');
  } catch (err) {
    console.error('Failed to inspect risk:', err);
  }
}

// -------------------------------------------------------------
// NETWORK GRAPH & MONEY FLOW TRACER (FT-18)
// -------------------------------------------------------------
let canvas, ctx;
let nodePositions = {};
let isDragging = false;
let draggedNode = null;

async function initNetworkGraph() {
  canvas = document.getElementById('networkCanvas');
  if (!canvas) return;
  ctx = canvas.getContext('2d');

  try {
    const res = await fetch('/api/network/graph');
    networkData = await res.json();
    layoutNodes();
    renderGraph();
    setupCanvasEvents();
  } catch (err) {
    console.error('Failed to load network graph:', err);
  }
}

function layoutNodes() {
  const width = canvas.width;
  const height = canvas.height;
  const count = networkData.nodes.length;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.38;

  networkData.nodes.forEach((node, i) => {
    const angle = (i / count) * 2 * Math.PI;
    nodePositions[node.id] = {
      x: centerX + radius * Math.cos(angle) + (Math.random() - 0.5) * 40,
      y: centerY + radius * Math.sin(angle) + (Math.random() - 0.5) * 40,
      radius: 18,
      node
    };
  });
}

function renderGraph() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Render Edges
  networkData.edges.forEach(edge => {
    const src = nodePositions[edge.source];
    const dst = nodePositions[edge.target];
    if (!src || !dst) return;

    const isHighlighted = activePathHops.some(h => h.sender === edge.source && h.receiver === edge.target);

    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(dst.x, dst.y);

    if (isHighlighted) {
      ctx.strokeStyle = '#f59e0b';
      ctx.lineWidth = 4;
      ctx.shadowColor = '#f59e0b';
      ctx.shadowBlur = 10;
    } else {
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 1.5;
      ctx.shadowBlur = 0;
    }
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Arrow indicator
    const midX = (src.x + dst.x) / 2;
    const midY = (src.y + dst.y) / 2;
    const angle = Math.atan2(dst.y - src.y, dst.x - src.x);
    ctx.beginPath();
    ctx.fillStyle = isHighlighted ? '#f59e0b' : '#475569';
    ctx.arc(midX, midY, isHighlighted ? 4 : 2, 0, 2 * Math.PI);
    ctx.fill();
  });

  // Render Nodes
  Object.values(nodePositions).forEach(item => {
    ctx.beginPath();
    ctx.arc(item.x, item.y, item.radius, 0, 2 * Math.PI);

    if (item.node.accountType === 'OFFSHORE') {
      ctx.fillStyle = '#ef4444'; // Red for offshore
    } else if (item.node.customerType === 'CORPORATE') {
      ctx.fillStyle = '#3b82f6'; // Blue for corporate
    } else {
      ctx.fillStyle = '#10b981'; // Green for retail
    }

    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Node label
    ctx.fillStyle = '#cbd5e1';
    ctx.font = '10px JetBrains Mono';
    ctx.textAlign = 'center';
    ctx.fillText(item.node.id, item.x, item.y + item.radius + 12);
  });
}

function setupCanvasEvents() {
  canvas.onmousedown = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    for (const item of Object.values(nodePositions)) {
      const dist = Math.hypot(item.x - mouseX, item.y - mouseY);
      if (dist <= item.radius) {
        isDragging = true;
        draggedNode = item;
        selectedNode = item.node;
        break;
      }
    }
  };

  canvas.onmousemove = (e) => {
    if (isDragging && draggedNode) {
      const rect = canvas.getBoundingClientRect();
      draggedNode.x = e.clientX - rect.left;
      draggedNode.y = e.clientY - rect.top;
      renderGraph();
    }
  };

  canvas.onmouseup = () => {
    isDragging = false;
    draggedNode = null;
  };
}

async function traceMoneyFlow() {
  const root = document.getElementById('traceRootInput').value.trim();
  const dest = document.getElementById('traceDestInput').value.trim();

  try {
    const res = await fetch(`/api/network/trace?root=${root}&destination=${dest}`);
    const data = await res.json();
    const resultBox = document.getElementById('pathTraceResult');

    if (data.paths && data.paths.length > 0) {
      const p = data.paths[0];
      activePathHops = p.hops;
      renderGraph();

      resultBox.innerHTML = `
        <div class="alert alert-warning">
          <strong>Path Identified (${p.totalHops} Hops):</strong>
          <div class="font-mono text-cyan mt-1">${p.pathString}</div>
          <div class="mt-2 text-xs text-muted">Minimum Flow Rate: $${p.minFlow.toLocaleString()} USD</div>
        </div>
        <div class="hops-detail mt-3">
          ${p.hops.map((h, i) => `
            <div class="timeline-item">
              <div class="timeline-header">
                <strong>Hop ${i + 1}: ${h.sender} ➔ ${h.receiver}</strong>
                <span class="badge badge-info">$${Number(h.amount).toLocaleString()}</span>
              </div>
              <div class="timeline-text text-muted text-xs">Txn ID: ${h.txnCode} | Date: ${h.date} | Channel: ${h.channel}</div>
            </div>
          `).join('')}
        </div>
      `;
    } else {
      activePathHops = [];
      renderGraph();
      resultBox.innerHTML = `<div class="alert alert-danger">${data.summary}</div>`;
    }
  } catch (err) {
    console.error('Failed to trace money flow:', err);
  }
}

// -------------------------------------------------------------
// ALERTS CENTER
// -------------------------------------------------------------
async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    const data = await res.json();
    const tbody = document.querySelector('#alertsTable tbody');

    if (!data.alerts || data.alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No alerts found.</td></tr>';
      return;
    }

    tbody.innerHTML = data.alerts.map(a => `
      <tr>
        <td><strong class="font-mono text-cyan">${a.alert_id}</strong></td>
        <td>${a.entity_id}</td>
        <td><span class="badge ${a.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${a.severity}</span></td>
        <td><span class="badge badge-danger">${a.score}</span></td>
        <td><span class="badge badge-info">${a.pattern_code}</span></td>
        <td><span class="badge badge-outline">${a.status}</span></td>
        <td>${a.assigned_name || 'Senior Investigator'}</td>
        <td>
          <button class="btn btn-secondary btn-xs" onclick="inspectRisk('TRANSACTION', '${a.entity_id}')">Explain</button>
          <button class="btn btn-primary btn-xs" onclick="openCreateCaseModal('${a.alert_id}')">Promote to Case</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load alerts:', err);
  }
}

// -------------------------------------------------------------
// CASE MANAGEMENT (FT-16, FT-17)
// -------------------------------------------------------------
async function loadCases() {
  try {
    const res = await fetch('/api/cases');
    const data = await res.json();
    const tbody = document.querySelector('#casesTable tbody');

    if (!data.cases || data.cases.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No open cases.</td></tr>';
      return;
    }

    tbody.innerHTML = data.cases.map(c => `
      <tr>
        <td><strong class="font-mono text-cyan">${c.case_id}</strong></td>
        <td>${c.title}</td>
        <td><span class="badge ${c.priority === 'HIGH' ? 'badge-danger' : 'badge-warning'}">${c.priority}</span></td>
        <td><span class="badge badge-success">${c.status}</span></td>
        <td>${c.assigned_name || 'Investigator'}</td>
        <td><button class="btn btn-secondary btn-xs" onclick="selectCase('${c.case_id}')">Open Dossier</button></td>
      </tr>
    `).join('');

    // Default select first case
    if (data.cases.length > 0) {
      selectCase(data.cases[0].case_id);
    }
  } catch (err) {
    console.error('Failed to load cases:', err);
  }
}

async function selectCase(caseId) {
  try {
    const res = await fetch(`/api/cases/${caseId}`);
    const data = await res.json();
    const c = data.caseData;
    const notes = data.notes || [];

    document.getElementById('caseDetailTitle').textContent = `${c.case_id}: ${c.title}`;
    document.getElementById('caseDossierActions').innerHTML = `
      <button class="btn btn-secondary btn-xs" onclick="generateReport('${c.case_id}')">Generate Report</button>
      <button class="btn btn-outline btn-xs" onclick="updateCaseStatus('${c.case_id}', 'Closed')">Mark Closed</button>
    `;

    document.getElementById('caseDetailBody').innerHTML = `
      <div class="dossier-meta">
        <div><strong>Status:</strong> <span class="badge badge-success">${c.status}</span></div>
        <div><strong>Priority:</strong> <span class="badge badge-danger">${c.priority}</span></div>
        <div><strong>Assigned To:</strong> ${c.assigned_name || 'Senior Investigator'}</div>
        <div><strong>Linked Alert:</strong> <span class="font-mono text-cyan">${c.alert_id || 'None'}</span></div>
      </div>
      <p class="text-sm mt-3">${c.description || 'No description provided.'}</p>
      
      <h4 class="mt-4">Case Notes & Findings (FT-17):</h4>
      <div class="notes-timeline mt-2" id="caseNotesTimeline">
        ${notes.map(n => `
          <div class="timeline-item">
            <div class="timeline-header">
              <strong>${n.author_name}</strong>
              <span>${n.created_at}</span>
            </div>
            <div class="timeline-text">${n.note_text}</div>
          </div>
        `).join('')}
      </div>

      <div class="add-note-box mt-4">
        <textarea id="newCaseNoteText" class="form-control" rows="2" placeholder="Record investigation findings or note..."></textarea>
        <button class="btn btn-primary btn-sm mt-2" onclick="submitCaseNote('${c.case_id}')">Add Note to History</button>
      </div>
    `;
  } catch (err) {
    console.error('Failed to select case:', err);
  }
}

async function submitCaseNote(caseId) {
  const text = document.getElementById('newCaseNoteText').value.trim();
  if (!text) return alert('Note text cannot be empty');

  try {
    const res = await fetch(`/api/cases/${caseId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ noteText: text })
    });
    const data = await res.json();
    if (data.success) {
      selectCase(caseId);
    }
  } catch (err) {
    console.error('Failed to submit note:', err);
  }
}

async function updateCaseStatus(caseId, status) {
  try {
    const res = await fetch(`/api/cases/${caseId}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    const data = await res.json();
    if (data.success) {
      loadCases();
      selectCase(caseId);
    }
  } catch (err) {
    console.error('Failed to update case status:', err);
  }
}

// -------------------------------------------------------------
// INVESTIGATION REPORT GENERATION (FT-19)
// -------------------------------------------------------------
async function generateReport(caseId = 'CASE-1001') {
  try {
    const res = await fetch('/api/reports/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caseId })
    });
    const data = await res.json();
    if (data.success) {
      switchTab('reports');
      const box = document.getElementById('reportContainer');
      const rep = data.report;
      box.innerHTML = `
        <div class="alert alert-success">
          <strong>Report ${data.reportId} Generated Successfully!</strong> Export ready for regulatory filing.
        </div>
        <div class="report-dossier-paper mt-3 card p-4">
          <div class="dossier-header border-b pb-3 mb-3">
            <h2 class="text-cyan">${rep.title}</h2>
            <div class="text-xs text-muted font-mono">Dossier ID: ${rep.reportId} | Classification: ${rep.classification}</div>
            <div class="text-xs text-muted font-mono">Generated At: ${rep.generatedAt} by ${rep.generatedBy}</div>
          </div>
          <h4>Executive Case Summary</h4>
          <p class="text-sm mt-1">${rep.caseDetails?.description || 'Circular routing network identified across multiple accounts.'}</p>
          <h4 class="mt-3">Primary Alert & Trigger Criteria</h4>
          <p class="text-sm text-amber font-mono">${rep.alertDetails?.explanation || 'Circular transfer loops with elevated velocity'}</p>
          <h4 class="mt-3">Investigation Timeline & Audit Trail</h4>
          <div class="mt-2">
            ${(rep.notesTimeline || []).map(n => `
              <div class="text-xs text-muted font-mono">[${n.created_at}] ${n.author_name}: ${n.note_text}</div>
            `).join('')}
          </div>
          <div class="mt-4 pt-3 border-t">
            <button class="btn btn-secondary btn-sm" onclick="window.print()">Print / Export PDF</button>
          </div>
        </div>
      `;
    }
  } catch (err) {
    console.error('Failed to generate report:', err);
  }
}

// -------------------------------------------------------------
// AUDIT LOGS (FT-20, NFT-15)
// -------------------------------------------------------------
async function loadAuditLogs() {
  try {
    const res = await fetch('/api/audit/logs');
    const data = await res.json();
    const tbody = document.querySelector('#auditTable tbody');

    if (!data.logs || data.logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No audit records found.</td></tr>';
      return;
    }

    tbody.innerHTML = data.logs.map(l => `
      <tr>
        <td>#${l.log_id}</td>
        <td>${l.timestamp}</td>
        <td>${l.user_id}</td>
        <td>${l.user_name}</td>
        <td><strong class="text-cyan">${l.action}</strong></td>
        <td>${l.target_entity}</td>
        <td class="text-xs text-dim">${l.details}</td>
        <td>${l.ip_address}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load audit logs:', err);
  }
}

// -------------------------------------------------------------
// SYSTEM VERIFICATION SUITE RUNNER
// -------------------------------------------------------------
async function runVerificationSuite() {
  const btn = document.getElementById('runFullTestSuiteBtn');
  btn.textContent = 'Executing 35 Test Cases...';
  btn.disabled = true;

  try {
    const res = await fetch('/api/test-suite/run');
    const data = await res.json();

    document.getElementById('testTotal').textContent = data.summary.total;
    document.getElementById('testPassed').textContent = data.summary.passed;
    document.getElementById('testFailed').textContent = data.summary.failed;
    const rate = Math.round((data.summary.passed / data.summary.total) * 100);
    document.getElementById('testRate').textContent = `${rate}%`;

    // Render FT Table (FT-01 to FT-20)
    const ftTbody = document.querySelector('#ftTable tbody');
    ftTbody.innerHTML = data.functionalTests.map(t => `
      <tr>
        <td><strong class="font-mono text-cyan">${t.id}</strong></td>
        <td>${t.name}</td>
        <td class="text-xs text-muted">${t.expected}</td>
        <td class="text-xs">${t.actual}</td>
        <td><span class="badge ${t.status === 'PASS' ? 'badge-success' : 'badge-danger'}">${t.status}</span></td>
      </tr>
    `).join('');

    // Render NFT Table (NFT-01 to NFT-15)
    const nftTbody = document.querySelector('#nftTable tbody');
    nftTbody.innerHTML = data.nonFunctionalTests.map(t => `
      <tr>
        <td><strong class="font-mono text-cyan">${t.id}</strong></td>
        <td>${t.name}</td>
        <td class="text-xs text-muted">${t.expected}</td>
        <td class="text-xs">${t.actual}</td>
        <td class="font-mono text-xs text-amber">${t.metric || '-'}</td>
        <td><span class="badge ${t.status === 'PASS' ? 'badge-success' : 'badge-danger'}">${t.status}</span></td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to execute test suite:', err);
  } finally {
    btn.textContent = 'Execute Full Test Suite (35 Tests)';
    btn.disabled = false;
  }
}

// -------------------------------------------------------------
// EVENT LISTENERS & MODALS
// -------------------------------------------------------------
function setupEventListeners() {
  document.getElementById('triggerDetectionBtn').addEventListener('click', runFraudEngineScan);
  document.getElementById('runFraudScanBtn').addEventListener('click', runFraudEngineScan);
  document.getElementById('applyFiltersBtn').addEventListener('click', loadTransactions);
  document.getElementById('resetFiltersBtn').addEventListener('click', () => {
    document.getElementById('filterStartDate').value = '2026-10-01';
    document.getElementById('filterEndDate').value = '2026-10-14';
    document.getElementById('filterMinAmount').value = '';
    document.getElementById('filterMaxAmount').value = '';
    document.getElementById('filterSearch').value = '';
    loadTransactions();
  });
  document.getElementById('traceFlowBtn').addEventListener('click', traceMoneyFlow);
  document.getElementById('generateNewReportBtn').addEventListener('click', () => generateReport('CASE-1001'));
  document.getElementById('refreshAuditBtn').addEventListener('click', loadAuditLogs);
  document.getElementById('runFullTestSuiteBtn').addEventListener('click', runVerificationSuite);

  // CSV Ingestion buttons
  document.getElementById('openUploadModalBtn').addEventListener('click', () => openModal('uploadModal'));
  document.getElementById('loadValidCsvBtn').addEventListener('click', () => {
    document.getElementById('csvDataInput').value = `TransactionID,SenderAccount,ReceiverAccount,Amount,Currency,TransactionDate,Channel,Description\nTXN-2001,ACC-1001,ACC-1002,15000.00,USD,2026-10-02,Wire,Initial fund transfer\nTXN-2002,ACC-1002,ACC-1003,14800.00,USD,2026-10-03,Wire,Intermediary forwarding`;
  });
  document.getElementById('loadInvalidCsvBtn').addEventListener('click', () => {
    document.getElementById('csvDataInput').value = `TransactionID,SenderAccount,ReceiverAccount,Amount,Currency,Channel,Description\nTXN-9001,ACC-1001,ACC-1002,15000.00,USD,Wire,Missing TransactionDate column`;
  });
  document.getElementById('loadDuplicateCsvBtn').addEventListener('click', () => {
    document.getElementById('csvDataInput').value = `TransactionID,SenderAccount,ReceiverAccount,Amount,Currency,TransactionDate,Channel,Description\nTXN-1001,ACC-1001,ACC-1002,15000.00,USD,2026-10-02,Wire,Duplicate ID row`;
  });

  document.getElementById('submitCsvUploadBtn').addEventListener('click', async () => {
    const csvData = document.getElementById('csvDataInput').value.trim();
    const feedback = document.getElementById('uploadFeedback');
    if (!csvData) {
      feedback.innerHTML = '<div class="alert alert-danger">Please enter or load CSV data</div>';
      return;
    }

    try {
      const res = await fetch('/api/transactions/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csvData })
      });
      const data = await res.json();
      if (data.success) {
        feedback.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
        setTimeout(() => {
          closeModal('uploadModal');
          loadTransactions();
          loadDashboardData();
        }, 1200);
      } else {
        feedback.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
      }
    } catch (err) {
      feedback.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
    }
  });

  // Case creation submit
  document.getElementById('openNewCaseModalBtn').addEventListener('click', () => openCreateCaseModal());
  document.getElementById('submitNewCaseBtn').addEventListener('click', async () => {
    const alertId = document.getElementById('caseAlertIdInput').value.trim();
    const title = document.getElementById('caseTitleInput').value.trim();
    const priority = document.getElementById('casePriorityInput').value;
    const description = document.getElementById('caseDescInput').value.trim();

    try {
      const res = await fetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertId, title, priority, description })
      });
      const data = await res.json();
      if (data.success) {
        closeModal('newCaseModal');
        loadCases();
      }
    } catch (err) {
      console.error('Failed to create case:', err);
    }
  });

  // Auth Modal
  document.getElementById('authModalBtn').addEventListener('click', () => openModal('authModal'));
  document.getElementById('submitLoginBtn').addEventListener('click', async () => {
    const email = document.getElementById('loginEmailInput').value.trim();
    const password = document.getElementById('loginPassInput').value;
    const fb = document.getElementById('loginFeedback');

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (data.success) {
        currentUser = data.user;
        currentToken = data.token;
        document.getElementById('roleSelector').value = data.user.role;
        fb.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
        setTimeout(() => closeModal('authModal'), 1000);
      } else {
        fb.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
      }
    } catch (err) {
      fb.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
    }
  });
}

function openCreateCaseModal(alertId = '') {
  document.getElementById('caseAlertIdInput').value = alertId;
  openModal('newCaseModal');
}

function initModals() {
  window.openModal = (modalId) => {
    const m = document.getElementById(modalId);
    if (m) m.classList.add('active');
  };
  window.closeModal = (modalId) => {
    const m = document.getElementById(modalId);
    if (m) m.classList.remove('active');
  };
}
