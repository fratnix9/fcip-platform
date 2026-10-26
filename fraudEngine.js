// fraudEngine.js - FCIP Suspicious Activity Detection & Explainable Risk Scoring Engine
// Implements FR13-FR22, NFR27-NFR29, and satisfies FT-11 through FT-15

class FraudEngine {
  constructor(db, auditLogger) {
    this.db = db;
    this.audit = auditLogger;
  }

  // FT-11: Detect Single Suspicious Transactions against Active Rules
  detectSuspiciousTransaction(transaction) {
    const activeRules = this.db.prepare(`
      SELECT rule_code, rule_name, rule_type, threshold_amount, severity, description
      FROM detection_rules
      WHERE status = 'ACTIVE'
    `).all();

    const triggeredRules = [];

    for (const rule of activeRules) {
      if (rule.rule_type === 'THRESHOLD' && transaction.amount >= rule.threshold_amount) {
        triggeredRules.push({
          ruleCode: rule.rule_code,
          ruleName: rule.rule_name,
          severity: rule.severity,
          reason: `Transaction amount $${transaction.amount.toLocaleString()} exceeds threshold limit of $${rule.threshold_amount.toLocaleString()}.`
        });
      }

      if (rule.rule_type === 'JURISDICTION' && (transaction.channel === 'Offshore Wire' || transaction.description?.toLowerCase().includes('offshore'))) {
        triggeredRules.push({
          ruleCode: rule.rule_code,
          ruleName: rule.rule_name,
          severity: rule.severity,
          reason: `Transaction routed via high-risk channel or offshore jurisdiction (${transaction.channel}).`
        });
      }
    }

    const isSuspicious = triggeredRules.length > 0;
    return {
      isSuspicious,
      transactionId: transaction.txn_code,
      triggeredRules
    };
  }

  // FT-12: Detect Complex Transaction Patterns (Structuring, Circular, Rapid Flow, Layering)
  detectPatterns() {
    const detectedPatterns = [];
    const txns = this.db.prepare(`
      SELECT id, txn_code, sender_account_id, receiver_account_id, amount, transaction_date, channel, description
      FROM transactions
      ORDER BY transaction_date ASC
    `).all();

    // 1. Detect Structuring / Smurfing (Repeated transactions just under $10,000 threshold)
    const receiverMap = {};
    for (const t of txns) {
      if (t.amount >= 9000 && t.amount < 10000) {
        if (!receiverMap[t.receiver_account_id]) receiverMap[t.receiver_account_id] = [];
        receiverMap[t.receiver_account_id].push(t);
      }
    }

    for (const [receiver, items] of Object.entries(receiverMap)) {
      if (items.length >= 2) {
        const totalAmount = items.reduce((sum, i) => sum + i.amount, 0);
        detectedPatterns.push({
          patternCode: 'PAT-STRUCTURING',
          patternName: 'Structuring / Smurfing Pattern',
          severity: 'HIGH',
          entityId: receiver,
          relatedTransactions: items.map(i => i.txn_code),
          explanation: `Detected ${items.length} sub-threshold transactions aggregating to $${totalAmount.toLocaleString()} deposited into account ${receiver}.`
        });
      }
    }

    // 2. Detect Circular Transfers (A -> B -> C -> A or direct cycle)
    const graph = {};
    const txnMap = {};
    for (const t of txns) {
      if (!graph[t.sender_account_id]) graph[t.sender_account_id] = [];
      graph[t.sender_account_id].push(t.receiver_account_id);
      const edgeKey = `${t.sender_account_id}->${t.receiver_account_id}`;
      if (!txnMap[edgeKey]) txnMap[edgeKey] = [];
      txnMap[edgeKey].push(t.txn_code);
    }

    const findCycles = () => {
      const visited = new Set();
      const recStack = new Set();
      const cycles = [];

      const dfs = (node, path) => {
        visited.add(node);
        recStack.add(node);
        const neighbors = graph[node] || [];

        for (const neighbor of neighbors) {
          if (!visited.has(neighbor)) {
            dfs(neighbor, [...path, neighbor]);
          } else if (recStack.has(neighbor)) {
            const cycleStartIdx = path.indexOf(neighbor);
            if (cycleStartIdx !== -1) {
              cycles.push(path.slice(cycleStartIdx).concat(neighbor));
            }
          }
        }
        recStack.delete(node);
      };

      for (const node of Object.keys(graph)) {
        if (!visited.has(node)) {
          dfs(node, [node]);
        }
      }
      return cycles;
    };

    const cycles = findCycles();
    for (const cycle of cycles) {
      if (cycle.length >= 3) {
        const relatedTxns = [];
        for (let i = 0; i < cycle.length - 1; i++) {
          const edge = `${cycle[i]}->${cycle[i + 1]}`;
          if (txnMap[edge]) relatedTxns.push(...txnMap[edge]);
        }
        detectedPatterns.push({
          patternCode: 'PAT-CIRCULAR',
          patternName: 'Circular Transaction Laundering',
          severity: 'CRITICAL',
          entityId: cycle[0],
          cyclePath: cycle.join(' -> '),
          relatedTransactions: [...new Set(relatedTxns)],
          explanation: `Identified closed money-flow cycle: ${cycle.join(' ➔ ')}. Funds return to origin entity.`
        });
      }
    }

    // 3. Detect Rapid Fund Movement (Passthrough within 48 hours)
    for (let i = 0; i < txns.length; i++) {
      for (let j = i + 1; j < txns.length; j++) {
        const inTxn = txns[i];
        const outTxn = txns[j];
        if (inTxn.receiver_account_id === outTxn.sender_account_id) {
          const d1 = new Date(inTxn.transaction_date).getTime();
          const d2 = new Date(outTxn.transaction_date).getTime();
          const diffHours = (d2 - d1) / (1000 * 60 * 60);
          if (diffHours >= 0 && diffHours <= 48 && Math.abs(inTxn.amount - outTxn.amount) / inTxn.amount < 0.15) {
            detectedPatterns.push({
              patternCode: 'PAT-RAPID',
              patternName: 'Rapid Intermediary Passthrough',
              severity: 'HIGH',
              entityId: inTxn.receiver_account_id,
              relatedTransactions: [inTxn.txn_code, outTxn.txn_code],
              explanation: `Account ${inTxn.receiver_account_id} received $${inTxn.amount.toLocaleString()} and rapidly forwarded $${outTxn.amount.toLocaleString()} within ${diffHours.toFixed(1)} hours.`
            });
          }
        }
      }
    }

    return detectedPatterns;
  }

  // FT-13: Calculate and Classify Risk Score (0 - 100)
  calculateRiskScore(entityType, entityId) {
    let factors = [];
    let baseScore = 15.0; // Baseline transaction friction

    if (entityType === 'TRANSACTION') {
      const txn = this.db.prepare('SELECT * FROM transactions WHERE txn_code = ?').get(entityId);
      if (!txn) return null;

      // Factor 1: Value magnitude
      if (txn.amount >= 500000) {
        factors.push({ category: 'THRESHOLD', name: 'High-Value Anomaly', points: 35.0, weight: 0.35, desc: 'Transaction amount exceeds $500,000 threshold' });
      } else if (txn.amount >= 50000) {
        factors.push({ category: 'THRESHOLD', name: 'Threshold Breach', points: 25.0, weight: 0.25, desc: 'Transaction amount exceeds $50,000 reporting limit' });
      } else if (txn.amount >= 9000 && txn.amount < 10000) {
        factors.push({ category: 'STRUCTURING', name: 'Sub-threshold Cash Amount', points: 30.0, weight: 0.30, desc: 'Amount lies just below the $10,000 mandatory CTR filing limit' });
      }

      // Factor 2: Channel & Jurisdiction Risk
      if (txn.channel === 'Offshore Wire') {
        factors.push({ category: 'JURISDICTION', name: 'Offshore Wire Transfer', points: 30.0, weight: 0.30, desc: 'Transfer dispatched via unverified offshore secrecy jurisdiction' });
      } else if (txn.channel === 'Cash Deposit') {
        factors.push({ category: 'CHANNEL', name: 'Cash Deposit High Velocity', points: 18.0, weight: 0.20, desc: 'Physical cash placement detected' });
      }

      // Factor 3: Pattern Involvement
      const patterns = this.detectPatterns();
      const matchedPat = patterns.find(p => p.relatedTransactions.includes(txn.txn_code));
      if (matchedPat) {
        factors.push({
          category: 'PATTERN',
          name: matchedPat.patternName,
          points: matchedPat.severity === 'CRITICAL' ? 38.0 : 25.0,
          weight: 0.40,
          desc: matchedPat.explanation
        });
      }
    } else if (entityType === 'ACCOUNT') {
      const acc = this.db.prepare('SELECT * FROM accounts WHERE account_id = ?').get(entityId);
      if (!acc) return null;
      if (acc.account_type === 'OFFSHORE') {
        factors.push({ category: 'ENTITY_TYPE', name: 'Offshore Account Classification', points: 35.0, weight: 0.40, desc: 'Registered in high-risk offshore jurisdiction' });
      }
      const txnsCount = this.db.prepare('SELECT COUNT(*) as count FROM transactions WHERE sender_account_id = ? OR receiver_account_id = ?').get(entityId, entityId).count;
      if (txnsCount > 3) {
        factors.push({ category: 'VELOCITY', name: 'Elevated Transaction Velocity', points: 25.0, weight: 0.30, desc: `Entity actively involved in ${txnsCount} transactions within window` });
      }
    }

    // Compute composite weighted score
    let calculatedScore = baseScore;
    for (const f of factors) {
      calculatedScore += f.points;
    }
    calculatedScore = Math.min(100.0, Math.max(0.0, Math.round(calculatedScore * 10) / 10));

    // FT-13 Risk Classification
    let riskLevel = 'LOW';
    if (calculatedScore >= 70.0) {
      riskLevel = 'HIGH';
    } else if (calculatedScore >= 40.0) {
      riskLevel = 'MEDIUM';
    }

    return {
      entityType,
      entityId,
      overallScore: calculatedScore,
      riskLevel,
      factors
    };
  }

  // FT-14: Save and Display Risk Score Explanation
  saveAndExplainRiskScore(entityType, entityId) {
    const assessment = this.calculateRiskScore(entityType, entityId);
    if (!assessment) return null;

    // Persist score
    const insertScore = this.db.prepare(`
      INSERT INTO risk_scores (entity_type, entity_id, score, risk_level, calculated_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `);
    const res = insertScore.run(assessment.entityType, assessment.entityId, assessment.overallScore, assessment.riskLevel);
    const scoreId = Number(res.lastInsertRowid);

    // Persist factors (NFT-07 parameterized)
    const insertFactor = this.db.prepare(`
      INSERT INTO risk_factors (risk_score_id, factor_category, factor_name, score_contribution, weight, description)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    for (const f of assessment.factors) {
      insertFactor.run(scoreId, f.category, f.name, f.points, f.weight, f.desc);
    }

    return {
      scoreId,
      ...assessment
    };
  }

  // FT-15: Auto-Generate Alert for High-Risk Activity
  evaluateAndGenerateAlerts() {
    const unflaggedTxns = this.db.prepare(`
      SELECT t.* FROM transactions t
      LEFT JOIN alerts a ON t.id = a.transaction_id
      WHERE a.id IS NULL
    `).all();

    const createdAlerts = [];

    for (const txn of unflaggedTxns) {
      const assessment = this.saveAndExplainRiskScore('TRANSACTION', txn.txn_code);
      if (assessment && assessment.overallScore >= 70.0) {
        const alertId = 'ALT-' + (1000 + Math.floor(Math.random() * 9000));
        const pattern = assessment.factors.find(f => f.category === 'PATTERN')?.category || 'HIGH_RISK_RULE';
        const explanation = assessment.factors.map(f => `${f.name}: ${f.desc}`).join('; ');

        this.db.prepare(`
          INSERT INTO alerts (alert_id, transaction_id, entity_type, entity_id, severity, status, pattern_code, score, explanation, created_at, assigned_to)
          VALUES (?, ?, 'TRANSACTION', ?, 'HIGH', 'NEW', ?, ?, ?, datetime('now'), 'USR-0002')
        `).run(alertId, txn.id, txn.txn_code, pattern, assessment.overallScore, explanation);

        createdAlerts.push({
          alertId,
          transactionId: txn.txn_code,
          score: assessment.overallScore,
          explanation
        });

        this.audit.log('SYSTEM', 'FraudEngine', 'ALERT_GENERATED', 'alerts', { alertId, transaction: txn.txn_code, score: assessment.overallScore });
      }
    }

    return createdAlerts;
  }
}

module.exports = { FraudEngine };
