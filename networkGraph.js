// networkGraph.js - FCIP Financial Network Analysis & Money-Flow Path Tracing Engine
// Implements FR25-FR30, NFR30 and satisfies FT-18

class NetworkGraphEngine {
  constructor(db) {
    this.db = db;
  }

  // Build the complete graph model from transactions and accounts
  getNetworkGraph() {
    const accounts = this.db.prepare(`
      SELECT a.account_id, a.account_number, a.account_type, a.balance, a.status, a.branch,
             c.customer_id, c.first_name, c.last_name, c.customer_type, c.risk_rating
      FROM accounts a
      JOIN customers c ON a.customer_id = c.customer_id
    `).all();

    const txns = this.db.prepare(`
      SELECT id, txn_code, sender_account_id, receiver_account_id, amount, transaction_date, channel, description
      FROM transactions
      ORDER BY transaction_date ASC
    `).all();

    const nodes = [];
    const nodeMap = new Set();

    for (const acc of accounts) {
      nodes.push({
        id: acc.account_id,
        label: `${acc.account_number} (${acc.first_name} ${acc.last_name})`,
        accountNumber: acc.account_number,
        customer: `${acc.first_name} ${acc.last_name}`,
        customerType: acc.customer_type,
        accountType: acc.account_type,
        balance: acc.balance,
        riskRating: acc.risk_rating,
        branch: acc.branch
      });
      nodeMap.add(acc.account_id);
    }

    const edges = [];
    const edgeAgg = {};

    for (const t of txns) {
      const key = `${t.sender_account_id}->${t.receiver_account_id}`;
      if (!edgeAgg[key]) {
        edgeAgg[key] = {
          source: t.sender_account_id,
          target: t.receiver_account_id,
          totalAmount: 0,
          count: 0,
          channels: new Set(),
          transactions: []
        };
      }
      edgeAgg[key].totalAmount += t.amount;
      edgeAgg[key].count += 1;
      edgeAgg[key].channels.add(t.channel);
      edgeAgg[key].transactions.push({
        txnCode: t.txn_code,
        amount: t.amount,
        date: t.transaction_date
      });
    }

    for (const [key, val] of Object.entries(edgeAgg)) {
      edges.push({
        id: key,
        source: val.source,
        target: val.target,
        amount: val.totalAmount,
        count: val.count,
        channels: [...val.channels],
        transactions: val.transactions
      });
    }

    return { nodes, edges };
  }

  // FT-18: Trace Money Flow Paths between Root Account and Destination Account
  traceMoneyFlow(rootAccountId, destinationAccountId) {
    const txns = this.db.prepare(`
      SELECT txn_code, sender_account_id, receiver_account_id, amount, transaction_date, channel
      FROM transactions
      ORDER BY transaction_date ASC
    `).all();

    // Build directed adjacency list
    const adj = {};
    for (const t of txns) {
      if (!adj[t.sender_account_id]) adj[t.sender_account_id] = [];
      adj[t.sender_account_id].push({
        next: t.receiver_account_id,
        txnCode: t.txn_code,
        amount: t.amount,
        date: t.transaction_date,
        channel: t.channel
      });
    }

    const allPaths = [];
    const maxDepth = 6;

    // DFS to enumerate paths from root to destination
    const findPaths = (current, target, visited, currentPath, currentFlow) => {
      if (current === target && currentPath.length > 0) {
        allPaths.push({
          hops: [...currentPath],
          totalHops: currentPath.length,
          minFlow: Math.min(...currentPath.map(h => h.amount)),
          pathString: [rootAccountId, ...currentPath.map(h => h.receiver)].join(' ➔ ')
        });
        return;
      }

      if (currentPath.length >= maxDepth) return;

      const neighbors = adj[current] || [];
      for (const edge of neighbors) {
        if (!visited.has(edge.next) || edge.next === target) {
          visited.add(edge.next);
          findPaths(
            edge.next,
            target,
            visited,
            [...currentPath, {
              sender: current,
              receiver: edge.next,
              txnCode: edge.txnCode,
              amount: edge.amount,
              date: edge.date,
              channel: edge.channel
            }],
            Math.min(currentFlow, edge.amount)
          );
          visited.delete(edge.next);
        }
      }
    };

    const visitedSet = new Set([rootAccountId]);
    findPaths(rootAccountId, destinationAccountId, visitedSet, [], Infinity);

    // Save discovered path in transaction_paths table
    if (allPaths.length > 0) {
      const bestPath = allPaths[0];
      this.db.prepare(`
        INSERT INTO transaction_paths (root_entity_id, destination_entity_id, hops_json, total_flow, pattern_detected, created_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `).run(
        rootAccountId,
        destinationAccountId,
        JSON.stringify(bestPath.hops),
        bestPath.minFlow,
        bestPath.totalHops > 2 ? 'MULTI_HOP_LAYERING' : 'DIRECT_TRANSFER'
      );
    }

    return {
      rootAccountId,
      destinationAccountId,
      pathsFound: allPaths.length,
      paths: allPaths,
      summary: allPaths.length > 0
        ? `Found ${allPaths.length} valid money-flow path(s) connecting root ${rootAccountId} to destination ${destinationAccountId}.`
        : `No direct or multi-hop money flow found connecting ${rootAccountId} to ${destinationAccountId}.`
    };
  }
}

module.exports = { NetworkGraphEngine };
