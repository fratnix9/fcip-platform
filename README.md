# Financial Crime Intelligence Platform (FCIP)
### School of Computer Science Engineering and Information Systems
### BCSE301P – Software Engineering Lab
**Vellore Institute of Technology (VIT)**

---

## 👥 Project Team
* **Abraham David Ambrose** (Reg No: `24BYB0172`)
* **Roshan Bilal** (Reg No: `24BYB0130`)
* **Arahat Gaikwad** (Reg No: `24BYB0182`)

---

## 📌 Executive Summary & Purpose
The **Financial Crime Intelligence Platform (FCIP)** is an enterprise-grade investigation system designed to detect, analyze, and visualize suspicious financial activities. The platform assists investigators, financial institutions, and regulatory authorities (FIU) by automatically identifying abnormal transaction patterns, assessing explainable risk levels, tracing money flows through multi-hop entity graphs, and maintaining full regulatory case dossiers.

---

## 🏛️ Architectural & Engineering Alignment

This implementation matches the Software Engineering Lab Assessment I specifications and models:

1. **Process Model:** **Agile (Scrum)** with iterative module delivery and continuous automated testing.
2. **Work Breakdown Structure (WBS):**
   * **Process-Based:** Planning $\rightarrow$ Design $\rightarrow$ Development $\rightarrow$ Testing $\rightarrow$ Deployment
   * **Product-Based:** Authentication, Financial Data, Fraud Engine, Dashboard, Case Mgmt & Reports
   * **Geographic/Deployment:** Client-Side SPA, Server-Side Node.js REST API, SQLite WAL Persistence
   * **Role-Based:** Project Manager, Frontend Developer, Backend Developer, Database Admin, QA Engineer
3. **Requirements Engineering:**
   * **42 Functional Requirements (FR01 – FR42):** User registration, RBAC, dataset ingestion, rule management, pattern detection, risk scoring, explainability breakdown, alert triage, network visualization, money flow tracing, case management, note timeline, reporting, and audit logging.
   * **35 Non-Functional Requirements (NFR01 – NFR35):** Performance ($\le 3\text{s}$), 500+ concurrency, data integrity, salted PBKDF2 password security, SQL injection protection, 99.5% availability, and backup restore capabilities.
4. **Unified Modeling Language (UML) & System Models:**
   * **Structural Modelling:** Entity Relationship Diagram (ERD) with 17 normalized entities.
   * **Functional Modelling:** Context Flow Diagram (Level 0 DFD) & Decomposed Level 1 DFD across 8 processes and 10 persistent Data Stores (`D1 User DB` to `D10 Audit Log DB`).
   * **Behavioral Modelling:** State Transition Diagrams (Authentication, Detection, Risk Assessment, Network Tracing, Case Management).
   * **Object-Oriented Design:** Use Case Diagram (43 use cases), Class Diagram (`User` hierarchy, `Transaction`, `Alert`, `Case`, `RiskScore`), Sequence & Collaboration Diagrams for the Investigation Workflow, Package Diagram (10 modular packages), Component Diagram (4-layer stack), and Deployment Diagram.

---

## 🛡️ Comprehensive Test Suite & Quality Verification Summary

This implementation achieves a **100% PASS rate across all 35 test cases (20 Functional + 15 Non-Functional)**:

| Test ID | Quality Attribute / Description | Initial Status | Remediation Implemented | Final Status |
| :--- | :--- | :---: | :--- | :---: |
| **NFT-02** | Load / Concurrent User Stability | ❌ FAIL | SQLite WAL (Write-Ahead Logging) mode + asynchronous event-driven connection pipeline | ✅ **PASS** |
| **NFT-06** | Secure Password Storage | ❌ FAIL | Replaced plaintext storage with salted PBKDF2-SHA512 one-way cryptographic hashes (100,000 rounds) | ✅ **PASS** |
| **NFT-07** | Injection Resistance | ❌ FAIL | Implemented strict SQLite parameterized prepared statements, completely neutralizing `' OR '1'='1` | ✅ **PASS** |
| **NFT-10** | Availability & Health Monitoring | ❌ FAIL | Added continuous `/api/health` heartbeat probe, self-healing supervisor, and connection pooling | ✅ **PASS** |
| **NFT-12** | Scalability with Growing Datasets | ❌ FAIL | B-Tree indexing on `txn_code`, `transaction_date`, `amount`, and account foreign keys | ✅ **PASS** |

### Complete Test Execution Matrix
* **Functional Tests (FT-01 to FT-20):** **20 / 20 PASS (100%)**
  * `FT-01` Register user with valid details $\rightarrow$ **PASS**
  * `FT-02` Reject invalid email $\rightarrow$ **PASS**
  * `FT-03` Login with valid credentials $\rightarrow$ **PASS**
  * `FT-04` Reject login with incorrect password $\rightarrow$ **PASS**
  * `FT-05` Enforce role-based access $\rightarrow$ **PASS**
  * `FT-06` Upload valid transaction dataset $\rightarrow$ **PASS**
  * `FT-07` Reject dataset missing required fields $\rightarrow$ **PASS**
  * `FT-08` Handle duplicate transaction IDs $\rightarrow$ **PASS**
  * `FT-09` Search transactions by date and amount $\rightarrow$ **PASS**
  * `FT-10` View transaction details $\rightarrow$ **PASS**
  * `FT-11` Detect suspicious transaction $\rightarrow$ **PASS**
  * `FT-12` Detect suspicious transaction pattern $\rightarrow$ **PASS**
  * `FT-13` Calculate and classify risk score $\rightarrow$ **PASS**
  * `FT-14` Display risk score explanation $\rightarrow$ **PASS**
  * `FT-15` Generate alert for high-risk activity $\rightarrow$ **PASS**
  * `FT-16` Create case from alert $\rightarrow$ **PASS**
  * `FT-17` Add notes and update case status $\rightarrow$ **PASS**
  * `FT-18` Explore network and trace money flow $\rightarrow$ **PASS**
  * `FT-19` Generate and export investigation report $\rightarrow$ **PASS**
  * `FT-20` Record activity in audit log $\rightarrow$ **PASS**

* **Non-Functional Tests (NFT-01 to NFT-15):** **15 / 15 PASS (100%)**
  * `NFT-01` Performance ($\le 3$s search) $\rightarrow$ **PASS** (avg $< 0.1$ms)
  * `NFT-02` Concurrency stability $\rightarrow$ **PASS** (0% errors under load)
  * `NFT-03` Dataset import duration $\rightarrow$ **PASS** ($< 2$ms validation)
  * `NFT-04` Unauthenticated access control $\rightarrow$ **PASS**
  * `NFT-05` Role-based restrictions $\rightarrow$ **PASS**
  * `NFT-06` Password storage security $\rightarrow$ **PASS** (Salted PBKDF2-SHA512)
  * `NFT-07` Injection resistance $\rightarrow$ **PASS** (SQL injection neutralized)
  * `NFT-08` Sensitive data privacy $\rightarrow$ **PASS**
  * `NFT-09` Consistent repeated results $\rightarrow$ **PASS**
  * `NFT-10` Service uptime & health probe $\rightarrow$ **PASS**
  * `NFT-11` Backup & restore recovery $\rightarrow$ **PASS**
  * `NFT-12` Scalability with growing data $\rightarrow$ **PASS**
  * `NFT-13` Core workflow usability $\rightarrow$ **PASS**
  * `NFT-14` Cross-browser operation $\rightarrow$ **PASS**
  * `NFT-15` Logging & secret sanitization $\rightarrow$ **PASS**

---

## 🚀 Running the Project

### Prerequisites
* **Node.js** (v22.5.0+ or v24.x recommended, which includes built-in `node:sqlite` and `node:crypto`).
* **Zero external npm dependencies required!** No `npm install` delays or internet downloads needed.

### 1. Run Automated Test Suite (System Verification)
```bash
npm test
# or
node testSuite.js
```
*Outputs full execution logs and confirms 35/35 PASSED test cases.*

### 2. Start the Interactive Web Application
```bash
npm start
# or
node server.js
```
*Open your browser and navigate to:*
```
http://localhost:3000
```

---

## 🖥️ Platform Modules in the UI
1. **Overview Dashboard:** Live KPI cards, total volume monitored, flagged transactions, and alert triage.
2. **Transaction Management:** Real-time date and amount range filters, search queries, and CSV dataset ingestion (FT-06, FT-07, FT-08, FT-09, FT-10).
3. **Fraud Detection Engine:** Toggle detection rules on/off, execute pattern detection for structuring, smurfing, circular laundering loops, and rapid passthroughs (FT-11, FT-12).
4. **Interactive Network Graph:** HTML5 Canvas node-link diagram with drag-and-drop nodes, entity categorization, and the **Money-Flow Path Tracer** (ACC-1001 to ACC-1004) (FT-18).
5. **Alerts Center:** Severity badges, explainable risk factor breakdown drawers, and one-click promotion to formal investigation cases (FT-14, FT-15, FT-16).
6. **Case Management:** Structured case dossiers, investigator assignments, status tracking, timestamped notes history (FT-16, FT-17).
7. **Investigation Reports:** Automated generation of formal Suspicious Activity Reports (SAR/STR) with print-to-PDF formatting (FT-19).
8. **Audit Trail:** Immutable activity log with automatic redaction of sensitive credentials (FT-20, NFT-15).
9. **Comprehensive Test Runner:** One-click live execution of all 35 test cases with live status badges directly in the web browser.
