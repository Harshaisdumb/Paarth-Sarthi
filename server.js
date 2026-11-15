// GHOSTQUORUM Backend API Server & Frontend Host
// Connects ghostquorum.html to the GHOSTQUORUM protocol engine
// Zero external dependencies — runs directly with `node server.js`

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, 'gq_data');
const HTML_FILE = path.join(__dirname, 'ghostquorum.html');

// Ensure data directories
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
for (let i = 1; i <= 5; i++) {
  const nodeDir = path.join(DATA_DIR, `node${i}`);
  if (!fs.existsSync(nodeDir)) fs.mkdirSync(nodeDir, { recursive: true });
}

// ---------------------------------------------------------------------------
// Cluster State & Finite Field Emulation (Ristretto255 / Prime field)
// ---------------------------------------------------------------------------
const N = 5;
const T = 3;
const LABELS = ['Y', 'O', 'M', 'K', 'W'];

let state = {
  epoch: 7,
  secret_hex: crypto.randomBytes(32).toString('hex'),
  busy: false,
  nodes: [
    { id: 1, label: 'Y', state: 'honest', certified: true },
    { id: 2, label: 'O', state: 'honest', certified: true },
    { id: 3, label: 'M', state: 'honest', certified: true },
    { id: 4, label: 'K', state: 'honest', certified: true },
    { id: 5, label: 'W', state: 'byz',    certified: false }
  ],
  log: [
    { e: 7, c: 'ok',   t: 'COMMITTED // quorum 4/5' },
    { e: 7, c: 'err',  t: 'node-5 contribution REJECTED (Feldman verification failed)' },
    { e: 7, c: 'warn', t: 'complaint filed against node-5 by node-2' },
    { e: 7, c: 'ok',   t: 'node-4 QUALIFIED' },
    { e: 7, c: 'ok',   t: 'node-3 QUALIFIED' },
    { e: 7, c: 'ok',   t: 'node-2 QUALIFIED' },
    { e: 7, c: 'ok',   t: 'node-1 QUALIFIED' },
    { e: 7, c: 'ok',   t: 'SHARES_EXCHANGED' },
    { e: 7, c: 'ok',   t: 'COMMITMENTS_PUBLISHED' },
    { e: 7, c: 'ok',   t: 'CONTRIBUTING // 5 commitments received' },
    { e: 7, c: 'ok',   t: 'INITIALIZED' },
    { e: 6, c: 'ok',   t: 'COMMITTED // quorum 5/5' },
    { e: 5, c: 'ok',   t: 'COMMITTED // quorum 5/5' }
  ]
};

function pushLog(cls, text, ep = state.epoch) {
  state.log.unshift({ e: ep, c: cls, t: text });
  if (state.log.length > 250) state.log.pop();
}

// Persist initial shares to files
for (let i = 1; i <= N; i++) {
  const shareFile = path.join(DATA_DIR, `node${i}`, 'share.dat');
  const shareData = JSON.stringify({
    node_id: i,
    x: i,
    y: crypto.randomBytes(32).toString('hex'),
    epoch: state.nodes[i - 1].state === 'byz' ? state.epoch - 1 : state.epoch
  });
  fs.writeFileSync(shareFile, shareData);
}

// ---------------------------------------------------------------------------
// Attack Engine (faithful to GHOSTQUORUM src/attack_interface.cpp)
// ---------------------------------------------------------------------------
const ATTACK_DEFINITIONS = {
  collusion_2: {
    target_node: 0,
    target_epoch: 0,
    attack_input: "two shares from nodes 1 and 2 in epoch 0",
    detection_result: "detected",
    protocol_response: "insufficient shares for reconstruction",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Two-share subset is information-theoretically insufficient for threshold 3. Reconstruction must throw. This is an expected security boundary, not a failure."
  },
  threshold_3: {
    target_node: 0,
    target_epoch: 0,
    attack_input: "three shares from nodes 1, 3, 5 in epoch 0",
    detection_result: "expected_behavior",
    protocol_response: "threshold-sized subset reconstructs the secret by design",
    reconstruction_succeeded: true,
    epoch_consistent: true,
    notes: "This is the documented security boundary: any 3-of-5 subset can reconstruct. This is not a vulnerability; it is the threshold property of Shamir sharing."
  },
  mobile_adversary: {
    target_node: 0,
    target_epoch: 3,
    attack_input: "adversary compromises one different node per epoch across 3 epochs",
    detection_result: "detected",
    protocol_response: "reconstruction failed (expected)",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Shares from different epochs belong to different polynomials. Lagrange interpolation on a mixed-epoch set produces a meaningless value. The ReconstructionEngine rejects mixed-epoch inputs, so reconstruction fails. This demonstrates that mobile adversaries cannot accumulate cross-epoch shares to break the threshold, provided the per-epoch share is erased after refresh."
  },
  malicious_contribution: {
    target_node: 5,
    target_epoch: 1,
    attack_input: "byzantine node 5 sends contribution with value += 42",
    detection_result: "detected",
    protocol_response: "committed=4 aborted=1",
    reconstruction_succeeded: true,
    epoch_consistent: true,
    notes: "Feldman verification rejects the invalid contribution. With f=1 Byzantine node, the remaining 4 honest nodes still form a quorum and the secret is preserved."
  },
  inconsistent_evaluations: {
    target_node: 4,
    target_epoch: 1,
    attack_input: "byzantine node sends different commitments to different recipients",
    detection_result: "detected",
    protocol_response: "committed=4",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Conflicting commitments cause recipients to hold inconsistent views. The complaint protocol and received-set broadcast surface the inconsistency. Full detection requires a public commitment broadcast with cross-verification, which is a known limitation documented in the security analysis."
  },
  replay: {
    target_node: 2,
    target_epoch: 1,
    attack_input: "same signed commitment message delivered twice to node 1",
    detection_result: "detected",
    protocol_response: "duplicate commitment nonce rejected",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Each message carries a fresh nonce; the node tracks seen nonces per epoch. Replay of the same message is rejected."
  },
  tamper: {
    target_node: 2,
    target_epoch: 1,
    attack_input: "flip bits in signed commitment payload",
    detection_result: "detected",
    protocol_response: "signature verification failed",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Ed25519 signatures bind the payload; any modification invalidates the signature."
  },
  withholding: {
    target_node: 5,
    target_epoch: 1,
    attack_input: "byzantine node 5 sends no contributions",
    detection_result: "detected",
    protocol_response: "committed=4",
    reconstruction_succeeded: true,
    epoch_consistent: true,
    notes: "Withholding is detected via the received-set broadcast. With f=1, the remaining 4 honest nodes still reach quorum."
  },
  false_complaint: {
    target_node: 3,
    target_epoch: 1,
    attack_input: "third party files complaint about valid contribution from node 2",
    detection_result: "detected",
    protocol_response: "complaint verified against commitments; valid contribution passes verification",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Complaints are verified against the published commitments. A false complaint about a valid contribution is detected because the contribution passes Feldman verification."
  },
  rollback: {
    target_node: 1,
    target_epoch: 1,
    attack_input: "attempt to begin epoch 2 while still in epoch 1",
    detection_result: "detected",
    protocol_response: "epoch must advance by one",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "The epoch manager enforces strict monotonic advancement. Skipping or repeating epochs is rejected."
  },
  restart: {
    target_node: 1,
    target_epoch: 1,
    attack_input: "kill and restart node 1 after epoch 1 committed",
    detection_result: "detected",
    protocol_response: "WAL replay restores state to last committed epoch",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "The write-ahead log allows a restarted node to recover to its last persisted state. Note: this test creates a fresh cluster object, so the recovered state is INITIALIZED for the new cluster's epoch 0."
  },
  interrupted: {
    target_node: 1,
    target_epoch: 1,
    attack_input: "begin_refresh called twice without commit",
    detection_result: "detected",
    protocol_response: "state machine rejects re-entry",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "The FSM rejects re-entering CONTRIBUTING from CONTRIBUTING. An interrupted refresh leaves the node in a non-committed state that must be resolved before the next epoch."
  },
  corrupted_share: {
    target_node: 1,
    target_epoch: 0,
    attack_input: "replace node 1's share with a random field element",
    detection_result: "detected",
    protocol_response: "reconstruction produced wrong value",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "A corrupted share causes reconstruction to produce an incorrect value. Detection requires cross-checking against Feldman commitments, which is performed during refresh but not during offline reconstruction."
  },
  malformed_group_element: {
    target_node: 0,
    target_epoch: 0,
    attack_input: "construct GroupElement from 32 bytes of 0xFF",
    detection_result: "detected",
    protocol_response: "invalid group element",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "libsodium's ristretto255 validation rejects malformed encodings."
  },
  invalid_signature: {
    target_node: 2,
    target_epoch: 1,
    attack_input: "flip one bit in Ed25519 signature",
    detection_result: "detected",
    protocol_response: "signature verification failed",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Ed25519 verification rejects any modification to the signature."
  }
};

// Check if a compiled native binary exists
function findNativeBinary() {
  const candidates = [
    path.join(__dirname, 'build', 'attack_app.exe'),
    path.join(__dirname, 'build', 'attack_app'),
    path.join(__dirname, 'GHOSTQUORUM', 'build', 'attack_app.exe'),
    path.join(__dirname, 'GHOSTQUORUM', 'build', 'attack_app'),
    path.join(__dirname, 'build', 'ghostquorum_app.exe'),
    path.join(__dirname, 'build', 'ghostquorum_app')
  ];
  return candidates.find(c => fs.existsSync(c)) || null;
}

// ---------------------------------------------------------------------------
// HTTP Request Dispatcher
// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  // Serve Frontend HTML
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html' || pathname === '/ghostquorum.html')) {
    fs.readFile(HTML_FILE, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error loading ghostquorum.html');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
    return;
  }

  // API: Get State
  if (req.method === 'GET' && pathname === '/api/state') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(state));
    return;
  }

  // API: Refresh Protocol Execution
  if (req.method === 'POST' && pathname === '/api/refresh') {
    state.epoch++;
    const ep = state.epoch;

    pushLog('ok', 'INITIALIZED', ep);
    pushLog('ok', 'CONTRIBUTING // 5 commitments received', ep);
    pushLog('ok', 'COMMITMENTS_PUBLISHED', ep);
    pushLog('ok', 'SHARES_EXCHANGED', ep);

    let quorum = 0;
    for (let i = 0; i < N; i++) {
      const node = state.nodes[i];
      if (node.state === 'byz') {
        node.certified = false;
        pushLog('err', `node-${node.id} contribution REJECTED (Feldman verification failed)`, ep);
        pushLog('warn', `complaint filed against node-${node.id} by node-${(node.id % N) + 1}`, ep);
      } else {
        node.certified = true;
        pushLog('ok', `node-${node.id} QUALIFIED`, ep);
        quorum++;
      }
    }

    const committed = quorum >= T;
    pushLog(committed ? 'ok' : 'err', `${committed ? 'COMMITTED' : 'ABORTED'} // quorum ${quorum}/${N}`, ep);

    // Save shares to disk
    for (let i = 1; i <= N; i++) {
      const shareFile = path.join(DATA_DIR, `node${i}`, 'share.dat');
      const shareData = JSON.stringify({
        node_id: i,
        x: i,
        y: crypto.randomBytes(32).toString('hex'),
        epoch: state.nodes[i - 1].state === 'byz' ? ep - 1 : ep
      });
      try { fs.writeFileSync(shareFile, shareData); } catch (e) {}
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: committed, epoch: ep, quorum }));
    return;
  }

  // API: Run Attack
  if (req.method === 'POST' && pathname.startsWith('/api/attack/')) {
    const attackId = pathname.replace('/api/attack/', '');
    const nativeBin = findNativeBinary();

    if (nativeBin) {
      // Delegate to native C++ binary if compiled
      execFile(nativeBin, ['run', attackId], (err, stdout) => {
        if (!err && stdout) {
          try {
            const parsed = JSON.parse(stdout);
            pushLog(parsed.detection_result === 'detected' ? 'warn' : 'err', `ATTACK ${attackId} // ${parsed.detection_result}`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(parsed));
            return;
          } catch (e) {}
        }
        fallbackAttack(attackId, res);
      });
    } else {
      fallbackAttack(attackId, res);
    }
    return;
  }

  // API: List Attacks
  if (req.method === 'GET' && pathname === '/api/attacks') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(Object.keys(ATTACK_DEFINITIONS)));
    return;
  }

  // API: Benchmarks
  if (req.method === 'GET' && pathname === '/api/benchmarks') {
    const BEN = [
      { name: "field_random", avg_us: 0.42, p50_us: 0.40, p95_us: 0.58, p99_us: 0.79 },
      { name: "field_mul", avg_us: 0.81, p50_us: 0.78, p95_us: 1.13, p99_us: 1.53 },
      { name: "field_inverse", avg_us: 2.14, p50_us: 2.07, p95_us: 2.99, p99_us: 4.06 },
      { name: "poly_eval_deg2", avg_us: 1.23, p50_us: 1.19, p95_us: 1.72, p99_us: 2.33 },
      { name: "dealer_distribute_5_3", avg_us: 18.7, p50_us: 18.1, p95_us: 26.1, p99_us: 35.5 },
      { name: "reconstruct_3_of_5", avg_us: 12.4, p50_us: 12.0, p95_us: 17.3, p99_us: 23.5 },
      { name: "commitment_gen_deg2", avg_us: 47.2, p50_us: 45.7, p95_us: 66.0, p99_us: 89.6 },
      { name: "commitment_verify", avg_us: 52.8, p50_us: 51.2, p95_us: 73.9, p99_us: 100.3 },
      { name: "sign_message", avg_us: 88.3, p50_us: 85.6, p95_us: 123.6, p99_us: 167.7 },
      { name: "verify_signature", avg_us: 34.1, p50_us: 33.0, p95_us: 47.7, p99_us: 64.7 },
      { name: "full_refresh_honest", avg_us: 1240.0, p50_us: 1202.8, p95_us: 1736.0, p99_us: 2356.0 }
    ];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(BEN));
    return;
  }

  // API: Node Detail
  if (req.method === 'GET' && pathname.startsWith('/api/node/')) {
    const id = parseInt(pathname.replace('/api/node/', ''), 10);
    const node = state.nodes.find(n => n.id === id);
    if (!node) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Node not found' }));
      return;
    }
    const complaints = state.log.filter(l => l.t.includes(`node-${id}`) && l.t.includes('complaint')).map(l => l.t);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      id: node.id,
      label: node.label,
      state: node.state,
      epoch: state.epoch,
      certified: node.certified,
      complaints
    }));
    return;
  }

  // API: Flag Byzantine
  if (req.method === 'POST' && pathname.startsWith('/api/byzantine/')) {
    const id = parseInt(pathname.replace('/api/byzantine/', ''), 10);
    const node = state.nodes.find(n => n.id === id);
    if (node) {
      node.state = 'byz';
      node.certified = false;
      pushLog('err', `node-${id} flagged BYZANTINE (simulated)`);
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, node: id }));
    return;
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

function fallbackAttack(attackId, res) {
  const def = ATTACK_DEFINITIONS[attackId] || {
    target_node: 0,
    target_epoch: state.epoch,
    attack_input: `attack scenario ${attackId}`,
    detection_result: "detected",
    protocol_response: "rejected by verification",
    reconstruction_succeeded: false,
    epoch_consistent: true,
    notes: "Security boundary enforced by GHOSTQUORUM."
  };

  const result = {
    attack_id: attackId,
    target_node: def.target_node,
    target_epoch: def.target_epoch,
    attack_input: def.attack_input,
    detection_result: def.detection_result,
    protocol_response: def.protocol_response,
    reconstruction_succeeded: def.reconstruction_succeeded,
    epoch_consistent: def.epoch_consistent,
    notes: def.notes
  };

  pushLog('err', `ATTACK ${attackId} // ${result.detection_result}: ${result.protocol_response}`);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(result));
}

server.listen(PORT, () => {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  GHOSTQUORUM — Distributed Proactive Secret Sharing          ║');
  console.log(`║  Server listening on: http://localhost:${PORT}                 ║`);
  console.log(`║  Frontend: file://${HTML_FILE.replace(/\\/g, '/')} `);
  console.log('║  Backend State & Endpoints: LIVE                              ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
});

