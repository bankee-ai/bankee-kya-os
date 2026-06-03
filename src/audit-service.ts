#!/usr/bin/env npx tsx
/**
 * Audit Service
 *
 * Records KYA-OS proof records from the payment server and provides:
 *   - A queryable audit trail (by DID, by tool, by time range)
 *   - Offline proof verification via ProofVerifier
 *   - A live HTML dashboard
 *
 * The payment server POSTs proof records here after each tool call.
 * Records are append-only and stored in memory (replace with Postgres/
 * object storage for production — see AuditLogProvider in @kya-os/mcp).
 *
 * Routes:
 *   POST /api/records          — Ingest a proof record (from payment server)
 *   GET  /api/records          — List all records (optional ?did= filter)
 *   GET  /api/records/:id      — Retrieve a single record
 *   POST /api/verify           — Verify a detached JWS proof
 *   GET  /                     — HTML audit dashboard
 *
 * Spec: KYA-OS §5 (Proof), §12.4 (Proof Retention)
 */

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ProofVerifier,
  NodeCryptoProvider,
  MemoryNonceCacheProvider,
  SystemClockProvider,
  RuntimeFetchProvider,
  type DetachedProof,
  type AuditRecord,
} from '@kya-os/mcp';

const AUDIT_PORT = parseInt(process.env['AUDIT_SERVICE_PORT'] ?? '3003', 10);

// Append-only in-memory store
interface StoredRecord extends AuditRecord {
  id: string;
  tool: string;
  receivedAt: string;
}
const records: StoredRecord[] = [];

// One ProofVerifier instance shared across requests
const verifier = new ProofVerifier({
  cryptoProvider:    new NodeCryptoProvider(),
  clockProvider:     new SystemClockProvider(),
  nonceCacheProvider: new MemoryNonceCacheProvider(),
  fetchProvider:     new RuntimeFetchProvider(),
  timestampSkewSeconds: 300, // generous for demo purposes
});

// ── Dashboard HTML ───────────────────────────────────────────────────────────

function renderDashboard(): string {
  const rows = records.slice().reverse().map(r => `
    <tr>
      <td>${r.receivedAt.slice(0,19).replace('T',' ')}</td>
      <td><code>${r.tool}</code></td>
      <td class="did" title="${r.did}">${r.did.slice(0, 30)}…</td>
      <td>${r.session.slice(0,16)}…</td>
      <td class="${r.verified ? 'ok' : 'fail'}">${r.verified ? '✓ verified' : '✗ failed'}</td>
      <td>${r.scope !== '-' ? `<span class="badge">${r.scope}</span>` : '—'}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <meta http-equiv="refresh" content="5" />
  <title>Audit Dashboard — Bankee KYA-OS</title>
  <style>
    *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#f6f9fc; color:#0a2540; padding:2rem; }
    h1 { font-size:1.5rem; font-weight:800; letter-spacing:-0.04em; margin-bottom:0.25rem; }
    .sub { color:#425466; font-size:0.875rem; margin-bottom:2rem; }
    .stats { display:flex; gap:1.5rem; margin-bottom:2rem; flex-wrap:wrap; }
    .stat { background:white; border:1px solid #e3e8ef; border-radius:12px; padding:1rem 1.5rem; }
    .stat-n { font-size:2rem; font-weight:800; color:#635bff; letter-spacing:-0.04em; }
    .stat-l { font-size:0.75rem; color:#8898aa; margin-top:0.25rem; }
    table { width:100%; border-collapse:collapse; background:white; border:1px solid #e3e8ef; border-radius:12px; overflow:hidden; }
    th { font-size:0.7rem; font-weight:700; text-transform:uppercase; letter-spacing:0.07em; color:#8898aa; padding:0.875rem 1rem; text-align:left; background:#f6f9fc; border-bottom:1px solid #e3e8ef; }
    td { font-size:0.8125rem; padding:0.75rem 1rem; border-bottom:1px solid #f0f4f8; vertical-align:top; }
    code { font-family:monospace; font-size:0.8em; background:#f0f4f8; padding:0.1em 0.35em; border-radius:4px; }
    .did { font-family:monospace; font-size:0.75rem; color:#425466; }
    .ok   { color:#059669; font-weight:600; }
    .fail { color:#dc2626; font-weight:600; }
    .badge { font-size:0.68rem; font-weight:700; padding:0.15rem 0.5rem; border-radius:999px; background:#ede9fe; color:#635bff; }
    .empty { text-align:center; color:#8898aa; padding:3rem; font-size:0.9rem; }
    .refresh { font-size:0.75rem; color:#8898aa; margin-top:1rem; }
  </style>
</head>
<body>
  <h1>Bankee KYA-OS — Audit Dashboard</h1>
  <p class="sub">Live proof records from the payment MCP server. Auto-refreshes every 5s.</p>

  <div class="stats">
    <div class="stat"><div class="stat-n">${records.length}</div><div class="stat-l">Total records</div></div>
    <div class="stat"><div class="stat-n">${records.filter(r => r.verified).length}</div><div class="stat-l">Verified proofs</div></div>
    <div class="stat"><div class="stat-n">${new Set(records.map(r => r.did)).size}</div><div class="stat-l">Unique agent DIDs</div></div>
    <div class="stat"><div class="stat-n">${records.filter(r => r.scope !== '-').length}</div><div class="stat-l">Delegated actions</div></div>
  </div>

  <table>
    <thead><tr>
      <th>Timestamp</th><th>Tool</th><th>Agent DID</th><th>Session</th><th>Status</th><th>Scope</th>
    </tr></thead>
    <tbody>
      ${rows || '<tr><td colspan="6" class="empty">No records yet. Run the demo agent to generate proof records.</td></tr>'}
    </tbody>
  </table>
  <p class="refresh">Page auto-refreshes every 5 seconds.</p>
</body>
</html>`;
}

// ── HTTP server ──────────────────────────────────────────────────────────────

async function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

const httpServer = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url ?? '/', `http://localhost:${AUDIT_PORT}`);

  // ── POST /api/records — ingest ─────────────────────────────────────────
  if (url.pathname === '/api/records' && req.method === 'POST') {
    const body = await readBody(req);
    const record = JSON.parse(body) as StoredRecord;
    record.id = `rec_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
    record.receivedAt = new Date().toISOString();
    records.push(record);
    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: record.id }));
    return;
  }

  // ── GET /api/records — query ───────────────────────────────────────────
  if (url.pathname === '/api/records' && req.method === 'GET') {
    const did    = url.searchParams.get('did');
    const tool   = url.searchParams.get('tool');
    const limit  = parseInt(url.searchParams.get('limit') ?? '100', 10);
    let results  = records.slice();
    if (did)  results = results.filter(r => r.did  === did);
    if (tool) results = results.filter(r => r.tool === tool);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ records: results.slice(-limit), total: results.length }));
    return;
  }

  // ── GET /api/records/:id ───────────────────────────────────────────────
  if (url.pathname.startsWith('/api/records/') && req.method === 'GET') {
    const id = url.pathname.split('/').pop()!;
    const r  = records.find(rec => rec.id === id);
    if (!r) { res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' })); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(r));
    return;
  }

  // ── POST /api/verify — verify a detached proof ─────────────────────────
  if (url.pathname === '/api/verify' && req.method === 'POST') {
    try {
      const body  = await readBody(req);
      const proof = JSON.parse(body) as DetachedProof;

      const jwk = await verifier.fetchPublicKeyFromDID(proof.meta.did);
      if (!jwk) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ valid: false, error: 'could_not_resolve_did', did: proof.meta.did }));
        return;
      }

      const result = await verifier.verifyProof(proof, jwk);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        valid:     result.valid,
        did:       proof.meta.did,
        kid:       proof.meta.kid,
        timestamp: new Date((proof.meta.ts ?? 0) * 1000).toISOString(),
        session:   proof.meta.sessionId,
        ...(result.valid ? {} : { error: result.errorCode, reason: result.reason }),
      }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'invalid_proof' }));
    }
    return;
  }

  // ── Dashboard ──────────────────────────────────────────────────────────
  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderDashboard());
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  httpServer.listen(AUDIT_PORT, () => {
    process.stderr.write(`\n[audit] ─────────────────────────────────────────\n`);
    process.stderr.write(`[audit] Bankee Audit Service\n`);
    process.stderr.write(`[audit] Dashboard:  http://localhost:${AUDIT_PORT}/\n`);
    process.stderr.write(`[audit] Records:    http://localhost:${AUDIT_PORT}/api/records\n`);
    process.stderr.write(`[audit] Verify:     POST http://localhost:${AUDIT_PORT}/api/verify\n`);
    process.stderr.write(`[audit] ─────────────────────────────────────────\n\n`);
  });
}
