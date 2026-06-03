#!/usr/bin/env npx tsx
/**
 * Bankee KYA-OS Web Interface
 *
 * A unified management dashboard for the three KYA-OS services:
 *   - Payment MCP Server  (port 3001)
 *   - Consent Service     (port 3002)
 *   - Audit Service       (port 3003)
 *
 * Routes:
 *   GET  /                  — Dashboard (system health + stats)
 *   GET  /payments          — Payment history
 *   GET  /audit             — Full audit trail + proof records
 *   GET  /consent           — Consent management (pending + history)
 *   GET  /verify            — Proof verification tool
 *   GET  /identity          — Server DID + session info
 *   GET  /api/*             — Transparent proxy to underlying services
 */

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT         = parseInt(process.env['WEB_UI_PORT']          ?? '3010', 10);
const PAYMENT_URL  = process.env['PAYMENT_SERVER_URL']  ?? 'http://localhost:3001';
const CONSENT_URL  = process.env['CONSENT_SERVICE_URL'] ?? 'http://localhost:3002';
const AUDIT_URL    = process.env['AUDIT_SERVICE_URL']   ?? 'http://localhost:3003';

// ── Shared layout ────────────────────────────────────────────────────────────

function layout(title: string, active: string, body: string): string {
  const nav = [
    { href: '/',         label: 'Dashboard',  icon: '⬡' },
    { href: '/payments', label: 'Payments',   icon: '₿' },
    { href: '/audit',    label: 'Audit Trail', icon: '🔏' },
    { href: '/consent',  label: 'Consent',    icon: '✓' },
    { href: '/verify',   label: 'Verify Proof', icon: '⚑' },
    { href: '/identity', label: 'Identity',   icon: '◎' },
  ].map(n => `<a href="${n.href}" class="nav-link${active === n.href ? ' active' : ''}">${n.icon} ${n.label}</a>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>${title} — Bankee KYA-OS</title>
  <style>
    *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #21262d;
      --text: #e6edf3; --muted: #768390; --cyan: #00c4cc;
      --purple: #635bff; --green: #3fb950; --red: #f85149;
      --yellow: #d29922; --orange: #ff9900;
    }
    body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; }
    .sidebar {
      width: 220px; min-height: 100vh; background: var(--surface);
      border-right: 1px solid var(--border); padding: 1.5rem 0; flex-shrink:0;
      display:flex; flex-direction:column;
    }
    .logo { padding:0 1.25rem 1.5rem; font-size:1.125rem; font-weight:800; letter-spacing:-0.04em; color:var(--text); border-bottom:1px solid var(--border); margin-bottom:1rem; }
    .logo span { color: var(--cyan); }
    .nav-link {
      display:block; padding:0.6rem 1.25rem; color:var(--muted); text-decoration:none;
      font-size:0.8375rem; font-weight:500; border-left:3px solid transparent;
      transition: color 0.1s, background 0.1s;
    }
    .nav-link:hover { color:var(--text); background: rgba(255,255,255,0.04); }
    .nav-link.active { color:var(--text); background: rgba(99,91,255,0.12); border-left-color: var(--purple); font-weight:600; }
    .sidebar-footer { margin-top:auto; padding:1rem 1.25rem; font-size:0.72rem; color:var(--muted); border-top:1px solid var(--border); }
    .main { flex:1; padding:2rem; overflow:auto; }
    h1 { font-size:1.375rem; font-weight:800; letter-spacing:-0.04em; margin-bottom:0.25rem; }
    .page-sub { color:var(--muted); font-size:0.8375rem; margin-bottom:2rem; }
    .grid { display:grid; grid-template-columns: repeat(auto-fill,minmax(180px,1fr)); gap:1rem; margin-bottom:2rem; }
    .stat { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:1rem 1.25rem; }
    .stat-n { font-size:1.75rem; font-weight:800; letter-spacing:-0.04em; }
    .stat-n.cyan   { color:var(--cyan); }
    .stat-n.purple { color:var(--purple); }
    .stat-n.green  { color:var(--green); }
    .stat-n.orange { color:var(--orange); }
    .stat-l { font-size:0.72rem; color:var(--muted); margin-top:0.25rem; text-transform:uppercase; letter-spacing:0.06em; }
    .card { background:var(--surface); border:1px solid var(--border); border-radius:10px; overflow:hidden; margin-bottom:1.5rem; }
    .card-head { padding:0.875rem 1.25rem; border-bottom:1px solid var(--border); font-size:0.8125rem; font-weight:700; display:flex; align-items:center; justify-content:space-between; }
    .card-head .count { font-size:0.72rem; color:var(--muted); font-weight:500; }
    table { width:100%; border-collapse:collapse; font-size:0.8rem; }
    th { padding:0.625rem 1rem; text-align:left; font-size:0.68rem; font-weight:700; text-transform:uppercase; letter-spacing:0.07em; color:var(--muted); border-bottom:1px solid var(--border); background: rgba(255,255,255,0.02); }
    td { padding:0.625rem 1rem; border-bottom:1px solid var(--border); vertical-align:top; }
    tr:last-child td { border-bottom:none; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    code { font-family:'SF Mono','Fira Code',monospace; font-size:0.78em; background:rgba(255,255,255,0.08); padding:0.15em 0.4em; border-radius:4px; }
    .did { font-family:monospace; font-size:0.72rem; color:var(--muted); }
    .badge { display:inline-block; font-size:0.65rem; font-weight:700; padding:0.15rem 0.5rem; border-radius:999px; }
    .badge.green  { background:rgba(63,185,80,0.15); color:var(--green); }
    .badge.purple { background:rgba(99,91,255,0.15); color:var(--purple); }
    .badge.red    { background:rgba(248,81,73,0.15);  color:var(--red); }
    .badge.yellow { background:rgba(210,153,34,0.15); color:var(--yellow); }
    .badge.orange { background:rgba(255,153,0,0.15);  color:var(--orange); }
    .badge.cyan   { background:rgba(0,196,204,0.15);  color:var(--cyan); }
    .health { display:flex; gap:0.5rem; align-items:center; font-size:0.8rem; }
    .dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
    .dot.up   { background:var(--green); box-shadow:0 0 6px var(--green); }
    .dot.down { background:var(--red); }
    .empty { text-align:center; color:var(--muted); padding:3rem; font-size:0.875rem; }
    textarea { width:100%; background:var(--bg); border:1px solid var(--border); color:var(--text); border-radius:8px; padding:1rem; font-family:monospace; font-size:0.8rem; line-height:1.6; resize:vertical; outline:none; }
    textarea:focus { border-color:var(--purple); }
    .btn { display:inline-flex; align-items:center; gap:0.4rem; padding:0.6rem 1.25rem; border-radius:8px; font-size:0.875rem; font-weight:600; cursor:pointer; border:none; }
    .btn-primary { background:var(--purple); color:white; }
    .btn-primary:hover { opacity:0.9; }
    #verify-result { margin-top:1rem; padding:1rem; border-radius:8px; display:none; font-size:0.875rem; line-height:1.7; }
    .result-valid   { background:rgba(63,185,80,0.1); border:1px solid rgba(63,185,80,0.3); color:var(--green); }
    .result-invalid { background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.3); color:var(--red); }
    .service-row { display:flex; align-items:center; justify-content:space-between; padding:0.875rem 1.25rem; border-bottom:1px solid var(--border); }
    .service-row:last-child { border-bottom:none; }
    @media (max-width:768px) { .sidebar { display:none; } }
  </style>
</head>
<body>
<nav class="sidebar">
  <div class="logo">Bankee<span>.</span>ai</div>
  ${nav}
  <div class="sidebar-footer">KYA-OS Infrastructure<br>DIF TAAWG · v1.6.0</div>
</nav>
<main class="main">
  ${body}
</main>
</body>
</html>`;
}

// ── API helpers ──────────────────────────────────────────────────────────────

async function fetchJSON<T>(url: string): Promise<T | null> {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) return null;
    return await r.json() as T;
  } catch { return null; }
}

// ── Dashboard page ───────────────────────────────────────────────────────────

async function renderDashboard(): Promise<string> {
  const [payInfo, conInfo, audInfo, audRecords] = await Promise.all([
    fetchJSON<Record<string,unknown>>(`${PAYMENT_URL}/`),
    fetchJSON<Record<string,unknown>>(`${CONSENT_URL}/`),
    fetchJSON<Record<string,unknown>>(`${AUDIT_URL}/`),
    fetchJSON<{records: unknown[]; total: number}>(`${AUDIT_URL}/api/records?limit=5`),
  ]);

  const payUp  = !!payInfo;
  const conUp  = !!conInfo;
  const audUp  = !!audInfo;
  const records = audRecords?.records as Array<Record<string,unknown>> ?? [];
  const total   = audRecords?.total ?? 0;

  const services = [
    { name: 'Payment MCP Server', port: 3001, up: payUp, did: payInfo?.['did'] as string, detail: `${payInfo?.['transports'] ? 'SSE + Streamable HTTP' : '—'}` },
    { name: 'Consent Service',    port: 3002, up: conUp, did: conInfo?.['issuerDid'] as string, detail: `${conInfo?.['credentialsIssued'] ?? 0} VCs issued` },
    { name: 'Audit Service',      port: 3003, up: audUp, did: undefined, detail: `${total} records` },
  ];

  const serviceRows = services.map(s => `
    <div class="service-row">
      <div class="health">
        <div class="dot ${s.up ? 'up' : 'down'}"></div>
        <div>
          <div style="font-size:0.875rem;font-weight:600">${s.name}</div>
          <div class="did">${s.did ? s.did.slice(0,50) + '…' : '—'}</div>
        </div>
      </div>
      <div style="text-align:right">
        <span class="badge ${s.up ? 'green' : 'red'}">${s.up ? 'online' : 'offline'}</span>
        <div style="font-size:0.72rem;color:var(--muted);margin-top:0.25rem">${s.detail}</div>
      </div>
    </div>`).join('');

  const recentRows = records.slice(0,5).map((r: Record<string,unknown>) => `
    <tr>
      <td>${String(r['receivedAt'] ?? '').slice(0,19).replace('T',' ')}</td>
      <td><code>${r['tool'] ?? '—'}</code></td>
      <td class="did">${String(r['did'] ?? '').slice(0,32)}…</td>
      <td><span class="badge ${r['verified'] ? 'green' : 'red'}">${r['verified'] ? 'valid' : 'invalid'}</span></td>
    </tr>`).join('') || `<tr><td colspan="4" class="empty">No records yet.</td></tr>`;

  return layout('Dashboard', '/', `
    <h1>KYA-OS Dashboard</h1>
    <p class="page-sub">End-to-end agentic payment infrastructure — identity, delegation, proof</p>

    <div class="grid">
      <div class="stat"><div class="stat-n cyan">${services.filter(s=>s.up).length}/3</div><div class="stat-l">Services online</div></div>
      <div class="stat"><div class="stat-n purple">${total}</div><div class="stat-l">Proof records</div></div>
      <div class="stat"><div class="stat-n green">${conInfo?.['credentialsIssued'] ?? 0}</div><div class="stat-l">VCs issued</div></div>
      <div class="stat"><div class="stat-n orange">${payInfo ? String(payInfo['highValueThreshold']) : '—'}</div><div class="stat-l">Threshold (minor units)</div></div>
    </div>

    <div class="card">
      <div class="card-head">Service Health</div>
      ${serviceRows}
    </div>

    <div class="card">
      <div class="card-head">Recent Proof Records <span class="count"><a href="/audit" style="color:var(--purple);text-decoration:none">view all →</a></span></div>
      <table><thead><tr><th>Time</th><th>Tool</th><th>Agent DID</th><th>Status</th></tr></thead>
      <tbody>${recentRows}</tbody></table>
    </div>`);
}

// ── Payments page ────────────────────────────────────────────────────────────

async function renderPayments(): Promise<string> {
  const data = await fetchJSON<{payments: unknown[]; total: number}>(`${PAYMENT_URL}/api/audit`);
  const payments = (data?.records as Array<Record<string,unknown>> ?? []).filter((r: Record<string,unknown>) => r['tool'] === 'create_payment');

  const rows = payments.length ? payments.map(p => `
    <tr>
      <td>${String(p['ts'] ? new Date((p['ts'] as number)).toISOString() : p['receivedAt'] ?? '').slice(0,19).replace('T',' ')}</td>
      <td><span class="badge green">completed</span></td>
      <td class="did">${String(p['did'] ?? '').slice(0,32)}…</td>
      <td>${p['scope'] !== '-' ? `<span class="badge purple">${p['scope']}</span>` : '<span class="badge cyan">autonomous</span>'}</td>
      <td class="did">${String(p['session'] ?? '').slice(0,16)}…</td>
    </tr>`).join('') : `<tr><td colspan="5" class="empty">No payments yet — run the demo agent.</td></tr>`;

  return layout('Payments', '/payments', `
    <h1>Payment History</h1>
    <p class="page-sub">All create_payment tool calls with proof records</p>
    <div class="card">
      <div class="card-head">Payments <span class="count">${payments.length} records</span></div>
      <table><thead><tr><th>Time</th><th>Status</th><th>Agent DID</th><th>Auth</th><th>Session</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>`);
}

// ── Audit trail page ─────────────────────────────────────────────────────────

async function renderAudit(): Promise<string> {
  const data = await fetchJSON<{records: unknown[]; total: number}>(`${AUDIT_URL}/api/records`);
  const records = data?.records as Array<Record<string,unknown>> ?? [];

  const rows = records.length ? records.slice().reverse().map(r => `
    <tr>
      <td>${String(r['receivedAt'] ?? '').slice(0,19).replace('T',' ')}</td>
      <td><code>${r['tool'] ?? '—'}</code></td>
      <td class="did" title="${r['did']}">${String(r['did'] ?? '').slice(0,32)}…</td>
      <td class="did">${String(r['session'] ?? '').slice(0,16)}…</td>
      <td><span class="badge ${r['verified'] ? 'green' : 'red'}">${r['verified'] ? '✓ valid' : '✗ invalid'}</span></td>
      <td>${r['scope'] && r['scope'] !== '-' ? `<span class="badge purple">${r['scope']}</span>` : '—'}</td>
    </tr>`).join('') : `<tr><td colspan="6" class="empty">No records yet.</td></tr>`;

  return layout('Audit Trail', '/audit', `
    <h1>Audit Trail</h1>
    <p class="page-sub">Immutable proof records — every tool call, every agent, every session</p>
    <div class="card">
      <div class="card-head">Proof Records <span class="count">${data?.total ?? 0} total</span></div>
      <table><thead><tr><th>Time</th><th>Tool</th><th>Agent DID</th><th>Session</th><th>Proof</th><th>Scope</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>`);
}

// ── Consent page ─────────────────────────────────────────────────────────────

async function renderConsent(): Promise<string> {
  const conInfo = await fetchJSON<Record<string,unknown>>(`${CONSENT_URL}/`);
  const issued  = (conInfo?.['credentialsIssued'] as number) ?? 0;

  return layout('Consent', '/consent', `
    <h1>Consent Management</h1>
    <p class="page-sub">Human-in-the-loop authorization for high-value payment requests</p>

    <div class="grid">
      <div class="stat"><div class="stat-n green">${issued}</div><div class="stat-l">VCs issued</div></div>
      <div class="stat"><div class="stat-n cyan">${conInfo ? '●' : '○'}</div><div class="stat-l">Consent service ${conInfo ? 'online' : 'offline'}</div></div>
    </div>

    <div class="card">
      <div class="card-head">Issuer Identity</div>
      <div class="service-row">
        <div>
          <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.25rem">Responsible Party DID</div>
          <code class="did">${conInfo?.['issuerDid'] ?? '—'}</code>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">Consent Approval Flow</div>
      <div style="padding:1.25rem;font-size:0.875rem;color:var(--muted);line-height:1.8">
        <p>When an agent calls <code>create_payment</code> above the high-value threshold:</p>
        <ol style="margin:1rem 0 0 1.5rem">
          <li>Payment server returns <code>needs_authorization</code> with a consent URL</li>
          <li>The consent URL includes: <code>tool</code>, <code>scopes</code>, <code>agent_did</code>, <code>resume_token</code></li>
          <li>Human reviews and approves at the consent page below</li>
          <li>Consent service issues a W3C Delegation VC signed with the Responsible Party key</li>
          <li>VC is stored on the payment server under the <code>resume_token</code></li>
          <li>Agent retries — delegation auto-applied — payment executes with proof</li>
        </ol>
        <div style="margin-top:1.5rem">
          <a href="${CONSENT_URL}/consent?tool=create_payment&scopes=payments%3Awrite&agent_did=did%3Akey%3Ademo&resume_token=demo-${Date.now()}"
             target="_blank"
             style="display:inline-flex;align-items:center;gap:0.5rem;background:var(--purple);color:white;padding:0.6rem 1.25rem;border-radius:8px;text-decoration:none;font-size:0.875rem;font-weight:600;">
            Open Consent UI ↗
          </a>
        </div>
      </div>
    </div>`);
}

// ── Verify page ──────────────────────────────────────────────────────────────

function renderVerify(): string {
  return layout('Verify Proof', '/verify', `
    <h1>Proof Verification</h1>
    <p class="page-sub">Paste a KYA-OS detached JWS proof to verify the signature chain</p>

    <div class="card">
      <div class="card-head">Detached Proof Verifier</div>
      <div style="padding:1.25rem">
        <p style="font-size:0.8125rem;color:var(--muted);margin-bottom:0.875rem">
          Paste the <code>_meta.proof</code> JSON object from any tool response.
          The verifier resolves the signer's DID, checks the Ed25519 signature, validates
          nonce freshness, and confirms the timestamp.
        </p>
        <textarea id="proof-input" rows="10" placeholder='{"jws":"eyJ...","meta":{"did":"did:key:...","kid":"...","ts":...,"nonce":"...","requestHash":"...","responseHash":"..."}}'></textarea>
        <div style="margin-top:0.875rem">
          <button class="btn btn-primary" onclick="verifyProof()">Verify Proof</button>
        </div>
        <div id="verify-result"></div>
      </div>
    </div>

    <script>
    async function verifyProof() {
      const input = document.getElementById('proof-input').value.trim();
      const result = document.getElementById('verify-result');
      result.style.display = 'none';
      if (!input) { alert('Paste a proof JSON first.'); return; }

      let proof;
      try { proof = JSON.parse(input); } catch { alert('Invalid JSON.'); return; }

      result.style.display = 'block';
      result.className = '';
      result.textContent = 'Verifying…';

      try {
        const resp = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(proof),
        });
        const data = await resp.json();
        if (data.valid) {
          result.className = 'result-valid';
          result.innerHTML = '<strong>✓ Proof Valid</strong><br>' +
            'DID: ' + data.did + '<br>' +
            'Signed at: ' + data.timestamp + '<br>' +
            'Session: ' + (data.session || '—');
        } else {
          result.className = 'result-invalid';
          result.innerHTML = '<strong>✗ Proof Invalid</strong><br>' +
            'Error: ' + (data.error || '—') + '<br>' +
            'Reason: ' + (data.reason || '—');
        }
      } catch (e) {
        result.className = 'result-invalid';
        result.textContent = '✗ Request failed: ' + e.message;
      }
    }
    </script>`);
}

// ── Identity page ────────────────────────────────────────────────────────────

async function renderIdentity(): Promise<string> {
  const [payInfo, conInfo] = await Promise.all([
    fetchJSON<Record<string,unknown>>(`${PAYMENT_URL}/`),
    fetchJSON<Record<string,unknown>>(`${CONSENT_URL}/`),
  ]);

  const identities = [
    { label: 'Payment Server (Proof Signer)', did: payInfo?.['did'] as string, role: 'Signs every tool response proof (§5)', color: 'cyan' as const },
    { label: 'Consent Service (Responsible Party)', did: conInfo?.['issuerDid'] as string, role: 'Signs delegation VCs — root of trust (§4)', color: 'purple' as const },
  ];

  const rows = identities.map(id => `
    <div class="service-row">
      <div>
        <div style="font-size:0.875rem;font-weight:600;margin-bottom:0.375rem">${id.label}</div>
        <code class="did" style="font-size:0.78rem">${id.did ?? '(service offline)'}</code>
        <div style="font-size:0.72rem;color:var(--muted);margin-top:0.25rem">${id.role}</div>
      </div>
      <span class="badge ${id.color}">${id.did?.startsWith('did:key:') ? 'did:key' : id.did?.startsWith('did:web:') ? 'did:web' : '—'}</span>
    </div>`).join('');

  return layout('Identity', '/identity', `
    <h1>Agent Identity</h1>
    <p class="page-sub">DID documents and key material for all KYA-OS participants</p>

    <div class="card">
      <div class="card-head">Service DIDs</div>
      ${rows}
    </div>

    <div class="card">
      <div class="card-head">DID Method Guidance</div>
      <div style="padding:1.25rem;font-size:0.8125rem;color:var(--muted);line-height:1.8">
        <p><strong style="color:var(--text)">did:key</strong> — Self-certifying, ephemeral. Generated from an Ed25519 key pair on startup.
        No external resolution required. Suitable for development and single-machine deployments.</p>
        <p style="margin-top:0.75rem"><strong style="color:var(--text)">did:web</strong> — Persistent, organisation-hosted. Resolves to a DID document
        at <code>https://&lt;domain&gt;/.well-known/did.json</code>. Required for production deployments where
        delegation VCs need to be verified by external parties.</p>
        <p style="margin-top:0.75rem">To persist a did:key across restarts, run: <code>npm run generate-identity</code></p>
        <p style="margin-top:0.5rem">To use did:web, publish a DID document at your domain and set <code>IDENTITY_PATH</code>.</p>
      </div>
    </div>`);
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

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');

  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

  // ── Proxy: /api/verify → audit service ───────────────────────────────
  if (url.pathname === '/api/verify' && req.method === 'POST') {
    const body = await readBody(req);
    try {
      const upstream = await fetch(`${AUDIT_URL}/api/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const data = await upstream.json() as unknown;
      res.writeHead(upstream.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch (err) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'audit_service_unavailable' }));
    }
    return;
  }

  // ── Pages ─────────────────────────────────────────────────────────────
  let html: string;
  if (url.pathname === '/') {
    html = await renderDashboard();
  } else if (url.pathname === '/payments') {
    html = await renderPayments();
  } else if (url.pathname === '/audit') {
    html = await renderAudit();
  } else if (url.pathname === '/consent') {
    html = await renderConsent();
  } else if (url.pathname === '/verify') {
    html = renderVerify();
  } else if (url.pathname === '/identity') {
    html = await renderIdentity();
  } else {
    res.writeHead(302, { Location: '/' });
    res.end();
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
});

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  server.listen(PORT, () => {
    process.stderr.write(`\n[web-ui] ─────────────────────────────────────────\n`);
    process.stderr.write(`[web-ui] Bankee KYA-OS Web Interface\n`);
    process.stderr.write(`[web-ui] Open: http://localhost:${PORT}\n`);
    process.stderr.write(`[web-ui] ─────────────────────────────────────────\n\n`);
  });
}
