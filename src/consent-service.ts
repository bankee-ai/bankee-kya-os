#!/usr/bin/env npx tsx
/**
 * Consent & Credential Service
 *
 * Handles the human-in-the-loop authorization flow for high-value payments.
 *
 * Flow:
 *   1. Payment server generates a consent URL with resume_token, tool, scopes, agent_did
 *   2. Agent presents the URL to the human operator
 *   3. Human visits /consent, reviews the payment request, clicks Approve
 *   4. This service issues a W3C Delegation Credential (VC) signed with the
 *      Responsible Party's Ed25519 key
 *   5. The VC is stored on the payment server via POST /api/delegations/:resume_token
 *   6. On the next tool call the payment server auto-applies the VC
 *
 * Routes:
 *   GET  /consent              — Human-readable approval page
 *   POST /api/approve          — Issue VC + notify payment server
 *   GET  /api/credentials/:id  — Retrieve an issued credential
 *   GET  /                     — Health / info
 *
 * Spec: KYA-OS §4 (Delegation), §6 (Authorization)
 */

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider } from '@kya-os/mcp';
import { loadOrGenerateIdentity } from './identity.js';
import { createDelegationIssuerFromIdentity, type DelegationIssuerFactory } from './delegation-issuer.js';

const CONSENT_PORT   = parseInt(process.env['CONSENT_SERVICE_PORT'] ?? '3002', 10);
const PAYMENT_URL    = process.env['PAYMENT_SERVER_URL'] ?? 'http://localhost:3001';
const DELEGATION_TTL = parseInt(process.env['DELEGATION_TTL_SECONDS'] ?? '3600', 10);

// Store issued credentials for retrieval
const issuedCredentials = new Map<string, unknown>();

// ── Consent HTML page ────────────────────────────────────────────────────────

function renderConsentPage(params: { tool: string; scopes: string; agentDid: string; resumeToken: string }): string {
  const amountNote = params.scopes.includes('payments:write')
    ? 'This authorisation permits one high-value payment execution.'
    : `Scope: <code>${escHtml(params.scopes)}</code>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Authorise Payment — Bankee</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #f6f9fc; color: #0a2540; min-height: 100vh;
      display: flex; align-items: center; justify-content: center; padding: 1.5rem;
    }
    .card {
      background: white; border-radius: 16px; padding: 2.5rem;
      max-width: 480px; width: 100%;
      box-shadow: 0 4px 24px rgba(10,37,64,0.10);
    }
    .logo { font-size: 1.375rem; font-weight: 800; letter-spacing: -0.04em; color: #0a2540; margin-bottom: 2rem; }
    .logo span { background: linear-gradient(135deg,#635bff,#00c4cc); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
    h1 { font-size: 1.25rem; font-weight: 700; margin-bottom: 0.5rem; }
    .subtitle { font-size: 0.875rem; color: #425466; margin-bottom: 2rem; line-height: 1.6; }
    .field { background: #f6f9fc; border: 1px solid #e3e8ef; border-radius: 10px; padding: 1rem 1.25rem; margin-bottom: 0.875rem; }
    .field-label { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: #8898aa; margin-bottom: 0.3rem; }
    .field-value { font-size: 0.875rem; color: #0a2540; font-family: monospace; word-break: break-all; }
    .scope-badge {
      display: inline-block; font-size: 0.7rem; font-weight: 700; padding: 0.2rem 0.6rem;
      border-radius: 999px; background: #ede9fe; color: #635bff; margin-top: 0.25rem;
    }
    .warning { background: #fff8ed; border: 1.5px solid #ff990040; border-radius: 10px; padding: 0.875rem 1rem; margin-bottom: 1.5rem; font-size: 0.8125rem; color: #b45309; line-height: 1.6; }
    .buttons { display: flex; gap: 0.75rem; }
    .btn-approve {
      flex: 1; background: linear-gradient(135deg, #635bff, #00c4cc); border: none; color: white;
      padding: 0.875rem; border-radius: 10px; font-size: 0.9375rem; font-weight: 700; cursor: pointer;
    }
    .btn-deny {
      flex: 1; background: transparent; border: 1.5px solid #e3e8ef; color: #8898aa;
      padding: 0.875rem; border-radius: 10px; font-size: 0.9375rem; font-weight: 600; cursor: pointer;
    }
    .result { padding: 1.5rem; border-radius: 10px; text-align: center; font-weight: 600; display: none; }
    .result.approved { background: #d1fae5; color: #059669; }
    .result.denied   { background: #fee2e2; color: #dc2626; }
    code { font-family: monospace; background: #f0f4f8; padding: 0.1em 0.35em; border-radius: 4px; font-size: 0.85em; }
  </style>
</head>
<body>
<div class="card">
  <div class="logo">Bankee<span>.</span>ai</div>
  <h1>Payment Authorisation Required</h1>
  <p class="subtitle">
    An AI agent is requesting permission to execute a high-value payment.
    Review the details below and approve or deny.
  </p>

  <div class="field">
    <div class="field-label">Tool</div>
    <div class="field-value">${escHtml(params.tool)}</div>
  </div>
  <div class="field">
    <div class="field-label">Requested Scope</div>
    <div class="field-value"><span class="scope-badge">${escHtml(params.scopes)}</span></div>
    <div class="field-value" style="margin-top:0.5rem;font-size:0.8rem;color:#425466">${amountNote}</div>
  </div>
  <div class="field">
    <div class="field-label">Agent DID</div>
    <div class="field-value">${escHtml(params.agentDid)}</div>
  </div>

  <div class="warning">
    ⚠️  This action will issue a cryptographically-signed Delegation Credential
    binding your identity as Responsible Party to this agent's payment action.
    The credential is recorded in the audit trail.
  </div>

  <div class="buttons" id="buttons">
    <button class="btn-deny" onclick="respond('deny')">Deny</button>
    <button class="btn-approve" onclick="respond('approve')">Approve Payment</button>
  </div>
  <div class="result" id="result"></div>
</div>
<script>
  async function respond(action) {
    document.getElementById('buttons').style.display = 'none';
    const r = document.getElementById('result');
    r.style.display = 'block';

    if (action === 'deny') {
      r.className = 'result denied';
      r.textContent = '✕  Payment denied. The agent has been notified.';
      return;
    }

    r.className = 'result approved';
    r.textContent = '⏳  Issuing delegation credential…';

    try {
      const resp = await fetch('/api/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: '${escHtml(params.tool)}',
          scopes: '${escHtml(params.scopes)}',
          agentDid: '${escHtml(params.agentDid)}',
          resumeToken: '${escHtml(params.resumeToken)}',
        }),
      });
      const data = await resp.json();
      if (data.credentialId) {
        r.textContent = '✓  Approved. The agent may now retry the payment.';
      } else {
        r.className = 'result denied';
        r.textContent = '✕  Error: ' + (data.error ?? 'unknown');
      }
    } catch (e) {
      r.className = 'result denied';
      r.textContent = '✕  Network error. Please try again.';
    }
  }
</script>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
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

async function startConsentService(factory: DelegationIssuerFactory) {
  const httpServer = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const url = new URL(req.url ?? '/', `http://localhost:${CONSENT_PORT}`);

    // ── GET /consent — render approval page ─────────────────────────────
    if (url.pathname === '/consent' && req.method === 'GET') {
      const params = {
        tool:        url.searchParams.get('tool')        ?? 'unknown',
        scopes:      url.searchParams.get('scopes')      ?? 'unknown',
        agentDid:    url.searchParams.get('agent_did')   ?? 'unknown',
        resumeToken: url.searchParams.get('resume_token') ?? '',
      };
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderConsentPage(params));
      return;
    }

    // ── POST /api/approve — issue VC + notify payment server ─────────────
    if (url.pathname === '/api/approve' && req.method === 'POST') {
      try {
        const body = await readBody(req);
        const { tool, scopes, agentDid, resumeToken } = JSON.parse(body) as {
          tool: string; scopes: string; agentDid: string; resumeToken?: string;
        };

        if (!tool || !scopes || !agentDid) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'missing_fields' }));
          return;
        }

        const nowSeconds = Math.floor(Date.now() / 1000);
        const credentialId = `delegation-${Date.now()}-${Math.random().toString(36).slice(2,8)}`;

        const vc = await factory.issuer.createAndIssueDelegation({
          id: credentialId,
          issuerDid: factory.identity.did,
          subjectDid: agentDid,
          constraints: {
            scopes: scopes.split(',').map(s => s.trim()).filter(Boolean),
            notAfter: nowSeconds + DELEGATION_TTL,
          },
          metadata: { tool, approvedAt: new Date().toISOString(), approvedBy: factory.identity.did },
        });

        issuedCredentials.set(credentialId, vc);
        process.stderr.write(`[consent] Issued VC ${credentialId} for ${agentDid} — tool: ${tool}\n`);

        // Notify payment server to store the delegation
        if (resumeToken) {
          try {
            await fetch(`${PAYMENT_URL}/api/delegations/${resumeToken}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ vc, ttlSeconds: DELEGATION_TTL }),
            });
            process.stderr.write(`[consent] Notified payment server for resume_token: ${resumeToken}\n`);
          } catch {
            process.stderr.write(`[consent] Warning: could not notify payment server\n`);
          }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ credentialId, issuerDid: factory.identity.did, subjectDid: agentDid }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'unknown' }));
      }
      return;
    }

    // ── GET /api/credentials/:id ─────────────────────────────────────────
    if (url.pathname.startsWith('/api/credentials/') && req.method === 'GET') {
      const id = url.pathname.split('/').pop()!;
      const vc = issuedCredentials.get(id);
      if (!vc) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not_found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(vc));
      return;
    }

    // ── Health ───────────────────────────────────────────────────────────
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: 'bankee-consent-service',
        issuerDid: factory.identity.did,
        credentialsIssued: issuedCredentials.size,
      }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });

  httpServer.listen(CONSENT_PORT, () => {
    process.stderr.write(`\n[consent] ─────────────────────────────────────────\n`);
    process.stderr.write(`[consent] Bankee Consent & Credential Service\n`);
    process.stderr.write(`[consent] Issuer DID: ${factory.identity.did}\n`);
    process.stderr.write(`[consent] Consent UI: http://localhost:${CONSENT_PORT}/consent\n`);
    process.stderr.write(`[consent] Approve:    POST http://localhost:${CONSENT_PORT}/api/approve\n`);
    process.stderr.write(`[consent] ─────────────────────────────────────────\n\n`);
  });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const identity = await loadOrGenerateIdentity('consent');
  const factory  = createDelegationIssuerFromIdentity(new NodeCryptoProvider(), identity);
  await startConsentService(factory);
}
