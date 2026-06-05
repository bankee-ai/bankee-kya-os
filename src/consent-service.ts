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
import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider } from '@kya-os/mcp';
import { loadOrGenerateIdentity } from './identity.js';
import { createDelegationIssuerFromIdentity, type DelegationIssuerFactory } from './delegation-issuer.js';

const CONSENT_PORT    = parseInt(process.env['CONSENT_SERVICE_PORT'] ?? '3002', 10);
const PAYMENT_URL     = process.env['PAYMENT_SERVER_URL'] ?? 'http://localhost:3001';
const DELEGATION_TTL  = parseInt(process.env['DELEGATION_TTL_SECONDS'] ?? '3600', 10);
const STATUS_LIST_URL = process.env['STATUS_LIST_URL'] ?? `http://localhost:${CONSENT_PORT}/api/status-list`;

const gzip   = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

// ── StatusList2021 ────────────────────────────────────────────────────────────
// W3C StatusList2021 spec: https://w3c.github.io/vc-status-list-2021/
//
// A compact revocation list: gzip-compressed bitstring where bit[i] = 1 means
// credential at index i is revoked. Published as a Verifiable Credential at
// GET /api/status-list. Individual VCs reference their index via credentialStatus.

const STATUS_LIST_SIZE = 131072; // 16KB = 131072 entries — enough for many VCs

class StatusList2021 {
  private bits   = new Uint8Array(Math.ceil(STATUS_LIST_SIZE / 8));
  private cursor = 0;

  allocate(): number {
    if (this.cursor >= STATUS_LIST_SIZE) throw new Error('status list full');
    return this.cursor++;
  }

  revoke(index: number): void {
    this.bits[Math.floor(index / 8)] |= (1 << (index % 8));
  }

  unrevoke(index: number): void {
    this.bits[Math.floor(index / 8)] &= ~(1 << (index % 8));
  }

  isRevoked(index: number): boolean {
    return !!(this.bits[Math.floor(index / 8)] & (1 << (index % 8)));
  }

  async encodedList(): Promise<string> {
    const compressed = await gzip(Buffer.from(this.bits));
    return compressed.toString('base64url');
  }
}

const statusList = new StatusList2021();

// Store issued credentials: id → { vc, statusIndex, subjectDid, scopes }
interface CredentialRecord {
  vc:          unknown;
  statusIndex: number;
  subjectDid:  string;
  scopes:      string[];
  issuedAt:    string;
  revokedAt?:  string;
  parentVcId?: string;   // for sub-delegations
  depth:       number;   // 0 = RP-issued, 1 = sub-delegation, etc.
}

const issuedCredentials = new Map<string, CredentialRecord>();

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

        const scopeList = scopes.split(',').map(s => s.trim()).filter(Boolean);
        const statusIndex = statusList.allocate();

        const vc = await factory.issuer.createAndIssueDelegation({
          id: credentialId,
          issuerDid: factory.identity.did,
          subjectDid: agentDid,
          constraints: {
            scopes: scopeList,
            notAfter: nowSeconds + DELEGATION_TTL,
          },
          metadata: { tool, approvedAt: new Date().toISOString(), approvedBy: factory.identity.did },
          // W3C StatusList2021 — verifiers can check revocation at STATUS_LIST_URL
          credentialStatus: {
            id: `${STATUS_LIST_URL}#${statusIndex}`,
            type: 'StatusList2021Entry',
            statusPurpose: 'revocation',
            statusListIndex: String(statusIndex),
            statusListCredential: STATUS_LIST_URL,
          },
        });

        issuedCredentials.set(credentialId, {
          vc,
          statusIndex,
          subjectDid: agentDid,
          scopes: scopeList,
          issuedAt: new Date().toISOString(),
          depth: 0,
        });
        process.stderr.write(`[consent] Issued VC ${credentialId} (index ${statusIndex}) for ${agentDid} — tool: ${tool}\n`);

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
      const record = issuedCredentials.get(id);
      if (!record) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not_found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ...record.vc as object,
        _meta: {
          statusIndex: record.statusIndex,
          revoked: !!record.revokedAt,
          revokedAt: record.revokedAt ?? null,
          depth: record.depth,
          parentVcId: record.parentVcId ?? null,
        },
      }));
      return;
    }

    // ── POST /api/revoke/:id — revoke an issued VC via StatusList2021 ────
    if (url.pathname.startsWith('/api/revoke/') && req.method === 'POST') {
      const id = url.pathname.replace('/api/revoke/', '');
      const record = issuedCredentials.get(id);
      if (!record) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'credential_not_found' }));
        return;
      }
      statusList.revoke(record.statusIndex);
      record.revokedAt = new Date().toISOString();
      process.stderr.write(`[consent] Revoked VC ${id} (index ${record.statusIndex})\n`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ revoked: true, id, statusIndex: record.statusIndex }));
      return;
    }

    // ── GET /api/status-list — W3C StatusList2021 credential ─────────────
    if (url.pathname === '/api/status-list' && req.method === 'GET') {
      const encodedList = await statusList.encodedList();
      const statusListCredential = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/vc/status-list/2021/v1',
        ],
        id: STATUS_LIST_URL,
        type: ['VerifiableCredential', 'StatusList2021Credential'],
        issuer: factory.identity.did,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: `${STATUS_LIST_URL}#list`,
          type: 'StatusList2021',
          statusPurpose: 'revocation',
          encodedList,
        },
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(statusListCredential));
      return;
    }

    // ── POST /api/delegate — sub-delegation (multi-hop) ──────────────────
    // An agent that holds a valid VC can request the RP issue a narrower
    // credential to a child agent — enabling multi-hop delegation chains.
    //
    //   RP → Business Agent VC  →  POST /api/delegate  →  Task Agent VC
    //   (parentVcId + subjectDid + scopes ⊆ parent scopes)
    if (url.pathname === '/api/delegate' && req.method === 'POST') {
      try {
        const body = await readBody(req);
        const { parentVcId, subjectDid, scopes, tool } = JSON.parse(body) as {
          parentVcId: string; subjectDid: string; scopes: string; tool?: string;
        };

        if (!parentVcId || !subjectDid || !scopes) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'missing_fields: parentVcId, subjectDid, scopes required' }));
          return;
        }

        const parent = issuedCredentials.get(parentVcId);
        if (!parent) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'parent_vc_not_found' }));
          return;
        }
        if (parent.revokedAt) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'parent_vc_revoked', revokedAt: parent.revokedAt }));
          return;
        }

        // Scope narrowing: requested scopes must be a subset of parent scopes
        const requestedScopes = scopes.split(',').map(s => s.trim()).filter(Boolean);
        const unauthorisedScopes = requestedScopes.filter(s => !parent.scopes.includes(s));
        if (unauthorisedScopes.length > 0) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'scope_exceeds_parent', unauthorisedScopes }));
          return;
        }

        const nowSeconds = Math.floor(Date.now() / 1000);
        const childId = `delegation-sub-${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
        const statusIndex = statusList.allocate();

        const childVc = await factory.issuer.createAndIssueDelegation({
          id: childId,
          issuerDid: factory.identity.did,
          subjectDid,
          constraints: { scopes: requestedScopes, notAfter: nowSeconds + DELEGATION_TTL },
          metadata: {
            tool: tool ?? 'inherited',
            approvedAt: new Date().toISOString(),
            approvedBy: factory.identity.did,
            parentVcId,
            delegationDepth: parent.depth + 1,
          },
          credentialStatus: {
            id: `${STATUS_LIST_URL}#${statusIndex}`,
            type: 'StatusList2021Entry',
            statusPurpose: 'revocation',
            statusListIndex: String(statusIndex),
            statusListCredential: STATUS_LIST_URL,
          },
        });

        issuedCredentials.set(childId, {
          vc: childVc,
          statusIndex,
          subjectDid,
          scopes: requestedScopes,
          issuedAt: new Date().toISOString(),
          parentVcId,
          depth: parent.depth + 1,
        });

        process.stderr.write(`[consent] Sub-delegation ${childId} (depth ${parent.depth + 1}) → ${subjectDid}\n`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ credentialId: childId, depth: parent.depth + 1, scopes: requestedScopes }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'unknown' }));
      }
      return;
    }

    // ── GET /api/credentials — list all issued VCs ────────────────────────
    if (url.pathname === '/api/credentials' && req.method === 'GET') {
      const list = Array.from(issuedCredentials.entries()).map(([id, r]) => ({
        id,
        subjectDid: r.subjectDid,
        scopes: r.scopes,
        issuedAt: r.issuedAt,
        revoked: !!r.revokedAt,
        revokedAt: r.revokedAt ?? null,
        depth: r.depth,
        parentVcId: r.parentVcId ?? null,
        statusIndex: r.statusIndex,
      }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ credentials: list, total: list.length }));
      return;
    }

    // ── Health ───────────────────────────────────────────────────────────
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: 'bankee-consent-service',
        issuerDid: factory.identity.did,
        credentialsIssued: issuedCredentials.size,
        statusListUrl: STATUS_LIST_URL,
        statusListEntries: issuedCredentials.size,
        revokedCount: Array.from(issuedCredentials.values()).filter(r => r.revokedAt).length,
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
