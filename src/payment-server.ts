#!/usr/bin/env npx tsx
/**
 * Bankee Payment MCP Server — KYA-OS secured
 *
 * Exposes five payment tools over SSE and Streamable HTTP:
 *
 *   get_balance        → proof only (no delegation required)
 *   get_exchange_rate  → proof only
 *   list_payments      → proof only
 *   get_payment_status → proof only
 *   create_payment     → proof only if amount ≤ HIGH_VALUE_THRESHOLD
 *                        consent gate + proof if amount > HIGH_VALUE_THRESHOLD
 *
 * Every tool response carries a detached JWS proof in _meta, recording:
 *   - the server's DID (agent identity)
 *   - the session ID (replay-attack protection)
 *   - SHA-256 hashes of the request and response (tamper evidence)
 *   - a timestamp
 *
 * Proof records are forwarded to the audit service via webhook.
 *
 * Architecture note: uses the low-level Server API + createKyaOsMiddleware
 * instead of withKyaOs(). Delegation-protected tools receive _kyaos_delegation
 * as an argument; McpServer.registerTool strips unknown keys via zod validation,
 * so the low-level API is required here.
 *
 * Spec coverage: KYA-OS §4 (Identity), §5 (Proof), §6 (Delegation/Authorization)
 */

import http from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import {
  createKyaOsMiddleware,
  NodeCryptoProvider,
  MemoryAuditLogProvider,
  buildAuditRecord,
  type KyaOsMiddleware,
  type AuditRecord,
} from '@kya-os/mcp';
import { loadOrGenerateIdentity } from './identity.js';

const PAYMENT_PORT       = parseInt(process.env['PAYMENT_SERVER_PORT']   ?? '3001', 10);
const CONSENT_URL        = `${process.env['CONSENT_SERVICE_URL'] ?? 'http://localhost:3002'}/consent`;
const AUDIT_URL          = `${process.env['AUDIT_SERVICE_URL']   ?? 'http://localhost:3003'}/api/records`;
const HIGH_VALUE         = parseInt(process.env['HIGH_VALUE_THRESHOLD']   ?? '10000', 10);

// ── In-process audit log + delegation store ──────────────────────────────────

const auditLog = new MemoryAuditLogProvider();
const auditRecords: AuditRecord[] = [];

// Delegation store: resume_token → approved VC (written by consent service)
const delegationStore = new Map<string, { vc: unknown; expiresAt: number }>();

function storeDelegation(resumeToken: string, vc: unknown, ttlSeconds = 3600) {
  delegationStore.set(resumeToken, { vc, expiresAt: Date.now() + ttlSeconds * 1000 });
}

function consumeDelegationForTool(toolName: string): { resumeToken: string; vc: unknown } | undefined {
  for (const [token, entry] of delegationStore) {
    if (Date.now() > entry.expiresAt) { delegationStore.delete(token); continue; }
    const vc = entry.vc as Record<string, unknown> | undefined;
    const metadata = (vc?.credentialSubject as Record<string, unknown>)
      ?.delegation as Record<string, unknown> | undefined;
    if (metadata?.metadata && (metadata.metadata as Record<string, unknown>)['tool'] === toolName) {
      delegationStore.delete(token);
      return { resumeToken: token, vc: entry.vc };
    }
  }
}

// Forward proof records to the audit service in the background
async function emitToAuditService(record: AuditRecord, toolName: string) {
  try {
    await fetch(AUDIT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...record, tool: toolName }),
    });
  } catch {
    // Audit service may not be running yet — silently skip
  }
}

// ── Mock Bankee SDK ──────────────────────────────────────────────────────────
// In production: replace with `import { BankeeSDK } from '@bankee/sdk'`

interface Payment { id: string; amount: number; currency: string; status: string; reference: string; created: string }
const mockPayments: Payment[] = [];

function mockBalance() {
  return { available: 125000, pending: 3200, currency: 'GBP', updated: new Date().toISOString() };
}

function mockRate(pair: string) {
  const rates: Record<string, number> = { 'GBP/USD': 1.267, 'GBP/EUR': 1.171, 'GBP/USDC': 1.265 };
  return rates[pair] ?? 1.0;
}

function mockCreatePayment(amount: number, currency: string, reference: string): Payment {
  const payment: Payment = {
    id: `pay_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    amount, currency, reference,
    status: 'completed',
    created: new Date().toISOString(),
  };
  mockPayments.push(payment);
  return payment;
}

// ── MCP server factory ───────────────────────────────────────────────────────

function createPaymentServer(kyaos: KyaOsMiddleware) {
  const server = new Server(
    { name: 'bankee-payment-server', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  // ── Tool: get_balance ───────────────────────────────────────────────────
  const getBalance = kyaos.wrapWithProof('get_balance', async (_args, sessionId) => {
    const balance = mockBalance();
    await auditLog.logAuditRecord({
      session: { sessionId: sessionId ?? 'unknown', audience: kyaos.identity.did },
      identity: { did: kyaos.identity.did, kid: kyaos.identity.kid },
      requestHash: 'sha256:get_balance',
      responseHash: `sha256:${balance.available}`,
      verified: true,
    });
    return { content: [{ type: 'text', text: JSON.stringify(balance, null, 2) }] };
  });

  // ── Tool: get_exchange_rate ─────────────────────────────────────────────
  const getRate = kyaos.wrapWithProof('get_exchange_rate', async (args, sessionId) => {
    const pair = (args['pair'] as string) ?? 'GBP/USD';
    const rate = mockRate(pair);
    await auditLog.logAuditRecord({
      session: { sessionId: sessionId ?? 'unknown', audience: kyaos.identity.did },
      identity: { did: kyaos.identity.did, kid: kyaos.identity.kid },
      requestHash: `sha256:rate:${pair}`,
      responseHash: `sha256:${rate}`,
      verified: true,
    });
    return { content: [{ type: 'text', text: JSON.stringify({ pair, rate, timestamp: new Date().toISOString() }, null, 2) }] };
  });

  // ── Tool: list_payments ─────────────────────────────────────────────────
  const listPayments = kyaos.wrapWithProof('list_payments', async (_args, sessionId) => {
    await auditLog.logAuditRecord({
      session: { sessionId: sessionId ?? 'unknown', audience: kyaos.identity.did },
      identity: { did: kyaos.identity.did, kid: kyaos.identity.kid },
      requestHash: 'sha256:list_payments',
      responseHash: `sha256:count:${mockPayments.length}`,
      verified: true,
    });
    return { content: [{ type: 'text', text: JSON.stringify({ payments: mockPayments, total: mockPayments.length }, null, 2) }] };
  });

  // ── Tool: get_payment_status ────────────────────────────────────────────
  const getPaymentStatus = kyaos.wrapWithProof('get_payment_status', async (args, sessionId) => {
    const id = args['payment_id'] as string;
    const payment = mockPayments.find(p => p.id === id);
    await auditLog.logAuditRecord({
      session: { sessionId: sessionId ?? 'unknown', audience: kyaos.identity.did },
      identity: { did: kyaos.identity.did, kid: kyaos.identity.kid },
      requestHash: `sha256:status:${id}`,
      responseHash: `sha256:${payment?.status ?? 'not_found'}`,
      verified: true,
    });
    if (!payment) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'Payment not found', id }) }], isError: true };
    }
    return { content: [{ type: 'text', text: JSON.stringify(payment, null, 2) }] };
  });

  // ── Tool: create_payment ────────────────────────────────────────────────
  // Low-value (≤ HIGH_VALUE): proof only — no human gate
  // High-value (> HIGH_VALUE): consent gate → delegation VC required → proof
  const rawCreatePayment = kyaos.wrapWithDelegation(
    'create_payment',
    {
      scopeId: 'payments:write',
      consentUrl: CONSENT_URL,
      formatChallenge: (challenge) => {
        const url = new URL(CONSENT_URL);
        url.searchParams.set('tool', 'create_payment');
        url.searchParams.set('scopes', challenge.scopes.join(','));
        url.searchParams.set('agent_did', kyaos.identity.did);
        url.searchParams.set('resume_token', challenge.resumeToken);
        return [{
          type: 'text' as const,
          text: [
            '⚠️  High-value payment requires authorisation.',
            '',
            `Amount: ${challenge.scopes.includes('payments:write') ? 'above threshold' : 'unknown'}`,
            '',
            `[Authorise payment](${url.toString()})`,
            '',
            'Retry after authorising.',
          ].join('\n'),
        }];
      },
    },
    kyaos.wrapWithProof('create_payment', async (args, sessionId) => {
      const amount    = args['amount']    as number;
      const currency  = args['currency']  as string ?? 'GBP';
      const reference = args['reference'] as string ?? `ref-${Date.now()}`;

      const payment = mockCreatePayment(amount, currency, reference);

      const record = buildAuditRecord({
        session:      { sessionId: sessionId ?? 'unknown', audience: kyaos.identity.did },
        identity:     { did: kyaos.identity.did, kid: kyaos.identity.kid },
        requestHash:  `sha256:create:${amount}:${currency}`,
        responseHash: `sha256:${payment.id}`,
        verified:     true,
        scopeId:      'payments:write',
      });
      auditRecords.push(record);
      void emitToAuditService({ ...record, tool: 'create_payment' } as AuditRecord & { tool: string }, 'create_payment');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            payment,
            message: `Payment of ${(amount / 100).toFixed(2)} ${currency} created successfully.`,
            agentDid: kyaos.identity.did,
          }, null, 2),
        }],
      };
    }),
  );

  // Auto-apply delegation from store on create_payment retry
  const createPayment = async (args: Record<string, unknown>, sessionId?: string) => {
    const amount = args['amount'] as number ?? 0;

    // Route low-value payments directly (no consent gate)
    if (amount <= HIGH_VALUE) {
      return kyaos.wrapWithProof('create_payment', async (a, sid) => {
        const payment = mockCreatePayment(a['amount'] as number, a['currency'] as string ?? 'GBP', a['reference'] as string ?? `ref-${Date.now()}`);
        const record = buildAuditRecord({
          session:  { sessionId: sid ?? 'unknown', audience: kyaos.identity.did },
          identity: { did: kyaos.identity.did, kid: kyaos.identity.kid },
          requestHash:  `sha256:create:${a['amount']}:${a['currency']}`,
          responseHash: `sha256:${payment.id}`,
          verified: true,
        });
        auditRecords.push(record);
        void emitToAuditService({ ...record, tool: 'create_payment' } as AuditRecord & { tool: string }, 'create_payment');
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ payment, message: `Autonomous payment of ${((a['amount'] as number) / 100).toFixed(2)} ${a['currency'] as string ?? 'GBP'} created.`, agentDid: kyaos.identity.did }, null, 2),
          }],
        };
      })(args, sessionId);
    }

    // High-value: check delegation store for auto-apply on retry
    if (!args['_kyaos_delegation']) {
      const pending = consumeDelegationForTool('create_payment');
      if (pending) {
        process.stderr.write(`[payment] Auto-applying delegation from consent (token: ${pending.resumeToken})\n`);
        return rawCreatePayment({ ...args, _kyaos_delegation: pending.vc }, sessionId);
      }
    }

    return rawCreatePayment(args, sessionId);
  };

  // ── Tool registry ────────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      kyaos.kyaOsTool,
      {
        name: 'get_balance',
        description: 'Get the current wallet balance. Proof attached. No delegation required.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'get_exchange_rate',
        description: 'Get a live foreign exchange rate. Proof attached. No delegation required.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            pair: { type: 'string', description: 'Currency pair, e.g. GBP/USD, GBP/EUR, GBP/USDC' },
          },
          required: ['pair'],
        },
      },
      {
        name: 'list_payments',
        description: 'List all payments in this session. Proof attached. No delegation required.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'get_payment_status',
        description: 'Get the status of a specific payment. Proof attached. No delegation required.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            payment_id: { type: 'string', description: 'Payment ID returned by create_payment' },
          },
          required: ['payment_id'],
        },
      },
      {
        name: 'create_payment',
        description: `Create a payment. Amounts ≤ £${(HIGH_VALUE / 100).toFixed(2)} execute autonomously (proof only). Amounts above require human consent — a Delegation VC with scope payments:write.`,
        inputSchema: {
          type: 'object' as const,
          properties: {
            amount:    { type: 'number',  description: 'Amount in minor units (e.g. 2500 = £25.00)' },
            currency:  { type: 'string',  description: 'ISO 4217 currency code (default: GBP)' },
            reference: { type: 'string',  description: 'Payment reference or description' },
          },
          required: ['amount'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    const sessionId = (request.params as Record<string, unknown>)['sessionId'] as string | undefined;

    if (name === '_kyaos')            return kyaos.handleKyaOs(args as Record<string, unknown>);
    if (name === 'get_balance')        return getBalance(args as Record<string, unknown>, sessionId);
    if (name === 'get_exchange_rate')  return getRate(args as Record<string, unknown>, sessionId);
    if (name === 'list_payments')      return listPayments(args as Record<string, unknown>, sessionId);
    if (name === 'get_payment_status') return getPaymentStatus(args as Record<string, unknown>, sessionId);
    if (name === 'create_payment')     return createPayment(args as Record<string, unknown>, sessionId);

    return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  });

  return server;
}

// ── HTTP server ──────────────────────────────────────────────────────────────

function setCors(res: http.ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, MCP-Session-Id');
  res.setHeader('Access-Control-Expose-Headers', 'MCP-Session-Id');
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

async function startServer(kyaos: KyaOsMiddleware) {
  let sseTransport: SSEServerTransport | null = null;

  const httpServer = http.createServer(async (req, res) => {
    setCors(res);

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const url = new URL(req.url ?? '/', `http://localhost:${PAYMENT_PORT}`);

    // SSE transport
    if (url.pathname === '/sse' && req.method === 'GET') {
      const server = createPaymentServer(kyaos);
      sseTransport = new SSEServerTransport('/messages', res);
      await server.connect(sseTransport);
      process.stderr.write('[payment] SSE client connected\n');
      return;
    }
    if (url.pathname === '/messages' && req.method === 'POST') {
      if (!sseTransport) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No SSE session. Connect to /sse first.' }));
        return;
      }
      await sseTransport.handlePostMessage(req, res);
      return;
    }

    // Streamable HTTP transport (MCP Inspector compatible)
    if (url.pathname === '/mcp' && req.method === 'POST') {
      const server = createPaymentServer(kyaos);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    // ── REST API for inter-service communication ─────────────────────────

    // Consent service calls this to store an approved delegation VC
    if (url.pathname.startsWith('/api/delegations/') && req.method === 'POST') {
      const resumeToken = url.pathname.split('/').pop()!;
      const body = await readBody(req);
      const { vc, ttlSeconds } = JSON.parse(body) as { vc: unknown; ttlSeconds?: number };
      storeDelegation(resumeToken, vc, ttlSeconds);
      process.stderr.write(`[payment] Stored delegation for resume_token: ${resumeToken}\n`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    // Audit query endpoint
    if (url.pathname === '/api/audit' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ records: auditRecords, total: auditRecords.length }));
      return;
    }

    // Info / health
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: 'bankee-payment-server',
        version: '1.0.0',
        did: kyaos.identity.did,
        highValueThreshold: HIGH_VALUE,
        transports: {
          sse: `http://localhost:${PAYMENT_PORT}/sse`,
          mcp: `http://localhost:${PAYMENT_PORT}/mcp`,
        },
      }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });

  httpServer.listen(PAYMENT_PORT, () => {
    process.stderr.write(`\n[payment] ─────────────────────────────────────────\n`);
    process.stderr.write(`[payment] Bankee Payment MCP Server\n`);
    process.stderr.write(`[payment] DID:      ${kyaos.identity.did}\n`);
    process.stderr.write(`[payment] SSE:      http://localhost:${PAYMENT_PORT}/sse\n`);
    process.stderr.write(`[payment] MCP:      http://localhost:${PAYMENT_PORT}/mcp\n`);
    process.stderr.write(`[payment] Audit:    http://localhost:${PAYMENT_PORT}/api/audit\n`);
    process.stderr.write(`[payment] High-val: £${(HIGH_VALUE / 100).toFixed(2)} threshold\n`);
    process.stderr.write(`[payment] ─────────────────────────────────────────\n\n`);
  });
}

// Run
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const identity = await loadOrGenerateIdentity('payment');
  const kyaos = createKyaOsMiddleware(
    { identity, session: { sessionTtlMinutes: 60 }, autoSession: true },
    new NodeCryptoProvider(),
  );
  await startServer(kyaos);
}
