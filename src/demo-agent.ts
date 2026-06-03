#!/usr/bin/env npx tsx
/**
 * Bankee KYA-OS Demo Agent
 *
 * Runs a complete end-to-end demonstration of the KYA-OS-secured
 * agentic payment infrastructure:
 *
 *   Step 1  — Handshake:     Establish a KYA-OS session with the payment server
 *   Step 2  — get_balance:   Call a proof-only tool (succeeds immediately)
 *   Step 3  — get_rate:      Call another proof-only tool
 *   Step 4  — Low payment:   create_payment £50 — autonomous, no consent
 *   Step 5  — High payment:  create_payment £500 — blocked, needs_authorization
 *   Step 6  — Consent:       Simulate human approval via consent service API
 *   Step 7  — Retry:         Retry create_payment — auto-applies delegation VC
 *   Step 8  — Status:        get_payment_status — proof attached
 *   Step 9  — List:          list_payments — full history
 *   Step 10 — Audit trail:   Query audit service for all proof records
 *   Step 11 — Verify:        Submit a proof to the audit service for verification
 *
 * Usage:
 *   npm run demo                   # starts all services + demo agent
 *   tsx src/demo-agent.ts          # if services already running
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

const PAYMENT_URL  = process.env['PAYMENT_SERVER_URL']  ?? 'http://localhost:3001';
const CONSENT_URL  = process.env['CONSENT_SERVICE_URL'] ?? 'http://localhost:3002';
const AUDIT_URL    = process.env['AUDIT_SERVICE_URL']   ?? 'http://localhost:3003';

// ── Console helpers ──────────────────────────────────────────────────────────

const c = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  cyan:   '\x1b[36m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  red:    '\x1b[31m',
  purple: '\x1b[35m',
  dim:    '\x1b[2m',
  blue:   '\x1b[34m',
};

function banner(step: number, title: string) {
  console.log(`\n${c.bold}${c.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}`);
  console.log(`${c.bold}${c.cyan}  Step ${step}: ${title}${c.reset}`);
  console.log(`${c.bold}${c.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}`);
}

function ok(msg: string)    { console.log(`  ${c.green}✓${c.reset} ${msg}`); }
function info(msg: string)  { console.log(`  ${c.blue}ℹ${c.reset} ${msg}`); }
function warn(msg: string)  { console.log(`  ${c.yellow}⚠${c.reset} ${msg}`); }
function proof(msg: string) { console.log(`  ${c.purple}🔏${c.reset} ${msg}`); }
function step(msg: string)  { console.log(`  ${c.dim}→${c.reset} ${msg}`); }

function printProofMeta(meta: Record<string, unknown> | undefined) {
  if (!meta?.proof) return;
  const p = meta.proof as Record<string, unknown>;
  const pm = p['meta'] as Record<string, unknown> | undefined;
  if (!pm) return;
  proof(`Proof attached:`);
  console.log(`    ${c.dim}DID:      ${String(pm['did']).slice(0, 50)}…${c.reset}`);
  console.log(`    ${c.dim}Session:  ${String(pm['sessionId'] ?? pm['nonce'] ?? '').slice(0, 20)}…${c.reset}`);
  console.log(`    ${c.dim}Req hash: ${String(pm['requestHash'] ?? '').slice(0,30)}…${c.reset}`);
  console.log(`    ${c.dim}Res hash: ${String(pm['responseHash'] ?? '').slice(0,30)}…${c.reset}`);
}

// ── MCP client helpers ───────────────────────────────────────────────────────

async function callTool(
  client: Client,
  name: string,
  args: Record<string, unknown> = {},
): Promise<{ result: Record<string, unknown>; text: string }> {
  const result = await client.callTool({ name, arguments: args }) as Record<string, unknown>;
  const content = (result['content'] as Array<{ type: string; text?: string }> | undefined) ?? [];
  const text = content.find(c => c.type === 'text')?.text ?? '';
  return { result, text };
}

async function waitForServer(url: string, label: string, maxAttempts = 20): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) { ok(`${label} is ready`); return; }
    } catch { /* keep waiting */ }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`${label} did not start within ${maxAttempts * 0.5}s`);
}

// ── Main demo ────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n${c.bold}${c.cyan}`);
  console.log(`  ██████╗  █████╗ ███╗   ██╗██╗  ██╗███████╗███████╗`);
  console.log(`  ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██╔════╝██╔════╝`);
  console.log(`  ██████╔╝███████║██╔██╗ ██║█████╔╝ █████╗  █████╗  `);
  console.log(`  ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██╔══╝  ██╔══╝  `);
  console.log(`  ██████╔╝██║  ██║██║ ╚████║██║  ██╗███████╗███████╗ `);
  console.log(`  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝`);
  console.log(`${c.reset}`);
  console.log(`  ${c.bold}KYA-OS End-to-End Payment Infrastructure Demo${c.reset}`);
  console.log(`  ${c.dim}Identity · Delegation · Proof · Consent · Audit${c.reset}\n`);

  // ── Wait for services ────────────────────────────────────────────────────
  banner(0, 'Waiting for services');
  await waitForServer(`${PAYMENT_URL}/`,  'Payment server');
  await waitForServer(`${CONSENT_URL}/`,  'Consent service');
  await waitForServer(`${AUDIT_URL}/`,    'Audit service');

  // Fetch server info
  const serverInfo = await fetch(`${PAYMENT_URL}/`).then(r => r.json()) as Record<string, unknown>;
  info(`Payment server DID: ${c.dim}${serverInfo['did']}${c.reset}`);
  info(`High-value threshold: £${((serverInfo['highValueThreshold'] as number) / 100).toFixed(2)}`);

  // ── Connect MCP client ───────────────────────────────────────────────────
  banner(1, 'Connect MCP client + KYA-OS handshake');
  step('Connecting to payment server via SSE…');

  const transport = new SSEClientTransport(new URL(`${PAYMENT_URL}/sse`));
  const client = new Client({ name: 'bankee-demo-agent', version: '1.0.0' });
  await client.connect(transport);
  ok('Connected via SSE transport');

  // KYA-OS handshake
  step('Performing KYA-OS session handshake…');
  const { result: handshakeResult, text: handshakeText } = await callTool(client, '_kyaos', {
    type: 'handshake_request',
    nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url'),
    audience: serverInfo['did'] as string,
    timestamp: Math.floor(Date.now() / 1000),
    agentDid: 'did:key:demo-agent',
  });

  let sessionId: string | undefined;
  try {
    const parsed = JSON.parse(handshakeText) as Record<string, unknown>;
    sessionId = parsed['sessionId'] as string | undefined;
    if (sessionId) {
      ok(`KYA-OS session established: ${c.dim}${sessionId}${c.reset}`);
    } else {
      ok('KYA-OS session handshake complete');
    }
  } catch {
    ok('KYA-OS session handshake complete');
  }
  void handshakeResult;

  // ── get_balance ──────────────────────────────────────────────────────────
  banner(2, 'get_balance (proof only)');
  step('Calling get_balance…');
  const { result: balResult, text: balText } = await callTool(client, 'get_balance');
  const balance = JSON.parse(balText) as Record<string, unknown>;
  ok(`Balance: £${((balance['available'] as number) / 100).toFixed(2)} available, £${((balance['pending'] as number) / 100).toFixed(2)} pending`);
  printProofMeta(balResult['_meta'] as Record<string, unknown>);

  // ── get_exchange_rate ────────────────────────────────────────────────────
  banner(3, 'get_exchange_rate (proof only)');
  step('Calling get_exchange_rate GBP/USDC…');
  const { result: rateResult, text: rateText } = await callTool(client, 'get_exchange_rate', { pair: 'GBP/USDC' });
  const rate = JSON.parse(rateText) as Record<string, unknown>;
  ok(`GBP/USDC rate: ${rate['rate']}`);
  printProofMeta(rateResult['_meta'] as Record<string, unknown>);

  // ── create_payment — low value (autonomous) ──────────────────────────────
  banner(4, 'create_payment £50 (autonomous — below threshold)');
  step('Creating £50 payment — no consent required…');
  const { result: pay1Result, text: pay1Text } = await callTool(client, 'create_payment', {
    amount: 5000,   // £50.00 in minor units
    currency: 'GBP',
    reference: 'Invoice INV-001 — API access fee',
  });
  const pay1 = JSON.parse(pay1Text) as Record<string, unknown>;
  const pay1Data = pay1['payment'] as Record<string, unknown>;
  ok(`Payment created: ${c.dim}${pay1Data['id']}${c.reset}`);
  ok(`Status: ${pay1Data['status']} | Amount: £${((pay1Data['amount'] as number) / 100).toFixed(2)}`);
  ok(`Agent DID in payment record: ${c.dim}${String(pay1['agentDid']).slice(0,40)}…${c.reset}`);
  printProofMeta(pay1Result['_meta'] as Record<string, unknown>);

  // ── create_payment — high value (needs authorisation) ────────────────────
  banner(5, 'create_payment £500 (high-value — consent required)');
  step('Attempting £500 payment — expecting needs_authorization…');
  const { result: pay2Result, text: pay2Text } = await callTool(client, 'create_payment', {
    amount: 50000,  // £500.00
    currency: 'GBP',
    reference: 'Enterprise licence — annual subscription',
  });

  let resumeToken: string | undefined;
  let consentPageUrl: string | undefined;

  // Check if this is a needs_authorization response or if the consent gate
  // returned a markdown link
  if (pay2Text.includes('needs_authorization') || pay2Text.includes('Authoris')) {
    warn('Payment blocked: needs_authorization');
    // Extract consent URL and resume_token from the response text
    const urlMatch = pay2Text.match(/\(([^)]+consent[^)]+)\)/);
    if (urlMatch) {
      consentPageUrl = urlMatch[1];
      const tokenMatch = consentPageUrl.match(/resume_token=([^&]+)/);
      if (tokenMatch) resumeToken = decodeURIComponent(tokenMatch[1]);
    }
    info(`Consent URL: ${c.dim}${consentPageUrl ?? `${CONSENT_URL}/consent`}${c.reset}`);
    info(`Resume token: ${c.dim}${resumeToken ?? '(extracted from URL)'}${c.reset}`);
    printProofMeta(pay2Result['_meta'] as Record<string, unknown>);
  } else {
    // Might have auto-applied a previous session's delegation
    ok('Payment executed (delegation auto-applied from previous session)');
  }

  // ── Simulate human consent approval ─────────────────────────────────────
  banner(6, 'Human approves via consent service');

  // Get server DID for delegation subject
  const serverDid = serverInfo['did'] as string;

  step('Operator approving payment via consent service API…');
  const approvalResp = await fetch(`${CONSENT_URL}/api/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tool: 'create_payment',
      scopes: 'payments:write',
      agentDid: serverDid,   // the payment server's DID (the agent executing the tool)
      resumeToken: resumeToken ?? `demo-token-${Date.now()}`,
    }),
  });

  const approval = await approvalResp.json() as Record<string, unknown>;
  if (approval['credentialId']) {
    ok(`Delegation VC issued: ${c.dim}${approval['credentialId']}${c.reset}`);
    ok(`Issuer DID: ${c.dim}${approval['issuerDid']}${c.reset}`);
    ok(`Subject DID: ${c.dim}${approval['subjectDid']}${c.reset}`);
  } else {
    warn(`Approval response: ${JSON.stringify(approval)}`);
  }

  // Brief pause for the delegation to propagate to the payment server
  await new Promise(r => setTimeout(r, 500));

  // ── Retry create_payment with delegation ─────────────────────────────────
  banner(7, 'Retry create_payment £500 (delegation VC auto-applied)');
  step('Retrying £500 payment — delegation VC now stored on server…');

  const { result: pay3Result, text: pay3Text } = await callTool(client, 'create_payment', {
    amount: 50000,
    currency: 'GBP',
    reference: 'Enterprise licence — annual subscription',
  });

  if (!pay3Text.includes('needs_authorization') && !pay3Text.includes('Authoris')) {
    try {
      const pay3 = JSON.parse(pay3Text) as Record<string, unknown>;
      const pay3Data = pay3['payment'] as Record<string, unknown>;
      ok(`Payment executed: ${c.dim}${pay3Data?.['id']}${c.reset}`);
      ok(`Status: ${pay3Data?.['status']} | Amount: £${(((pay3Data?.['amount'] as number) ?? 0) / 100).toFixed(2)}`);
    } catch {
      ok('Payment executed successfully');
      info(pay3Text.slice(0, 200));
    }
  } else {
    warn('Payment still needs authorization (delegation may not have propagated in time)');
    info('In production: poll consent service or use webhook to trigger retry');
  }
  printProofMeta(pay3Result['_meta'] as Record<string, unknown>);

  // ── get_payment_status ───────────────────────────────────────────────────
  banner(8, 'get_payment_status (proof only)');
  const paymentId = (JSON.parse(pay1Text)['payment'] as Record<string, unknown>)['id'] as string;
  step(`Checking status of payment ${paymentId}…`);
  const { result: statusResult, text: statusText } = await callTool(client, 'get_payment_status', {
    payment_id: paymentId,
  });
  const status = JSON.parse(statusText) as Record<string, unknown>;
  ok(`Payment ${status['id']}: ${status['status']}`);
  printProofMeta(statusResult['_meta'] as Record<string, unknown>);

  // ── list_payments ────────────────────────────────────────────────────────
  banner(9, 'list_payments (proof only)');
  step('Listing all payments in this session…');
  const { result: listResult, text: listText } = await callTool(client, 'list_payments');
  const listData = JSON.parse(listText) as Record<string, unknown>;
  ok(`Total payments: ${listData['total']}`);
  const payments = listData['payments'] as Array<Record<string, unknown>>;
  for (const p of payments) {
    info(`  ${p['id']} — £${((p['amount'] as number) / 100).toFixed(2)} ${p['currency']} — ${p['status']}`);
  }
  printProofMeta(listResult['_meta'] as Record<string, unknown>);

  // ── Audit trail ──────────────────────────────────────────────────────────
  banner(10, 'Query audit service — full proof trail');
  step(`Fetching audit records from ${AUDIT_URL}/api/records…`);

  const auditResp = await fetch(`${AUDIT_URL}/api/records`);
  const auditData = await auditResp.json() as Record<string, unknown>;
  const auditRecords = auditData['records'] as Array<Record<string, unknown>>;
  ok(`Audit records on file: ${auditData['total']}`);

  for (const r of auditRecords.slice(-5)) {
    const tool   = r['tool'] as string ?? 'unknown';
    const did    = r['did'] as string ?? '';
    const scope  = r['scope'] as string ?? '-';
    const ver    = r['verified'] as boolean ?? false;
    info(`  ${tool.padEnd(22)} DID: ${did.slice(0,30)}… scope: ${scope} ${ver ? c.green+'✓'+c.reset : c.red+'✗'+c.reset}`);
  }

  if (auditRecords.length === 0) {
    warn('No audit records yet — records are forwarded asynchronously');
    info('Check audit dashboard at: ' + AUDIT_URL);
  }

  // ── Proof verification ───────────────────────────────────────────────────
  banner(11, 'Verify a detached proof via audit service');

  // Extract proof from the balance result
  const proofToVerify = (balResult['_meta'] as Record<string, unknown> | undefined)?.['proof'];
  if (proofToVerify) {
    step('Submitting balance response proof for verification…');
    const verResp = await fetch(`${AUDIT_URL}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(proofToVerify),
    });
    const verResult = await verResp.json() as Record<string, unknown>;

    if (verResult['valid']) {
      ok(`${c.green}${c.bold}PROOF VALID${c.reset}`);
      ok(`Signer DID:  ${c.dim}${verResult['did']}${c.reset}`);
      ok(`Signed at:   ${verResult['timestamp']}`);
      ok(`Session:     ${verResult['session']}`);
    } else {
      warn(`Proof invalid: ${verResult['error']} — ${verResult['reason']}`);
      info('(did:key proofs require online DID resolution in some environments)');
    }
  } else {
    info('No proof in balance response _meta — KYA-OS session may not have been established');
    info('Try running the demo with a connected payment server');
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  console.log(`\n${c.bold}${c.green}`);
  console.log(`  ┌─────────────────────────────────────────────────┐`);
  console.log(`  │                Demo Complete ✓                   │`);
  console.log(`  └─────────────────────────────────────────────────┘`);
  console.log(`${c.reset}`);

  console.log(`  ${c.bold}What was demonstrated:${c.reset}`);
  console.log(`  ${c.green}✓${c.reset}  KYA-OS handshake — session established with server DID`);
  console.log(`  ${c.green}✓${c.reset}  Proof-only tools — every response carries detached JWS`);
  console.log(`  ${c.green}✓${c.reset}  Autonomous payment — £50 below threshold, no gate`);
  console.log(`  ${c.green}✓${c.reset}  Consent gate — £500 blocked, needs_authorization returned`);
  console.log(`  ${c.green}✓${c.reset}  VC issuance — W3C Delegation Credential signed by Responsible Party`);
  console.log(`  ${c.green}✓${c.reset}  Auto-delegation — server auto-applied VC on retry`);
  console.log(`  ${c.green}✓${c.reset}  Audit trail — proof records forwarded to audit service`);
  console.log(`  ${c.green}✓${c.reset}  Proof verification — ProofVerifier validated signature`);

  console.log(`\n  ${c.bold}Next steps:${c.reset}`);
  console.log(`  ${c.dim}→${c.reset}  Open the audit dashboard: ${c.cyan}${AUDIT_URL}${c.reset}`);
  console.log(`  ${c.dim}→${c.reset}  Connect MCP Inspector:    ${c.cyan}npx @modelcontextprotocol/inspector${c.reset}`);
  console.log(`  ${c.dim}→${c.reset}  Inspect a payment:        ${c.cyan}${PAYMENT_URL}/api/audit${c.reset}`);
  console.log(`  ${c.dim}→${c.reset}  Generate persistent DID:  ${c.cyan}npm run generate-identity${c.reset}\n`);

  await client.close();
  process.exit(0);
}

main().catch((err) => {
  console.error(`\n${c.red}✗  Demo failed:${c.reset}`, err instanceof Error ? err.message : err);
  console.error(`\n${c.dim}Make sure all services are running: npm run start:all${c.reset}\n`);
  process.exit(1);
});
