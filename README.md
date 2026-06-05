# bankee-kya-os

[![DIF TAAWG](https://img.shields.io/badge/DIF-TAAWG%20Protocol-0066cc?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQxIDAtOC0zLjU5LTgtOHMzLjU5LTggOC04IDggMy41OSA4IDgtMy41OSA4LTggOHoiLz48L3N2Zz4=)](https://github.com/decentralized-identity/kya-os-mcp)
[![KYA-OS](https://img.shields.io/badge/KYA--OS-MCP%20Binding-635bff)](https://github.com/bankee-ai/kya-os-mcp)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](LICENSE)
[![DIF Member](https://img.shields.io/badge/DIF-Contributing%20Member-003366)](https://identity.foundation)

End-to-end agentic payment infrastructure built on [KYA-OS](https://github.com/decentralized-identity/kya-os-mcp) — the DIF TAAWG protocol that gives AI agents cryptographic identity, delegation authority, and tamper-evident proof of every action they take. Every payment tool call produces a detached JWS signed by `did:web:bankee.ai`, every high-value transaction requires a human-approved W3C Verifiable Credential before it executes, and every proof is forwarded to an append-only audit service where it can be independently verified — in real time or years later.

---

## Table of Contents

- [What KYA-OS gives you](#what-kya-os-gives-you)
- [Architecture](#architecture)
- [Services at a glance](#services-at-a-glance)
- [Quick start](#quick-start)
- [Demo walkthrough](#demo-walkthrough)
- [Proof structure](#proof-structure)
- [Verifiable Credential structure](#verifiable-credential-structure)
- [API reference](#api-reference)
- [Environment variables](#environment-variables)
- [Identity management](#identity-management)
- [Deployment](#deployment)
- [Connecting to OpenClaw agents](#connecting-to-openclaw-agents)
- [Contributing / DIF TAAWG](#contributing--dif-taawg)
- [Links](#links)

---

## What KYA-OS gives you

KYA-OS is the MCP binding of the [DIF TAAWG](https://identity.foundation/working-groups/trust-and-agent-authorization.html) (Trust and Agent Authorization Working Group) specification. It adds three cryptographic primitives on top of any MCP server, with zero changes to the tools themselves:

| Primitive | How it works | What it prevents |
|---|---|---|
| **Cryptographic identity** | Every server has a stable DID (`did:web` in production, `did:key` in dev). The DID document is published at `/.well-known/did.json` and holds the Ed25519 public key. Clients verify they are talking to the claimed identity before the first tool call. | Agent impersonation; MITM attacks on the MCP channel |
| **Delegation authority** | Tools above a configurable threshold are wrapped with `wrapWithDelegation`. Without a W3C Verifiable Credential bearing the correct scope, the tool returns `needs_authorization` and a consent URL. A human approves once; the VC is stored server-side and auto-applied on retry. Sub-delegation lets a VC holder delegate narrower authority to a child agent. | Autonomous over-limit payments; unauthorized scope escalation |
| **Tamper-evident proof** | Every tool response carries a detached JWS in `_meta.proof`. The JWS covers SHA-256 hashes of both the request and the response, the session ID, a timestamp, and a nonce. The audit service stores every proof record and exposes a `/api/verify` endpoint for independent verification. | Repudiation; undetected response tampering; replay attacks |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Client / AI agent                                                   │
│  (OpenClaw agent, MCP Inspector, demo-agent.ts, any MCP client)     │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  SSE  /sse  ·  Streamable HTTP  /mcp
                            ▼
        ┌───────────────────────────────────┐
        │  Payment MCP Server  :3001        │  ← bankee-payment
        │                                   │
        │  Tools:                           │
        │    get_balance           (proof)  │
        │    get_exchange_rate     (proof)  │
        │    list_payments         (proof)  │
        │    get_payment_status    (proof)  │
        │    create_payment  ≤£100 (proof)  │
        │    create_payment  >£100 (gate)   │──────────────────────┐
        │                                   │                      │
        │  Identity: did:web:bankee.ai      │                      │
        │  Key: Ed25519 (persisted volume)  │                      │
        └──────────────┬────────────────────┘                      │
                       │  POST /api/records  (proof audit)         │
                       │  POST /api/delegations/:token  (VC store) │
                       ▼                    ▲                      ▼
        ┌──────────────────────┐   ┌────────────────────────────────────┐
        │  Audit Service :3003 │   │  Consent & VC Service  :3002       │
        │                      │   │                                    │
        │  POST /api/records   │   │  GET  /consent          (UI)       │
        │  GET  /api/records   │   │  POST /api/approve      (issue VC) │
        │  POST /api/verify    │   │  POST /api/revoke/:id   (revoke)   │
        │  GET  /  (dashboard) │   │  GET  /api/status-list  (SL2021)   │
        │                      │   │  POST /api/delegate     (sub-del)  │
        │  Trusted DID key     │   │                                    │
        │  cache (no outbound  │   │  Same DID as payment server        │
        │  DID resolution)     │   │  (shared Responsible Party)        │
        └──────────────────────┘   └────────────────────────────────────┘

        ┌──────────────────────────────────────────────────────────────┐
        │  Web UI  :3010                                               │
        │                                                              │
        │  /           Dashboard     /payments  Payment history        │
        │  /audit      Audit trail   /consent   Consent management     │
        │  /verify     Proof tool    /identity  DID + session info     │
        └──────────────────────────────────────────────────────────────┘

Networks:
  bankee-kya-os_net       — internal service mesh (all 4 containers)
  ai-stack_openclaw_net   — external join
                            lets OpenClaw agents reach bankee-payment:3001

Volumes:
  bankee-kya-os_identity  — Ed25519 key pair + DID, persisted across restarts
```

---

## Services at a glance

| Service | Port | Container | Purpose |
|---|---|---|---|
| Payment MCP Server | 3001 | `bankee-payment` | MCP server; 5 payment tools; JWS proof on every response; consent gate on high-value calls |
| Consent & VC Service | 3002 | `bankee-consent` | Human approval UI; W3C VC issuance; StatusList2021 revocation; sub-delegation |
| Audit Service | 3003 | `bankee-audit` | Proof record ingestion; query API; independent proof verification; live HTML dashboard |
| Web UI | 3010 | `bankee-kya-os-ui` | Management dashboard; 6 pages; proxies to all three backend services |

---

## Quick start

**Prerequisites:** Docker, Docker Compose, Node.js 20+ (for running the demo agent outside Docker).

### 1. Clone

```bash
git clone https://github.com/bankee-ai/bankee-kya-os.git
cd bankee-kya-os
```

### 2. Generate a persistent identity

This creates an Ed25519 key pair and writes it to `.kya-os/identity.json`. Both the payment server and the consent service load from this file on startup so they share a single Responsible Party DID.

```bash
npm install
npm run generate-identity
```

Output:

```
✓  Identity written to .kya-os/identity.json
   DID:  did:key:z6Mk...
   KID:  did:key:z6Mk...#z6Mk...

   The payment server and consent service will load this on startup.
```

Skip this step if you want ephemeral identities (fresh key pair every restart). Note that existing delegation VCs become invalid after a restart with an ephemeral identity.

### 3. Start the services

```bash
docker-compose up -d
```

Four containers start: `bankee-payment`, `bankee-consent`, `bankee-audit`, and `bankee-kya-os-ui`.

Health checks:

```bash
curl http://localhost:3001/   # payment server info + DID
curl http://localhost:3002/   # consent service stats
curl http://localhost:3003/   # audit service
open http://localhost:3010    # web dashboard
```

### 4. Run the demo agent

```bash
# Starts all services (if not already running) then runs the demo
npm run demo

# Or, if Docker services are already up:
npx tsx src/demo-agent.ts
```

### 5. Connect MCP Inspector

```bash
npx @modelcontextprotocol/inspector http://localhost:3001/mcp
```

---

## Demo walkthrough

The demo agent (`src/demo-agent.ts`) runs 11 steps that exercise every KYA-OS feature end to end. Below is the actual output from a clean run on 2026-06-05.

```
  ██████╗  █████╗ ███╗   ██╗██╗  ██╗███████╗███████╗
  ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██╔════╝██╔════╝
  ██████╔╝███████║██╔██╗ ██║█████╔╝ █████╗  █████╗
  ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██╔══╝  ██╔══╝
  ██████╔╝██║  ██║██║ ╚████║██║  ██╗███████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝

  KYA-OS End-to-End Payment Infrastructure Demo
  Identity · Delegation · Proof · Consent · Audit
```

---

**Step 0: Waiting for services**

Services are polled on startup with exponential back-off. The demo does not proceed until all three backend services respond on their health endpoints.

```
  ✓ Payment server is ready — DID: did:web:bankee.ai
  ✓ Consent service is ready
  ✓ Audit service is ready
  ℹ Payment server DID: did:web:bankee.ai
  ℹ High-value threshold: £100.00
```

---

**Step 1: Connect MCP client + KYA-OS handshake**

The demo agent connects to the payment server over SSE transport (`/sse`), then calls the built-in `_kyaos` tool to perform the session handshake. The server responds with a session ID that is embedded in every subsequent proof.

```
  → Connecting to payment server via SSE…
  ✓ Connected via SSE transport
  → Performing KYA-OS session handshake…
  ✓ KYA-OS session established: kyaos_39e5b35c-f1b8-43e3-8ed4-bdf0617a817d
```

The handshake binds the agent's DID and a client nonce to the session. Every subsequent proof carries this session ID, making replays detectable.

---

**Step 2: get_balance (proof only)**

No delegation required. The tool executes immediately and the response carries a detached JWS in `_meta.proof`.

```
  → Calling get_balance…
  ✓ Balance: £1250.00 available, £32.00 pending
  🔏 Proof attached:
      DID:      did:web:bankee.ai
      Session:  kyaos_39e5b35c…
      Req hash: sha256:get_balance…
      Res hash: sha256:125000…
```

---

**Step 3: get_exchange_rate (proof only)**

```
  → Calling get_exchange_rate GBP/USDC…
  ✓ GBP/USDC rate: 1.265
  🔏 Proof attached:
      DID:      did:web:bankee.ai
      Session:  kyaos_39e5b35c…
```

---

**Step 4: create_payment £50 (autonomous — below threshold)**

Payments at or below the `HIGH_VALUE_THRESHOLD` (default 10,000 minor units = £100.00) execute autonomously — proof only, no consent gate.

```
  → Creating £50 payment — no consent required…
  ✓ Payment created: pay_1780657765156_ytmgzs
  ✓ Status: completed | Amount: £50.00
  ✓ Agent DID in payment record: did:web:bankee.ai…
  🔏 Proof attached:
      DID:      did:web:bankee.ai
      Session:  kyaos_39e5b35c…
```

---

**Step 5: create_payment £500 (high-value — consent required)**

The `create_payment` tool is wrapped with `wrapWithDelegation`. A £500 payment (50,000 minor units) exceeds the threshold. Without a Delegation VC the tool returns `needs_authorization` with a consent URL and a `resume_token`.

```
  → Attempting £500 payment — expecting needs_authorization…
  ⚠ Payment blocked: needs_authorization
  ℹ Consent URL: http://localhost:3002/consent?tool=create_payment
                 &scopes=payments%3Awrite&agent_did=did%3Aweb%3Abankee.ai
                 &resume_token=3bc697c0-61b6…
  ℹ Resume token: 3bc697c0-61b6…
```

The agent presents the consent URL to the operator. Nothing executes until a human approves.

---

**Step 6: Human approves via consent service**

The operator (or, in the demo, an automated call) visits the consent UI or calls `POST /api/approve` directly. The consent service:

1. Issues a W3C Delegation Credential signed by `did:web:bankee.ai`
2. Assigns it a StatusList2021 index for future revocation
3. POSTs the VC to the payment server at `/api/delegations/:resume_token`

```
  → Operator approving payment via consent service API…
  ✓ Delegation VC issued: delegation-1780657765174-647rnk
  ✓ Issuer DID: did:web:bankee.ai
  ✓ Subject DID: did:web:bankee.ai
```

---

**Step 7: Retry create_payment £500 (delegation VC auto-applied)**

The agent retries the exact same tool call without any changes. The payment server detects the stored VC for `create_payment`, auto-applies it, and the tool executes.

```
  → Retrying £500 payment — delegation VC now stored on server…
  ✓ Payment executed: pay_1780657765698_rk9mz2
  ✓ Status: completed | Amount: £500.00
  🔏 Proof attached (now includes delegation scope):
      DID:      did:web:bankee.ai
      Session:  kyaos_39e5b35c…
```

---

**Step 8: get_payment_status (proof only)**

```
  → Checking status of payment pay_1780657765156_ytmgzs…
  ✓ Payment pay_1780657765156_ytmgzs: completed
  🔏 Proof attached
```

---

**Step 9: list_payments (proof only)**

```
  → Listing all payments in this session…
  ✓ Total payments: 2
  ℹ   pay_1780657765156_ytmgzs — £50.00 GBP — completed
  ℹ   pay_1780657765698_rk9mz2 — £500.00 GBP — completed
```

---

**Step 10: Query audit service — full proof trail**

```
  → Fetching audit records from http://localhost:3003/api/records…
  ✓ Audit records on file: 4
  ℹ   get_balance            DID: did:web:bankee.ai… scope: - ✓
  ℹ   get_exchange_rate      DID: did:web:bankee.ai… scope: - ✓
  ℹ   create_payment         DID: did:web:bankee.ai… scope: - ✓
  ℹ   create_payment         DID: did:web:bankee.ai… scope: payments:write ✓
```

---

**Step 11: Verify a detached proof via audit service**

The demo extracts the raw `_meta.proof` object from the `get_balance` response and submits it to `POST /api/verify`. The audit service verifies the Ed25519 signature against the pre-loaded trusted public key for `did:web:bankee.ai` — no outbound DID resolution required.

```
  → Submitting balance response proof for verification…
  ✓ PROOF VALID
  ✓ Signer DID:  did:web:bankee.ai
  ✓ Signed at:   2026-06-05T11:09:25.000Z
  ✓ Session:     kyaos_39e5b35c-f1b8-43e3-8ed4-bdf0617a817d
```

---

**Demo complete**

```
  ┌─────────────────────────────────────────────────┐
  │                Demo Complete ✓                   │
  └─────────────────────────────────────────────────┘

  ✓  KYA-OS handshake — session established with server DID
  ✓  Proof-only tools — every response carries detached JWS
  ✓  Autonomous payment — £50 below threshold, no gate
  ✓  Consent gate — £500 blocked, needs_authorization returned
  ✓  VC issuance — W3C Delegation Credential signed by Responsible Party
  ✓  Auto-delegation — server auto-applied VC on retry
  ✓  Audit trail — proof records forwarded to audit service
  ✓  Proof verification — ProofVerifier validated signature
```

---

## Proof structure

Every tool response (whether the tool succeeds, is blocked, or returns an error) carries a detached JWS proof in `_meta.proof`. The JWS is signed with the server's Ed25519 private key.

```json
{
  "jws": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YmFua2VlLmFpI2tleS0xIn0..<sig>",
  "meta": {
    "did": "did:web:bankee.ai",
    "kid": "did:web:bankee.ai#key-1",
    "ts": 1780657765,
    "nonce": "xK9mP2vQs7rTnL4w",
    "sessionId": "kyaos_39e5b35c-f1b8-43e3-8ed4-bdf0617a817d",
    "requestHash": "sha256:c66cf361137f40cf8b506cd74b0f3e9a2d1c8547f2a19e3b4d05726a8c1f3e9",
    "responseHash": "sha256:f9e1a5316cc6abf511f3c8247d0e93b5e4c2d1a0f78356e9c142b0d57a2f8c4"
  }
}
```

| Field | Description |
|---|---|
| `jws` | Compact detached JWS (RFC 7515). Algorithm: `EdDSA`. The payload is the canonical JSON of `meta`. |
| `meta.did` | The server's DID — the Responsible Party for this action. |
| `meta.kid` | Key ID within the DID document used to produce the signature. |
| `meta.ts` | Unix timestamp (seconds) at signing time. |
| `meta.nonce` | 16-byte random nonce. The audit service caches nonces to reject replays. |
| `meta.sessionId` | KYA-OS session established during the handshake. Ties all proofs in a session together. |
| `meta.requestHash` | SHA-256 of the canonical tool request (tool name + arguments). |
| `meta.responseHash` | SHA-256 of the canonical tool response. Detects response tampering in transit. |

**Verifying offline:**

```bash
curl -s http://localhost:3003/api/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "jws": "eyJ...",
    "meta": {
      "did": "did:web:bankee.ai",
      "kid": "did:web:bankee.ai#key-1",
      "ts": 1780657765,
      "nonce": "xK9mP2vQs7rTnL4w",
      "sessionId": "kyaos_39e5b35c-f1b8-43e3-8ed4-bdf0617a817d",
      "requestHash": "sha256:...",
      "responseHash": "sha256:..."
    }
  }'
```

```json
{
  "valid": true,
  "did": "did:web:bankee.ai",
  "kid": "did:web:bankee.ai#key-1",
  "timestamp": "2026-06-05T11:09:25.000Z",
  "session": "kyaos_39e5b35c-f1b8-43e3-8ed4-bdf0617a817d"
}
```

---

## Verifiable Credential structure

When a human approves a high-value payment the consent service issues a W3C Verifiable Credential (VC) with an embedded `Ed25519Signature2020` proof. The VC is a standard JSON-LD document — any W3C VC-compatible verifier can process it.

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "delegation-1780657765174-647rnk",
  "type": ["VerifiableCredential", "KyaOsDelegationCredential"],
  "issuer": "did:web:bankee.ai",
  "issuanceDate": "2026-06-05T11:09:25.174Z",
  "expirationDate": "2026-06-05T12:09:25.174Z",
  "credentialSubject": {
    "id": "did:web:bankee.ai",
    "delegation": {
      "scopeId": "payments:write",
      "scopes": ["payments:write"],
      "notAfter": 1780661365,
      "metadata": {
        "tool": "create_payment",
        "approvedAt": "2026-06-05T11:09:25.174Z",
        "approvedBy": "did:web:bankee.ai"
      }
    }
  },
  "credentialStatus": {
    "id": "https://bankee.ai:3002/api/status-list#4",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "4",
    "statusListCredential": "https://bankee.ai:3002/api/status-list"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-06-05T11:09:25.174Z",
    "verificationMethod": "did:web:bankee.ai#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5Q7YLtJ3Km9..."
  }
}
```

| Field | Description |
|---|---|
| `issuer` | The Responsible Party DID. Always `did:web:bankee.ai` in production. |
| `credentialSubject.id` | The agent DID being granted authority. |
| `credentialSubject.delegation.scopes` | List of authorized scopes (e.g. `payments:write`). |
| `credentialSubject.delegation.notAfter` | Unix expiry timestamp. Default TTL: 3600 seconds (configurable via `DELEGATION_TTL_SECONDS`). |
| `credentialStatus` | [StatusList2021](https://w3c.github.io/vc-status-list-2021/) entry. Verifiers fetch `statusListCredential` to check revocation without calling the issuer. |
| `proof.proofValue` | Base64url-encoded Ed25519 signature over the canonical VC JSON. |

**Revoking a VC:**

```bash
curl -X POST http://localhost:3002/api/revoke/delegation-1780657765174-647rnk

# The StatusList2021 bit at index 4 is flipped. Verifiers fetching
# /api/status-list will see the credential as revoked immediately.
```

**Sub-delegation (multi-hop):**

An agent that holds a valid VC can request a narrower credential for a child agent. The consent service enforces that requested scopes are a strict subset of the parent VC's scopes.

```bash
curl -X POST http://localhost:3002/api/delegate \
  -H 'Content-Type: application/json' \
  -d '{
    "parentVcId": "delegation-1780657765174-647rnk",
    "subjectDid": "did:key:z6MkChildAgent...",
    "scopes": "payments:write",
    "tool": "create_payment"
  }'
```

The child VC carries `metadata.delegationDepth: 1` and references the parent via `metadata.parentVcId`. Revocation of the parent does not automatically revoke children — revoke each explicitly, or set short TTLs.

---

## API reference

### Payment MCP Server — port 3001

| Route | Method | Description |
|---|---|---|
| `/` | GET | Health check. Returns DID, threshold, transport URLs. |
| `/sse` | GET | Open SSE transport (for MCP clients). |
| `/messages` | POST | Post a message on the current SSE session. |
| `/mcp` | POST | Streamable HTTP transport (MCP Inspector compatible). |
| `/api/delegations/:token` | POST | Store an approved delegation VC (called by consent service). |
| `/api/audit` | GET | Return all in-process audit records. |

**MCP tools:**

| Tool | Args | Delegation required |
|---|---|---|
| `_kyaos` | `type`, `nonce`, `audience`, `timestamp`, `agentDid` | No — KYA-OS handshake |
| `get_balance` | — | No |
| `get_exchange_rate` | `pair` (e.g. `GBP/USD`) | No |
| `list_payments` | — | No |
| `get_payment_status` | `payment_id` | No |
| `create_payment` | `amount` (minor units), `currency`, `reference` | Yes, if `amount > HIGH_VALUE_THRESHOLD` |

---

### Consent & VC Service — port 3002

| Route | Method | Description |
|---|---|---|
| `/` | GET | Health check. Returns issuer DID, counts, status list URL. |
| `/consent` | GET | Human approval UI. Query params: `tool`, `scopes`, `agent_did`, `resume_token`. |
| `/api/approve` | POST | Issue a Delegation VC and notify the payment server. Body: `{ tool, scopes, agentDid, resumeToken }`. |
| `/api/credentials` | GET | List all issued VCs with revocation status. |
| `/api/credentials/:id` | GET | Retrieve a specific VC with status metadata. |
| `/api/revoke/:id` | POST | Revoke a VC via StatusList2021. |
| `/api/status-list` | GET | W3C StatusList2021 credential (gzip-encoded bitstring). |
| `/api/delegate` | POST | Issue a sub-delegation VC. Body: `{ parentVcId, subjectDid, scopes, tool? }`. |

---

### Audit Service — port 3003

| Route | Method | Description |
|---|---|---|
| `/` | GET | Live HTML audit dashboard (auto-refreshes every 5s). |
| `/api/records` | POST | Ingest a proof record from the payment server. |
| `/api/records` | GET | Query records. Optional filters: `?did=`, `?tool=`, `?limit=`. |
| `/api/records/:id` | GET | Retrieve a single record by ID. |
| `/api/verify` | POST | Verify a detached JWS proof. Body: `DetachedProof` object. |

---

### Web UI — port 3010

| Route | Description |
|---|---|
| `/` | System dashboard: health stats for all three services. |
| `/payments` | Payment history from the payment server. |
| `/audit` | Full audit trail with proof status indicators. |
| `/consent` | Issued VCs, revocation controls, sub-delegation form. |
| `/verify` | Paste a raw proof object and verify it in-browser. |
| `/identity` | Server DID, current session info, public key. |
| `/api/*` | Transparent proxy to the backend services. |

---

## Environment variables

### Payment server

| Variable | Default | Description |
|---|---|---|
| `PAYMENT_SERVER_PORT` | `3001` | Listening port. |
| `CONSENT_SERVICE_URL` | `http://localhost:3002` | URL of the consent service (used to build consent URLs). |
| `AUDIT_SERVICE_URL` | `http://localhost:3003` | URL of the audit service (proof records are POSTed here). |
| `HIGH_VALUE_THRESHOLD` | `10000` | Payments above this many minor units require a Delegation VC. Default = £100.00. |
| `IDENTITY_DID` | _(none)_ | Override the DID. Set to `did:web:bankee.ai` in production. |
| `IDENTITY_PATH` | `.kya-os/identity.json` | Path to the persisted identity file. |

### Consent & VC service

| Variable | Default | Description |
|---|---|---|
| `CONSENT_SERVICE_PORT` | `3002` | Listening port. |
| `PAYMENT_SERVER_URL` | `http://localhost:3001` | Used to POST delegation VCs after approval. |
| `DELEGATION_TTL_SECONDS` | `3600` | How long issued VCs remain valid (1 hour). |
| `IDENTITY_DID` | _(none)_ | Override the DID. Must match the payment server's DID. |
| `IDENTITY_PATH` | `.kya-os/identity.json` | Shared with the payment server — same key pair. |
| `STATUS_LIST_URL` | `http://localhost:3002/api/status-list` | Public URL embedded in VC `credentialStatus`. Set to your externally reachable URL in production. |

### Audit service

| Variable | Default | Description |
|---|---|---|
| `AUDIT_SERVICE_PORT` | `3003` | Listening port. |
| `TRUSTED_DID` | _(none)_ | A DID whose public key should be pre-loaded (avoids outbound DID resolution). |
| `TRUSTED_PUBLIC_KEY_B64` | _(none)_ | Standard Base64-encoded Ed25519 public key for `TRUSTED_DID`. |
| `TRUSTED_DID_JWKS` | _(none)_ | JSON map `{ "did:web:example.com": { "kty": "OKP", "crv": "Ed25519", "x": "..." } }` for multiple trusted DIDs. |

### Web UI

| Variable | Default | Description |
|---|---|---|
| `WEB_UI_PORT` | `3010` | Listening port. |
| `PAYMENT_SERVER_URL` | `http://localhost:3001` | Backend URL for payment data. |
| `CONSENT_SERVICE_URL` | `http://localhost:3002` | Backend URL for consent data. |
| `AUDIT_SERVICE_URL` | `http://localhost:3003` | Backend URL for audit data. |

---

## Identity management

### Development (ephemeral)

By default each service generates a fresh Ed25519 key pair at startup. This is convenient for development but means delegation VCs become invalid across restarts.

### Development (persistent did:key)

```bash
npm run generate-identity
# Writes .kya-os/identity.json
# Mount this file into containers via the ./identity volume in docker-compose.yml
```

The `did:key` DID is derived directly from the Ed25519 public key. It resolves offline — no DNS, no external registry.

### Production (did:web)

Set `IDENTITY_DID=did:web:bankee.ai` on both the payment server and consent service. The existing Ed25519 key pair from `bankee-kya-os_identity` volume is reused; only the DID identifier changes to the `did:web` form.

The DID document must be published at `https://bankee.ai/.well-known/did.json`:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:bankee.ai",
  "verificationMethod": [{
    "id": "did:web:bankee.ai#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:bankee.ai",
    "publicKeyJwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url public key>"
    }
  }],
  "assertionMethod": ["did:web:bankee.ai#key-1"],
  "authentication": ["did:web:bankee.ai#key-1"]
}
```

Bankee's live DID document: [https://bankee.ai/.well-known/did.json](https://bankee.ai/.well-known/did.json)

---

## Deployment

The Bankee.ai dev environment is a dedicated machine running Docker, accessible across the Bankee infrastructure via Tailscale.

The production overlay (`docker-compose.trapdoor.yml`) extends the base compose file with:

- `IDENTITY_DID=did:web:bankee.ai` on all services
- `bankee-kya-os_identity` Docker volume (external, pre-populated once) for the persisted Ed25519 key pair
- Audit service pre-loaded with the trusted public key — no outbound DID resolution from inside Docker
- Web UI bound to Tailscale IP and localhost on port 3010
- Payment server joined to `ai-stack_openclaw_net` (see next section)

**First-time setup:**

```bash
# 1. Create the identity volume
docker volume create bankee-kya-os_identity

# 2. Generate the identity and copy it into the volume
npm run generate-identity
docker run --rm \
  -v bankee-kya-os_identity:/dest \
  -v "$(pwd)/.kya-os":/src \
  alpine cp /src/identity.json /dest/identity.json

# 3. Start with the dev environment overlay
docker-compose -f docker-compose.yml -f docker-compose.trapdoor.yml up -d

# 4. Verify
curl http://localhost:3001/ | jq .did
# → "did:web:bankee.ai"
```

**Access from other Tailscale nodes:**

```
Web UI:       http://<tailscale-ip>:3010
Audit dash:   http://<tailscale-ip>:3003
Payment MCP:  http://<tailscale-ip>:3001/sse
```

**Updating the trusted public key in the audit service:**

After regenerating the identity, extract the new public key and update the compose env var:

```bash
# Get the standard Base64 public key from the identity file
node -e "
  const f = require('fs');
  const id = JSON.parse(f.readFileSync('.kya-os/identity.json', 'utf-8'));
  console.log(Buffer.from(id.publicKey, 'base64url').toString('base64'));
"

# Set TRUSTED_PUBLIC_KEY_B64=<output> in docker-compose.trapdoor.yml, then:
docker-compose -f docker-compose.yml -f docker-compose.trapdoor.yml restart audit-service
```

---

## Connecting to OpenClaw agents

In production Bankee.ai dev environment runs the [OpenClaw](https://github.com/bankee-ai/openclaw) AI agent orchestrator. The payment server joins the `ai-stack_openclaw_net` Docker network in the dev environment overlay, making it reachable at `bankee-payment:3001` from within the OpenClaw network.

OpenClaw agent configuration example:

```json
{
  "mcpServers": {
    "bankee-payment": {
      "transport": "sse",
      "url": "http://bankee-payment:3001/sse"
    }
  }
}
```

Or from outside Docker (e.g., a Claude Desktop instance on the same Tailscale network):

```json
{
  "mcpServers": {
    "bankee-payment": {
      "transport": "sse",
      "url": "http://<tailscale-ip>:3001/sse"
    }
  }
}
```

The agent will receive `needs_authorization` responses for payments above £100 and must surface the consent URL to a human operator. A future version will integrate with OpenClaw's notification channels to route approval requests automatically.

---

## Contributing / DIF TAAWG

Bankee is a contributing member of the [Decentralized Identity Foundation](https://identity.foundation) and participates in the [Trust and Agent Authorization Working Group (TAAWG)](https://identity.foundation/working-groups/trust-and-agent-authorization.html), which owns the KYA-OS specification.

### How this repo relates to upstream

| Repo | Role |
|---|---|
| [`decentralized-identity/kya-os-mcp`](https://github.com/decentralized-identity/kya-os-mcp) | Upstream DIF TAAWG spec + reference implementation |
| [`bankee-ai/kya-os-mcp`](https://github.com/bankee-ai/kya-os-mcp) | Bankee's fork — publishes `@kya-os/mcp` on npm; implements payment-domain extensions |
| [`bankee-ai/bankee-kya-os`](https://github.com/bankee-ai/bankee-kya-os) | This repo — end-to-end payment infrastructure consuming `@kya-os/mcp` |

### Contributing to the spec

Issues and pull requests relating to the core KYA-OS protocol (proof format, delegation credential schema, handshake flow, StatusList2021 integration) should be opened against [decentralized-identity/kya-os-mcp](https://github.com/decentralized-identity/kya-os-mcp). Join the TAAWG working group calls to participate in the standards process.

### Contributing to this repo

Issues and pull requests are welcome. Areas of active development:

- **Persistent storage** — swap `MemoryAuditLogProvider` for a Postgres- or S3-backed provider
- **VC-JWT support** — `DelegationIssuerFactory.issueAsJWT` is implemented; wire it into the consent service approval flow
- **Webhook retry** — proof forwarding to the audit service is fire-and-forget; add retry with exponential back-off
- **OpenClaw integration** — automatic consent-request routing via OpenClaw notification channels
- **Agent-initiated sub-delegation** — let agents request child credentials without operator involvement for pre-approved scope trees

```bash
git clone https://github.com/bankee-ai/bankee-kya-os.git
cd bankee-kya-os
npm install
npm run typecheck      # type-check without building
npm run start:all      # start all 4 services locally (no Docker)
npx tsx src/demo-agent.ts
```

---

## Links

| | |
|---|---|
| This repo | [github.com/bankee-ai/bankee-kya-os](https://github.com/bankee-ai/bankee-kya-os) |
| KYA-OS MCP fork | [github.com/bankee-ai/kya-os-mcp](https://github.com/bankee-ai/kya-os-mcp) |
| DIF TAAWG spec | [github.com/decentralized-identity/kya-os-mcp](https://github.com/decentralized-identity/kya-os-mcp) |
| Bankee DID document | [bankee.ai/.well-known/did.json](https://bankee.ai/.well-known/did.json) |
| Bankee website | [bankee.ai](https://bankee.ai) |
| DIF TAAWG working group | [identity.foundation/working-groups/trust-and-agent-authorization](https://identity.foundation/working-groups/trust-and-agent-authorization.html) |

---

*Bankee is a [DIF contributing member](https://identity.foundation). KYA-OS is a [DIF TAAWG](https://identity.foundation/working-groups/trust-and-agent-authorization.html) protocol.*
