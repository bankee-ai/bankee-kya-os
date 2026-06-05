/**
 * Identity management: load a persisted DID or generate an ephemeral one.
 *
 * Persistent identity (created by `npm run generate-identity`):
 *   - Survives server restarts
 *   - Uses did:key derived from a stable Ed25519 key pair
 *   - Stored at IDENTITY_PATH (.kya-os/identity.json by default)
 *
 * did:web override (production):
 *   - Set IDENTITY_DID=did:web:bankee.ai (or any did:web)
 *   - The existing Ed25519 key pair is reused; only the DID identifier changes
 *   - The DID document must be published at https://<domain>/.well-known/did.json
 *   - Bankee's DID document: https://bankee.ai/.well-known/did.json
 *
 * Ephemeral identity (default):
 *   - Fresh key pair on every startup
 *   - Convenient for development and demos
 *   - Existing delegation VCs become invalid after restart
 */

import fs from 'node:fs';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import type { AgentIdentityConfig } from './delegation-issuer.js';

const IDENTITY_PATH = path.resolve(
  process.env['IDENTITY_PATH'] ?? '.kya-os/identity.json',
);

/** Override DID to did:web while reusing the existing key pair. */
function applyDidWebOverride(identity: AgentIdentityConfig): AgentIdentityConfig {
  const override = process.env['IDENTITY_DID'];
  if (!override) return identity;
  if (!override.startsWith('did:web:') && !override.startsWith('did:key:')) {
    process.stderr.write(`[identity] Warning: IDENTITY_DID "${override}" is not a recognised DID method — ignoring\n`);
    return identity;
  }
  if (override === identity.did) return identity;
  // For did:web the kid convention is <did>#key-1
  const kid = override.startsWith('did:web:') ? `${override}#key-1` : identity.kid;
  process.stderr.write(`[identity] Overriding DID: ${identity.did} → ${override}\n`);
  return { ...identity, did: override, kid };
}

export async function loadOrGenerateIdentity(label = 'server'): Promise<AgentIdentityConfig> {
  const crypto = new NodeCryptoProvider();

  if (fs.existsSync(IDENTITY_PATH)) {
    const stored = JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8')) as AgentIdentityConfig;
    const identity = applyDidWebOverride(stored);
    process.stderr.write(`[${label}] Loaded identity: ${identity.did}\n`);
    return identity;
  }

  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const base: AgentIdentityConfig = { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
  const identity = applyDidWebOverride(base);

  process.stderr.write(`[${label}] Generated ephemeral identity: ${identity.did}\n`);
  process.stderr.write(`[${label}] Run 'npm run generate-identity' to persist across restarts\n`);

  return identity;
}
