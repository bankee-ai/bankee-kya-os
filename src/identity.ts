/**
 * Identity management: load a persisted DID or generate an ephemeral one.
 *
 * Persistent identity (created by `npm run generate-identity`):
 *   - Survives server restarts
 *   - Uses did:key derived from a stable Ed25519 key pair
 *   - Stored at IDENTITY_PATH (.kya-os/identity.json by default)
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

export async function loadOrGenerateIdentity(label = 'server'): Promise<AgentIdentityConfig> {
  const crypto = new NodeCryptoProvider();

  if (fs.existsSync(IDENTITY_PATH)) {
    const stored = JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8')) as AgentIdentityConfig;
    process.stderr.write(`[${label}] Loaded identity: ${stored.did}\n`);
    return stored;
  }

  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const identity: AgentIdentityConfig = {
    did,
    kid,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };

  process.stderr.write(`[${label}] Generated ephemeral identity: ${did}\n`);
  process.stderr.write(`[${label}] Run 'npm run generate-identity' to persist across restarts\n`);

  return identity;
}
