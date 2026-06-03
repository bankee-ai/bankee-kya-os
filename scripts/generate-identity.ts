#!/usr/bin/env npx tsx
/**
 * Generate a persistent Ed25519 identity for the payment server.
 *
 * Writes a did:key DID and its key pair to .kya-os/identity.json.
 * Both the payment server and consent service load this file on startup,
 * ensuring delegation VCs issued by the consent service are trusted by
 * the payment server (same Responsible Party DID).
 *
 * Usage:
 *   npm run generate-identity
 */

import fs from 'node:fs';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const IDENTITY_DIR  = '.kya-os';
const IDENTITY_PATH = path.join(IDENTITY_DIR, 'identity.json');

const crypto = new NodeCryptoProvider();
const keyPair = await crypto.generateKeyPair();
const did = generateDidKeyFromBase64(keyPair.publicKey);
const kid = `${did}#${did.replace('did:key:', '')}`;

const identity = { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };

fs.mkdirSync(IDENTITY_DIR, { recursive: true });
fs.writeFileSync(IDENTITY_PATH, JSON.stringify(identity, null, 2), { mode: 0o600 });

console.log(`\n✓  Identity written to ${IDENTITY_PATH}`);
console.log(`   DID:  ${did}`);
console.log(`   KID:  ${kid}`);
console.log(`\n   The payment server and consent service will load this on startup.\n`);
