/**
 * Delegation Issuer Factory
 *
 * Creates a DelegationCredentialIssuer from a KYA-OS identity config.
 * Used by the consent service to issue W3C Delegation Credentials (VCs)
 * when a human approves a high-value payment request.
 *
 * Supports two credential formats:
 *   - Embedded proof (Ed25519Signature2020) — standard W3C VC as JSON
 *   - VC-JWT — compact JWT string (header.payload.signature)
 *
 * Ported from the KYA-OS consent-basic reference implementation.
 * Spec: KYA-OS §3.1 (VC structure), §4.1 (DelegationRecord)
 */

import {
  DelegationCredentialIssuer,
  base64urlEncodeFromBytes,
  createUnsignedVCJWT,
  completeVCJWT,
  type VCSigningFunction,
  type Proof,
  type CryptoProvider,
} from '@kya-os/mcp';

export interface AgentIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;  // base64url-encoded Ed25519 private key seed
  publicKey: string;   // base64url-encoded Ed25519 public key
}

export interface DelegationIssuerFactory {
  issuer: DelegationCredentialIssuer;
  identity: AgentIdentityConfig;
  /** Issue a delegation credential as a VC-JWT compact string. */
  issueAsJWT: (
    params: Parameters<DelegationCredentialIssuer['createAndIssueDelegation']>[0],
    options?: Parameters<DelegationCredentialIssuer['createAndIssueDelegation']>[1],
  ) => Promise<string>;
}

export function createDelegationIssuerFromIdentity(
  crypto: CryptoProvider,
  identity: AgentIdentityConfig,
): DelegationIssuerFactory {
  // Signing function: Ed25519Signature2020 embedded proof
  const signingFunction: VCSigningFunction = async (
    canonicalVC: string,
    _issuerDid: string,
    kid: string,
  ): Promise<Proof> => {
    const data = new TextEncoder().encode(canonicalVC);
    const sigBytes = await crypto.sign(data, identity.privateKey);
    const proofValue = base64urlEncodeFromBytes(sigBytes);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue,
    };
  };

  const issuer = new DelegationCredentialIssuer(
    {
      getDid: () => identity.did,
      getKeyId: () => identity.kid,
      getPrivateKey: () => identity.privateKey,
    },
    signingFunction,
  );

  // VC-JWT variant: strip embedded proof, sign as compact JWT instead
  const issueAsJWT: DelegationIssuerFactory['issueAsJWT'] = async (params, options) => {
    const vc = await issuer.createAndIssueDelegation(params, options);
    const vcWithoutProof = { ...vc } as Record<string, unknown>;
    delete vcWithoutProof['proof'];
    const { signingInput } = createUnsignedVCJWT(vcWithoutProof, { keyId: identity.kid });
    const sigBytes = await crypto.sign(new TextEncoder().encode(signingInput), identity.privateKey);
    const signature = base64urlEncodeFromBytes(sigBytes);
    return completeVCJWT(signingInput, signature);
  };

  return { issuer, identity, issueAsJWT };
}
