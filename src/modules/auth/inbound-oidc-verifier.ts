import {
  jwtVerify,
  type JWTVerifyGetKey,
  type JWTVerifyResult,
  type JWTPayload,
} from "jose";

export interface InboundOidcVerificationPolicy {
  issuer: string;
  clientId: string;
  nonce: string;
  algorithms: string[];
  maxTokenAge?: string | number;
  clockToleranceSeconds?: number;
}

export class InboundOidcClaimError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InboundOidcClaimError";
  }
}

/**
 * Cryptographically verify an inbound tenant-IdP token and the OIDC claims
 * that bind it to the one-time federation transaction. The key resolver may
 * be a remote JWKS in production or a local JWKS in conformance tests.
 */
export async function verifyInboundOidcToken(
  idToken: string,
  keySet: JWTVerifyGetKey,
  policy: InboundOidcVerificationPolicy,
): Promise<JWTPayload> {
  if (policy.algorithms.length === 0) {
    throw new InboundOidcClaimError("No allowed signing algorithm was supplied.");
  }

  const verified: JWTVerifyResult = await jwtVerify(idToken, keySet, {
    algorithms: policy.algorithms,
    issuer: policy.issuer,
    audience: policy.clientId,
    maxTokenAge: policy.maxTokenAge ?? "5m",
    clockTolerance: policy.clockToleranceSeconds ?? 30,
  });

  const audience = verified.payload.aud;
  if (Array.isArray(audience) && verified.payload.azp !== policy.clientId) {
    throw new InboundOidcClaimError("Identity response authorized party is invalid.");
  }
  if (verified.payload.nonce !== policy.nonce) {
    throw new InboundOidcClaimError("Identity response nonce is invalid.");
  }

  return verified.payload;
}
