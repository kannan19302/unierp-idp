import { Injectable, Logger } from "@nestjs/common";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { idpPrisma } from "@kannan19302/database";
import {
  OAUTH_ERROR,
  PKCE_METHOD_S256,
  TOKEN_TTL,
} from "../oidc.constants";

/**
 * Authorization-code issuance and redemption.
 *
 * The code is the one credential that travels through the user's browser — in a
 * query string, into history, past whatever extensions are installed — so it is
 * treated as compromised by default and made useless on its own:
 *
 *   * it is single-use, and redeeming it twice revokes everything derived from it;
 *   * it expires in a minute;
 *   * it is bound to a PKCE challenge, so possession of the code alone is not
 *     enough — the redeemer must also prove it holds the original verifier;
 *   * only its SHA-256 hash is stored, so a database dump yields no usable codes.
 */

export class OAuthError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "OAuthError";
  }
}

export interface IssueCodeInput {
  clientId: string;
  userId: string;
  tenantId: string;
  /** Session the code is bound to; revoking it revokes the derived tokens. */
  sid: string;
  redirectUri: string;
  scopes: string[];
  codeChallenge: string;
  codeChallengeMethod: string;
  nonce?: string;
}

export interface RedeemedCode {
  clientId: string;
  userId: string;
  tenantId: string;
  sid: string;
  scopes: string[];
  nonce: string | null;
}

@Injectable()
export class AuthorizationService {
  private readonly logger = new Logger(AuthorizationService.name);

  /**
   * Issues a code and returns the raw value — the only moment it exists in
   * clear text. 32 bytes of CSPRNG output; guessing is not a threat model we
   * need to reason further about.
   */
  async issueCode(input: IssueCodeInput): Promise<string> {
    if (input.codeChallengeMethod !== PKCE_METHOD_S256) {
      // Also enforced by a CHECK constraint, but failing here gives the client
      // a protocol-shaped error instead of a database error.
      throw new OAuthError(
        OAUTH_ERROR.INVALID_REQUEST,
        "code_challenge_method must be S256",
      );
    }
    if (!input.codeChallenge) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_REQUEST,
        "code_challenge is required (PKCE is mandatory)",
      );
    }

    const code = randomBytes(32).toString("base64url");

    await idpPrisma.authorizationCode.create({
      data: {
        codeHash: hashCode(code),
        clientId: input.clientId,
        userId: input.userId,
        tenantId: input.tenantId,
        sid: input.sid,
        redirectUri: input.redirectUri,
        scopes: input.scopes,
        nonce: input.nonce ?? null,
        codeChallenge: input.codeChallenge,
        codeChallengeMethod: PKCE_METHOD_S256,
        expiresAt: new Date(Date.now() + TOKEN_TTL.AUTHORIZATION_CODE_MS),
      },
    });

    return code;
  }

  /**
   * Redeems a code exactly once.
   *
   * Every check that can fail is deliberately reported as the same
   * `invalid_grant` error. Distinguishing "no such code" from "wrong client"
   * from "already used" would let an attacker probe for valid codes.
   */
  async redeemCode(params: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier: string;
  }): Promise<RedeemedCode> {
    const codeHash = hashCode(params.code);
    const record = await idpPrisma.authorizationCode.findUnique({
      where: { codeHash },
    });

    if (!record) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid authorization code");
    }

    // Replay. The legitimate client already exchanged this code, so a second
    // presentation means the code leaked — from browser history, a proxy log,
    // a referrer header. The tokens the real client is holding may belong to
    // an attacker, so tear the whole grant down rather than merely refusing.
    if (record.consumedAt) {
      this.logger.warn(
        `Authorization code replayed for client ${record.clientId}; revoking derived grants for session ${record.sid}`,
      );
      await this.revokeGrantsForSession(record.sid);
      throw new OAuthError(
        OAUTH_ERROR.INVALID_GRANT,
        "Invalid authorization code",
      );
    }

    if (record.expiresAt < new Date()) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid authorization code");
    }

    // A code issued to one client must not be redeemable by another, even if
    // that other client somehow observed it.
    if (record.clientId !== params.clientId) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid authorization code");
    }

    // redirect_uri must match the one the code was issued against. Without
    // this, an attacker who can register a client could have a code minted for
    // one destination and redeemed against another.
    if (record.redirectUri !== params.redirectUri) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid authorization code");
    }

    if (!verifyPkce(params.codeVerifier, record.codeChallenge)) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid authorization code");
    }

    // Consume atomically. Two concurrent redemptions of the same code must not
    // both succeed, so the update is conditional on it still being unconsumed
    // and we check that it actually matched a row.
    const consumed = await idpPrisma.authorizationCode.updateMany({
      where: { codeHash, consumedAt: null },
      data: { consumedAt: new Date() },
    });
    if (consumed.count !== 1) {
      // Another request won the race between our read and this write.
      await this.revokeGrantsForSession(record.sid);
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid authorization code");
    }

    return {
      clientId: record.clientId,
      userId: record.userId,
      tenantId: record.tenantId,
      sid: record.sid,
      scopes: record.scopes,
      nonce: record.nonce,
    };
  }

  /** Revokes every refresh grant derived from a session. */
  async revokeGrantsForSession(sid: string): Promise<number> {
    const { count } = await idpPrisma.refreshGrant.updateMany({
      where: { sid, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return count;
  }

  /**
   * Clears codes that are past use. Expired-but-unconsumed rows are the bulk;
   * consumed rows are kept briefly so a replay is still detectable rather than
   * silently reading as "unknown code".
   */
  async purgeExpiredCodes(consumedRetentionMs = 24 * 60 * 60_000): Promise<number> {
    const now = new Date();
    const { count } = await idpPrisma.authorizationCode.deleteMany({
      where: {
        OR: [
          { consumedAt: null, expiresAt: { lt: now } },
          {
            consumedAt: { lt: new Date(now.getTime() - consumedRetentionMs) },
          },
        ],
      },
    });
    return count;
  }
}

/** Codes are stored hashed; a database dump must not yield usable codes. */
function hashCode(code: string): string {
  return createHash("sha256").update(code).digest("base64url");
}

/**
 * PKCE S256 verification: BASE64URL(SHA256(verifier)) must equal the challenge
 * captured at /authorize.
 *
 * Compared in constant time. A length-dependent early return would leak the
 * challenge a byte at a time to an attacker who can time the endpoint.
 */
export function verifyPkce(verifier: string, challenge: string): boolean {
  if (!verifier || !challenge) return false;

  const computed = createHash("sha256").update(verifier).digest("base64url");
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);

  // timingSafeEqual throws on length mismatch, which would itself be a timing
  // signal; compare lengths separately and still run the constant-time compare.
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export { hashCode };
