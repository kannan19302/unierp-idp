export interface WebAuthnConfig {
  rpId: string;
  rpName: string;
  expectedOrigins: string[];
}

export function getWebAuthnConfig(): WebAuthnConfig {
  return {
    rpId: process.env.WEBAUTHN_RP_ID?.trim() || "localhost",
    rpName: process.env.WEBAUTHN_RP_NAME?.trim() || "UniERP",
    expectedOrigins: (process.env.WEBAUTHN_ORIGINS || "http://localhost:3005")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  };
}
