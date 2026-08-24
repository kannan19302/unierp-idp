export interface LegalDocumentDescriptor {
  url: string;
  version: string;
  effectiveDate: string;
}

export interface RegistrationLegalConfig {
  terms: LegalDocumentDescriptor;
  privacy: LegalDocumentDescriptor;
}

/**
 * Server-authoritative legal document identifiers used for both rendering and
 * consent evidence. The browser never chooses the version that is recorded.
 */
export function getRegistrationLegalConfig(
  source: NodeJS.ProcessEnv = process.env,
): RegistrationLegalConfig {
  return {
    terms: {
      url:
        source.TERMS_OF_SERVICE_URL ??
        "http://localhost:4001/terms",
      version: source.TERMS_OF_SERVICE_VERSION ?? "2026-07-development",
      effectiveDate: source.TERMS_OF_SERVICE_EFFECTIVE_DATE ?? "2026-07-01",
    },
    privacy: {
      url:
        source.PRIVACY_POLICY_URL ??
        "http://localhost:4001/privacy",
      version: source.PRIVACY_POLICY_VERSION ?? "2026-07-development",
      effectiveDate: source.PRIVACY_POLICY_EFFECTIVE_DATE ?? "2026-07-01",
    },
  };
}
