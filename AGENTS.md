<!-- UniERP-Agent-Protocol: 1.1.0 -->
# UniERP Repository Agent Entrypoint: Sovereign IdP (`idp`)

This repository is one delivery unit in the UniERP polyrepo. Before analysis, planning, review, or mutation, every
AI agent from every provider MUST read and follow:

1. the workspace entrypoint at [`../AGENTS.md`](../AGENTS.md);
2. the canonical standard at
   [`../platform/docs/standards/AI_AGENT_DEVELOPMENT_PROTOCOL.md`](../platform/docs/standards/AI_AGENT_DEVELOPMENT_PROTOCOL.md);
3. the owning platform documents selected through
   [`../platform/docs/PLATFORM_CATALOG.md`](../platform/docs/PLATFORM_CATALOG.md).

If the workspace entrypoint or canonical standard is unavailable, the protocol bundle is incomplete. The agent
MUST stop before mutation and report the missing dependency. This bootstrap adds no weaker or conflicting rules.
Repository-specific additions may be appended below only when they narrow implementation behavior without
redefining platform ownership, security, contracts, or cross-platform standards.

---

## 1. Repository Identity & Mission

- **Repository**: `idp`
- **Platform Owner**: `PLT-IAM` (Identity & Access Management)
- **Architectural Layer**: **Layer 3 (Identity Services)**
- **Runtime Port**: `3005`
- **Mission**: Sovereign OIDC / OAuth 2.1 / SAML 2.0 / WebAuthn Identity Provider — responsible for user authentication, passwordless MFA, enterprise federation, token signing, session lifecycle, and cryptographic keyring rotation.

---

## 2. Zero-Trust Security Guidance

1. **Cryptographic Standards**:
   - Asymmetric token signing with RS256/EdDSA; keyring rotation with overlap windows.
   - Secure hash algorithms (Argon2id for passwords).
2. **Tenant Isolation in Identity**:
   - Multi-tenant realm separation; users, identity pools, and SSO federation configurations are tenant-isolated.
3. **Session & Cookie Hygiene**:
   - `HttpOnly`, `SameSite=Lax/Strict`, `Secure` cookie attributes.
   - Protection against CSRF, replay attacks, and session fixation.
4. **Secret Quarantine**:
   - Signing keys and secrets must never be committed to Git. All environments consume secrets via environment variables or KMS.

---

## 3. Industrial Software Engineering Standards

1. **Strict Static Typing**:
   - TypeScript `strict: true`; NestJS controllers and services must use typed DTOs.
2. **Deterministic Authentication Tests**:
   - Unit and integration tests must verify positive auth, wrong password, expired token, wrong issuer, and revoked session behaviors without network dependencies.

---

## 4. Verification Gates & Mandatory Toolchain

Before declaring any cycle `DONE`, run and verify:

```powershell
pnpm typecheck              # Strict TypeScript verification
pnpm build                  # NestJS production build
pnpm test                   # Vitest unit test suite
node scripts/check-layer.mjs # Canonical Layer Gate enforcement
```
