    <!-- UniERP-Agent-Protocol: 1.1.0 -->
    # idp agent rules

    This is the only repository agent instruction file. Read [the workspace entrypoint](../AGENTS.md),
    the [canonical protocol](../platform/docs/standards/AI_AGENT_DEVELOPMENT_PROTOCOL.md),
    the enterprise brain, applicable accepted ADRs and the owning platform requirements before
    material work. Follow authority precedence; this file narrows implementation behavior only.
    If a required authority is missing, stop before mutation.

    **Layer:** L3. **Accountable platform:** PLT-IAM. **Scope:** Principals, sessions, authentication and entitlement evaluation.
    Resolve actual dependencies, packages and scripts from current manifests and the platform catalog.
    Preserve unrelated changes. Define numbered acceptance criteria and a knowledge delta before editing.
    For coordinated changes, publish the change contract, validate upstream first, and hand off
    to downstream consumers with exact evidence.

    ## Repository rules

    - Own credentials and sessions; other apps consume the published IAM contract. Keep provider and tenant realms separate.
- Use standards-compliant OIDC/SAML validation, PKCE, state/nonce, safe redirects, secure cookies and key rotation. Deny invalid or missing authority.
- Test wrong issuer/audience, replay, revocation, recovery, privilege boundaries and tenant isolation. Never log secrets.

    ## Verification

    Run applicable commands from this repository, plus risk-specific contract, security, data,
    accessibility, integration, migration or release gates required by the canonical protocol:
    pnpm typecheck; pnpm lint; pnpm test; pnpm build; node ../platform/workspace/scripts/check-layer.mjs

    A command's presence here is not proof that it ran. Report exact results, failures and NOT RUN
    reasons; review the diff; then follow the canonical status and source-control procedure.
