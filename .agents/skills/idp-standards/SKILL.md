---
name: idp-standards
description: Repository guidance, architectural context, and verification routing for idp.
version: 1.0.0
author: UniERP Architecture Governance
---

# UniERP Identity Provider (IdP) — AI Agent Guidance & Project Skill

Read the [applicable AGENTS.md](../../../AGENTS.md) first. This skill is subordinate implementation guidance.
Resolve ownership and current topology through that entrypoint; examples and performance aspirations are not
verified product facts. Select verification from the owning package scripts and canonical risk matrix.
The commands below are not a complete substitute for applicable security, integration, lint or build gates.


This skill governs all code modification, analysis, and testing within `idp` (**Layer L3: Service**). Every AI agent and software engineer working in this repository MUST follow these rules without exception.

---

## 🏛️ 1. Architectural Position & Boundary Rules

- **Repository**: `idp`
- **Layer**: **L3 (Service)**
- **Package Identity**: `@kannan19302/idp`
- **Allowed Inbound Callers**: L4 (Presentation apps), L5 (Clients), External Identity Federations
- **Allowed Outbound Dependencies**: @kannan19302/contracts (L0); L1 packages; @kannan19302/database (L2)
- **STRICTLY FORBIDDEN DEPENDENCIES**:
  - ❌ Layers L4-L7

> **Unidirectional Rule**: You may ONLY import published artifacts from strictly lower layers. Sibling imports within the same layer are prohibited unless mediated through L0 contracts.

---

## 🎯 2. The Platform Goal & Repository Mandate

> **Platform North Star Goal**:  
> "Build the world's premier autonomous, multi-tenant Enterprise SaaS Operating System: 100% Zero-Trust Multi-Tenant Isolation, Absolute Decimal(19,4) Numeric Precision, Atomic Durable Audit Logging, Sub-100ms P99 Latency, and Strata Workbench High-Density UI."

### Repository Responsibility Mandate
Central authentication and identity authority: OIDC/OAuth2 server, WebAuthn passkeys, session management, and multi-factor auth.

---

## 📐 3. Repository-Specific Coding Standards

### Core Implementation Standards
1. Maintain strict modular boundaries and single-responsibility interfaces.
2. Export all public types from the root `index.ts`.
3. Ensure zero TypeScript compilation errors under `tsc --noEmit`.

---

## 🛡️ 4. Mandatory Pre-Commit Verification Gate

Before submitting or reporting completion on any change in this repository, run and verify:

```bash
pnpm test && pnpm typecheck
```

All tests must pass with 0 failures and 0 type errors.
