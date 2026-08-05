# unierp-idp

> Part of **[UniERP](https://github.com/kannan19302/UniERP)** — an open-source, self-hostable multi-tenant application platform.
> [Repository map](https://github.com/kannan19302/UniERP#repository-map) · [Architecture](https://github.com/kannan19302/UniERP#how-the-pieces-fit-at-runtime) · [Contributing](https://github.com/kannan19302/UniERP/blob/main/CONTRIBUTING.md) · [Security](https://github.com/kannan19302/UniERP/blob/main/SECURITY.md)

**Layer L3 — Service** of the UniERP platform. Depends on: L0, L1, L2.

## What this is

The identity provider. Issues and validates sessions for each plane.

## The invariant this repository owns

**Separate realms per plane (§ 5.2).** No customer identity can obtain a control-plane token, because the realm is separate — not because a claim is checked.

## The rule that applies everywhere

A repository may depend only on published artifacts of a **strictly lower
layer** — never sideways within a layer, never upward. A cycle is not
discouraged; it is unrepresentable, because the lower layer's package cannot
name the higher one.

## Licence

AGPL-3.0.
