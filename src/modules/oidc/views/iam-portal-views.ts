/**
 * ──────────────────────────────────────────────────────────────────────────
 * IAM & Onboarding Portal Views — Strata Design Language DL 3.0
 * Pixel-accurate server-rendered HTML views for:
 * - IAM-003 through IAM-016 (Authentication and Risk Cards)
 * - REG-002 through REG-004 (Registration & Sovereign Onboarding)
 * ──────────────────────────────────────────────────────────────────────────
 */

export function escapeHtml(s?: string): string {
  if (!s) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export interface PortalViewBaseOpts {
  returnTo?: string;
  error?: string;
  success?: string;
  csrfToken?: string;
}

// ── IAM-003: Single Sign-On (SSO) Discovery ─────────────────────────────
export function renderSsoDiscovery(opts: PortalViewBaseOpts & { email?: string }): string {
  const returnTo = encodeURIComponent(opts.returnTo || "/");
  return `
    <div class="auth-container" style="max-width: 440px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Enterprise Identity</span>
          <h1>Single Sign-On (SSO)</h1>
          <p>Enter your enterprise work email to be redirected to your company's identity provider.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/sso">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>

          <div class="form-group">
            <label class="form-label" for="sso-email">Corporate Work Email</label>
            <input
              id="sso-email"
              type="email"
              name="email"
              required
              autofocus
              placeholder="alex.chen@enterprise.com"
              value="${escapeHtml(opts.email || "")}"
              class="form-input"
            />
          </div>

          <div class="trust-pill" style="margin: 12px 0; padding: 8px 12px; background: var(--bg-hero); border: 1px solid var(--border-card); border-radius: 6px; font-size: 0.72rem; color: var(--text-muted); display: flex; align-items: center; gap: 8px;">
            <span>🔒 SAML 2.0 / OIDC FedRAMP High compliant federation</span>
          </div>

          <button type="submit" class="btn-submit">
            <span>Continue to Enterprise IdP →</span>
          </button>
        </form>

        <p class="auth-alternative" style="margin-top: 18px; text-align: center;">
          <a href="/oidc/login?return_to=${returnTo}" class="auth-link">← Return to standard sign in</a>
        </p>
      </div>
    </div>
  `;
}

// ── IAM-005: Workspace Switcher ─────────────────────────────────────────
export interface WorkspaceItem {
  id: string;
  name: string;
  sub: string;
  letter: string;
  active?: boolean;
}

export function renderWorkspaceSwitcher(opts: PortalViewBaseOpts & { workspaces?: WorkspaceItem[] }): string {
  const items = opts.workspaces && opts.workspaces.length > 0 ? opts.workspaces : [
    { id: "ws-1", name: "Acme Global Corporation", sub: "acme.unierp.cloud • EU Central", letter: "A", active: true },
    { id: "ws-2", name: "Starlight Health Systems", sub: "starlight.unierp.cloud • US East", letter: "S" },
    { id: "ws-3", name: "Apex FinTech Holdings", sub: "apex.unierp.cloud • AP South", letter: "A" },
  ];

  const wsListHtml = items.map((w) => `
    <form method="POST" action="/oidc/workspaces/switch" style="margin: 0;">
      <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
      <input type="hidden" name="workspace_id" value="${escapeHtml(w.id)}"/>
      <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>
      <button type="submit" class="workspace-btn" style="width: 100%; display: flex; align-items: center; justify-content: space-between; padding: 12px; margin-bottom: 8px; background: var(--bg-card); border: 1px solid ${w.active ? 'var(--brand-primary)' : 'var(--border-card)'}; border-radius: 8px; cursor: pointer; text-align: left; transition: all 0.15s ease;">
        <div style="display: flex; align-items: center; gap: 12px;">
          <div style="width: 36px; height: 36px; border-radius: 8px; background: ${w.active ? 'var(--brand-primary)' : 'var(--bg-pill)'}; color: ${w.active ? '#ffffff' : 'var(--text-title)'}; font-weight: 700; display: flex; align-items: center; justify-content: center; font-size: 0.95rem;">
            ${escapeHtml(w.letter)}
          </div>
          <div>
            <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-title);">${escapeHtml(w.name)}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted); font-family: monospace;">${escapeHtml(w.sub)}</div>
          </div>
        </div>
        ${w.active ? '<span style="font-size: 0.7rem; font-weight: 600; color: var(--brand-primary); background: var(--brand-light); padding: 3px 8px; border-radius: 999px;">Active</span>' : '<span style="color: var(--text-muted); font-size: 0.85rem;">→</span>'}
      </button>
    </form>
  `).join("");

  return `
    <div class="auth-container" style="max-width: 460px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Multi-Tenant Routing</span>
          <h1>Select a workspace</h1>
          <p>Choose an enterprise partition to access with your verified credentials.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <div style="margin-bottom: 12px;">
          <input type="text" id="ws-search" placeholder="🔍 Search organizations or domains..." class="form-input" style="height: 36px; margin-bottom: 12px;" onkeyup="filterWorkspaces(this.value)"/>
        </div>

        <div id="ws-container">
          ${wsListHtml}
        </div>

        <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border-card); display: flex; justify-content: space-between; align-items: center;">
          <a href="/oidc/register" class="auth-link" style="font-size: 0.78rem;">+ Create new organization</a>
          <a href="/oidc/logout" class="auth-link" style="font-size: 0.78rem; color: var(--text-muted);">Sign out</a>
        </div>
      </div>
    </div>
    <script>
      function filterWorkspaces(q) {
        var query = q.toLowerCase();
        var buttons = document.querySelectorAll('#ws-container button');
        buttons.forEach(function(btn) {
          var text = btn.innerText.toLowerCase();
          btn.parentElement.style.display = text.includes(query) ? '' : 'none';
        });
      }
    </script>
  `;
}

// ── IAM-006: Session Lockout Console ────────────────────────────────────
export function renderSessionLockout(opts: PortalViewBaseOpts & { userName?: string; email?: string }): string {
  return `
    <div class="auth-container" style="max-width: 440px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="radar-ring" style="color: var(--brand-primary); background: var(--brand-light);">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>

        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow" style="color: var(--error-text);">SecOps Compliance Policy</span>
          <h1>Session locked</h1>
          <p>Locked due to 15m inactivity per SOC2 / FINRA Rule 4370 requirements.</p>
        </div>

        <div style="text-align: center; margin-bottom: 16px; padding: 10px; background: var(--bg-hero); border-radius: 8px;">
          <div style="font-weight: 600; font-size: 0.85rem;">${escapeHtml(opts.userName || "Alex Chen")}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(opts.email || "alex.chen@enterprise.com")}</div>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/lockout/unlock">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>

          <div class="form-group">
            <label class="form-label" for="lockout-password">Master Password</label>
            <input
              id="lockout-password"
              type="password"
              name="password"
              required
              autofocus
              placeholder="••••••••••••"
              class="form-input"
            />
          </div>

          <button type="submit" class="btn-submit" style="margin-top: 8px;">
            <span>Unlock session →</span>
          </button>
        </form>

        <div style="margin-top: 18px; text-align: center; font-size: 0.72rem; color: var(--text-muted);">
          <a href="/oidc/secops/break-glass" class="auth-link" style="color: var(--text-muted);">Emergency SecOps break-glass console</a>
          <span style="margin: 0 6px;">•</span>
          <a href="/oidc/logout" class="auth-link" style="color: var(--text-muted);">Log out</a>
        </div>
      </div>
    </div>
  `;
}

// ── IAM-007: MFA Setup (Authenticator App) ──────────────────────────────
export function renderMfaSetup(opts: PortalViewBaseOpts & { secretKey?: string; qrDataUri?: string }): string {
  const secret = opts.secretKey || "JBSWY3DPEHPK3PXP";
  return `
    <div class="auth-container" style="max-width: 460px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Zero-Trust Hardening</span>
          <h1>Set up 2-Factor Auth</h1>
          <p>Scan this QR code with Google Authenticator, 1Password, or Microsoft Authenticator.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <!-- QR Placeholder Box -->
        <div style="display: flex; justify-content: center; margin: 16px 0;">
          <div style="padding: 12px; background: #ffffff; border: 1px solid var(--border-card); border-radius: 10px; display: flex; flex-direction: column; align-items: center; gap: 8px;">
            <svg width="130" height="130" viewBox="0 0 100 100" fill="#000000">
              <rect x="5" y="5" width="30" height="30" rx="4" fill="none" stroke="#000000" stroke-width="6"/>
              <rect x="13" y="13" width="14" height="14" rx="2" fill="#000000"/>
              <rect x="65" y="5" width="30" height="30" rx="4" fill="none" stroke="#000000" stroke-width="6"/>
              <rect x="73" y="13" width="14" height="14" rx="2" fill="#000000"/>
              <rect x="5" y="65" width="30" height="30" rx="4" fill="none" stroke="#000000" stroke-width="6"/>
              <rect x="13" y="73" width="14" height="14" rx="2" fill="#000000"/>
              <rect x="45" y="15" width="10" height="25" fill="#000000"/>
              <rect x="15" y="45" width="25" height="10" fill="#000000"/>
              <rect x="45" y="45" width="12" height="12" fill="#000000"/>
              <rect x="65" y="45" width="25" height="10" fill="#000000"/>
              <rect x="65" y="65" width="12" height="25" fill="#000000"/>
              <rect x="82" y="82" width="10" height="10" fill="#000000"/>
            </svg>
            <span style="font-family: monospace; font-size: 0.72rem; color: #475569; letter-spacing: 0.1em; background: #f1f5f9; padding: 4px 8px; border-radius: 4px;">${escapeHtml(secret)}</span>
          </div>
        </div>

        <form method="POST" action="/oidc/mfa-setup">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="secret_key" value="${escapeHtml(secret)}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>

          <div class="form-group">
            <label class="form-label" for="totp-code" style="text-align: center;">Enter 6-digit confirmation code</label>
            <input
              id="totp-code"
              type="text"
              name="code"
              inputmode="numeric"
              maxlength="6"
              required
              autofocus
              placeholder="123456"
              class="form-input"
              style="text-align: center; font-size: 1.25rem; letter-spacing: 0.3em; font-family: monospace;"
            />
          </div>

          <button type="submit" class="btn-submit" style="margin-top: 10px;">
            <span>Verify & Activate MFA →</span>
          </button>
        </form>
      </div>
    </div>
  `;
}

// ── IAM-008: Passkey Enrollment ─────────────────────────────────────────
export function renderPasskeyEnroll(opts: PortalViewBaseOpts): string {
  return `
    <div class="auth-container" style="max-width: 460px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="radar-ring" style="color: var(--brand-primary); background: var(--brand-light);">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path>
            <path d="M2 12h20"></path>
          </svg>
        </div>

        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow">FIDO2 / WebAuthn Certified</span>
          <h1>Enroll a Passkey</h1>
          <p>Sign in instantly using Touch ID, Face ID, Windows Hello, or an enterprise YubiKey.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <div style="padding: 14px; background: var(--bg-hero); border: 1px solid var(--border-card); border-radius: 8px; margin-bottom: 16px; font-size: 0.78rem; line-height: 1.4; color: var(--text-secondary);">
          <div>✓ Phishing-resistant cryptographic public/private keypair</div>
          <div>✓ Hardware security enclave protection (zero password storage)</div>
          <div>✓ Seamless synchronization across approved enterprise devices</div>
        </div>

        <input type="hidden" id="account-passkey-csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
        <input type="hidden" id="passkey-name" value="Enterprise Device Passkey"/>

        <button type="button" id="add-passkey" class="btn-submit">
          <span>Create & Register Passkey</span>
        </button>

        <p id="passkey-account-status" style="text-align: center; font-size: 0.75rem; color: var(--text-muted); margin-top: 10px;"></p>

        <p class="auth-alternative" style="margin-top: 16px; text-align: center;">
          <a href="/oidc/login" class="auth-link">Skip for now (use standard password)</a>
        </p>
      </div>
    </div>
  `;
}

// ── IAM-009: Recovery Backup Codes ──────────────────────────────────────
export function renderRecoveryCodes(opts: PortalViewBaseOpts & { codes?: string[] }): string {
  const codes = opts.codes || [
    "7F2A-99B1", "44C8-2E10", "A93D-77F4", "1B88-C392",
    "66D1-00E5", "3E92-BB71", "88A3-5F19", "C210-449D",
  ];

  const codePills = codes.map((c) => `
    <div style="background: var(--bg-pill); border: 1px solid var(--border-subtle); padding: 8px; border-radius: 6px; text-align: center; font-family: monospace; font-weight: 700; font-size: 0.85rem; color: var(--text-title); letter-spacing: 0.05em;">
      ${escapeHtml(c)}
    </div>
  `).join("");

  return `
    <div class="auth-container" style="max-width: 480px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Emergency Access</span>
          <h1>Recovery backup codes</h1>
          <p>Store these one-time cryptographic emergency codes in a secure password manager or enterprise vault.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 16px 0;">
          ${codePills}
        </div>

        <div style="padding: 10px 12px; background: var(--bg-hero); border-radius: 6px; font-size: 0.72rem; color: var(--text-muted); margin-bottom: 16px;">
          ⚠️ Each recovery code can only be used once. If your primary authenticator device is lost, these codes are the only way to recover account ownership.
        </div>

        <form method="POST" action="/oidc/recovery-codes/confirm">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>

          <label class="checkbox-label" style="margin-bottom: 16px;">
            <input type="checkbox" name="saved_acknowledged" required />
            <span>I have safely recorded or printed these 8 recovery codes</span>
          </label>

          <button type="submit" class="btn-submit">
            <span>Confirm & Complete Setup →</span>
          </button>
        </form>
      </div>
    </div>
  `;
}

// ── IAM-010: Forced Password Change ─────────────────────────────────────
export function renderForcedPasswordChange(opts: PortalViewBaseOpts & { reason?: string }): string {
  return `
    <div class="auth-container" style="max-width: 460px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow" style="color: var(--error-text);">Security Policy Enforcement</span>
          <h1>Password change required</h1>
          <p>${escapeHtml(opts.reason || "Your enterprise security policy requires regular password rotation or a mandatory reset.")}</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/forced-password-change">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>

          <div class="form-group">
            <label class="form-label" for="current-pw">Current Password</label>
            <input id="current-pw" type="password" name="current_password" required class="form-input"/>
          </div>

          <div class="form-group">
            <label class="form-label" for="new-pw">New Sovereign Password</label>
            <input id="new-pw" type="password" name="new_password" required placeholder="Minimum 12 characters" class="form-input"/>
          </div>

          <div class="form-group">
            <label class="form-label" for="confirm-pw">Confirm New Password</label>
            <input id="confirm-pw" type="password" name="confirm_password" required class="form-input"/>
          </div>

          <button type="submit" class="btn-submit" style="margin-top: 12px;">
            <span>Update Password & Continue →</span>
          </button>
        </form>
      </div>
    </div>
  `;
}

// ── IAM-011: Magic Link Notice ──────────────────────────────────────────
export function renderMagicLinkNotice(opts: PortalViewBaseOpts & { email?: string }): string {
  return `
    <div class="auth-container" style="max-width: 440px; grid-template-columns: 1fr;">
      <div class="auth-form-panel" style="text-align: center;">
        <div style="font-size: 2.5rem; margin-bottom: 12px;">✉️</div>
        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow">Passwordless Dispatch</span>
          <h1>Magic link sent</h1>
          <p>We dispatched a secure sign-in token to <strong>${escapeHtml(opts.email || "your corporate email")}</strong>.</p>
        </div>

        <div style="padding: 12px; background: var(--bg-hero); border: 1px solid var(--border-card); border-radius: 8px; margin: 16px 0; font-size: 0.75rem; color: var(--text-muted); line-height: 1.4;">
          The cryptographic link expires in 15 minutes. Check your inbox and click the button to authenticate directly.
        </div>

        <form method="POST" action="/oidc/magic-link" style="margin-top: 16px;">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="email" value="${escapeHtml(opts.email || "")}"/>
          <button type="submit" class="social-btn" style="width: 100%; justify-content: center;">
            Resend magic link
          </button>
        </form>

        <p class="auth-alternative" style="margin-top: 16px;">
          <a href="/oidc/login" class="auth-link">← Sign in using standard password</a>
        </p>
      </div>
    </div>
  `;
}

// ── IAM-012: Suspicious Login Challenge ─────────────────────────────────
export function renderSuspiciousLogin(opts: PortalViewBaseOpts & { challengeNumber?: number; location?: string; ip?: string }): string {
  const challenge = opts.challengeNumber || 42;
  return `
    <div class="auth-container" style="max-width: 440px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="radar-ring" style="color: var(--error-text); background: var(--error-bg);">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
          </svg>
        </div>

        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow" style="color: var(--error-text);">Risk Engine Challenge</span>
          <h1>Verify this login</h1>
          <p>We detected an unfamiliar location or network (${escapeHtml(opts.location || "Frankfurt, Germany")} • IP: ${escapeHtml(opts.ip || "193.14.22.8")}).</p>
        </div>

        <div style="display: flex; flex-direction: column; align-items: center; margin: 16px 0;">
          <div style="width: 72px; height: 72px; border-radius: 50%; background: var(--brand-primary); color: #ffffff; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: 800; font-family: monospace; box-shadow: var(--shadow-card);">
            ${challenge}
          </div>
          <span style="font-size: 0.75rem; color: var(--text-muted); margin-top: 8px;">Select this matching number on your authenticator device app.</span>
        </div>

        <form method="POST" action="/oidc/verify-location">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="challenge_number" value="${challenge}"/>
          <button type="submit" class="btn-submit">
            <span>I verified the push challenge on my phone →</span>
          </button>
        </form>

        <p class="auth-alternative" style="margin-top: 16px; text-align: center;">
          <a href="/oidc/secops/report-suspicious" class="auth-link" style="color: var(--error-text);">This wasn't me (lock my account immediately)</a>
        </p>
      </div>
    </div>
  `;
}

// ── IAM-013: Enterprise Invitation Accept ────────────────────────────────
export function renderInvitationAccept(opts: PortalViewBaseOpts & { orgName?: string; inviterName?: string; email?: string }): string {
  return `
    <div class="auth-container" style="max-width: 460px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Enterprise Invitation</span>
          <h1>Join ${escapeHtml(opts.orgName || "Acme Global")}</h1>
          <p>${escapeHtml(opts.inviterName || "Sarah Jenkins")} has invited you to join the enterprise workspace.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/invitation">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>

          <div class="form-group">
            <label class="form-label">Email Address</label>
            <input type="email" value="${escapeHtml(opts.email || "user@company.com")}" readonly class="form-input"/>
          </div>

          <div class="form-group">
            <label class="form-label" for="inv-name">Your Full Name</label>
            <input id="inv-name" type="text" name="full_name" required placeholder="Alex Chen" class="form-input"/>
          </div>

          <div class="form-group">
            <label class="form-label" for="inv-password">Create Work Password</label>
            <input id="inv-password" type="password" name="password" required placeholder="Minimum 12 characters" class="form-input"/>
          </div>

          <label class="checkbox-label" style="margin: 12px 0;">
            <input type="checkbox" name="terms_accepted" required checked />
            <span>I accept the enterprise membership terms and security policies.</span>
          </label>

          <button type="submit" class="btn-submit">
            <span>Accept invitation & enter workspace →</span>
          </button>
        </form>
      </div>
    </div>
  `;
}

// ── IAM-014: OAuth 2.0 / OIDC Consent ───────────────────────────────────
export function renderOAuthConsent(opts: PortalViewBaseOpts & { clientName?: string; scopes?: string[] }): string {
  const scopes = opts.scopes || [
    "Read purchase orders, inventory, and line items",
    "Manage webhook event subscriptions",
    "View user profile, email, and company domain",
  ];

  const scopeHtml = scopes.map((s) => `
    <div style="display: flex; align-items: flex-start; gap: 8px; font-size: 0.78rem; margin-bottom: 6px; color: var(--text-title);">
      <span style="color: var(--success-solid); font-weight: 700;">✓</span>
      <span>${escapeHtml(s)}</span>
    </div>
  `).join("");

  return `
    <div class="auth-container" style="max-width: 460px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Application Authorization</span>
          <h1>Authorize ${escapeHtml(opts.clientName || "Enterprise Analytics Sync")}</h1>
          <p>The application is requesting access to your UniERP partition under your assigned RBAC privileges.</p>
        </div>

        <div style="padding: 12px; background: var(--bg-hero); border: 1px solid var(--border-card); border-radius: 8px; margin: 16px 0;">
          <div style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase;">Requested Permissions</div>
          ${scopeHtml}
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
          <form method="POST" action="/oidc/consent" style="margin: 0;">
            <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
            <input type="hidden" name="decision" value="deny"/>
            <button type="submit" class="social-btn" style="width: 100%; justify-content: center;">Deny access</button>
          </form>
          <form method="POST" action="/oidc/consent" style="margin: 0;">
            <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
            <input type="hidden" name="decision" value="approve"/>
            <button type="submit" class="btn-submit">Authorize App</button>
          </form>
        </div>
      </div>
    </div>
  `;
}

// ── IAM-015: Device Code Flow (CLI Auth) ─────────────────────────────────
export function renderDeviceCodeAuth(opts: PortalViewBaseOpts & { userCode?: string }): string {
  const code = (opts.userCode || "WBX9-4K72").replace("-", "");
  return `
    <div class="auth-container" style="max-width: 440px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Terminal & CLI Access</span>
          <h1>Authorize Device</h1>
          <p>Confirm the 8-character device pairing code shown in your terminal shell.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/device">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>

          <div class="form-group">
            <label class="form-label" for="device-code" style="text-align: center;">Pairing User Code</label>
            <input
              id="device-code"
              type="text"
              name="user_code"
              maxlength="9"
              required
              autofocus
              placeholder="WBX9-4K72"
              value="${escapeHtml(code.slice(0, 4) + '-' + code.slice(4))}"
              class="form-input"
              style="text-align: center; font-family: monospace; font-size: 1.35rem; font-weight: 700; letter-spacing: 0.15em;"
            />
          </div>

          <div style="font-size: 0.72rem; color: var(--text-muted); text-align: center; margin: 12px 0;">
            ⏱ Device authorization codes expire in 10 minutes.
          </div>

          <button type="submit" class="btn-submit">
            <span>Authorize CLI Terminal Session →</span>
          </button>
        </form>
      </div>
    </div>
  `;
}

// ── IAM-016: Account Suspended / Threat Response ────────────────────────
export function renderAccountSuspended(opts: PortalViewBaseOpts & { incidentId?: string; reason?: string }): string {
  return `
    <div class="auth-container" style="max-width: 460px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="radar-ring" style="color: var(--error-solid); background: var(--error-bg);">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
        </div>

        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow" style="color: var(--error-text);">SecOps Security Lockout</span>
          <h1>Account suspended</h1>
          <p>${escapeHtml(opts.reason || "Suspended by automated threat defense policy due to excessive failed attempts or anomalous geolocation.")}</p>
        </div>

        <div style="padding: 12px; background: var(--error-bg); border: 1px solid var(--error-border); border-radius: 8px; margin: 16px 0; font-size: 0.75rem; color: var(--error-text);">
          <strong>Incident Ticket:</strong> ${escapeHtml(opts.incidentId || "SEC-2026-9481")}<br/>
          <strong>Enforcement Zone:</strong> Global Sovereign Vault • Cell US-EAST-1A
        </div>

        <div style="display: flex; flex-direction: column; gap: 8px;">
          <a href="/oidc/secops/yubikey-verify" class="btn-submit" style="text-decoration: none; text-align: center;">
            Verify identity with hardware key (YubiKey)
          </a>
          <a href="/support" class="social-btn" style="justify-content: center; text-decoration: none;">
            Contact Enterprise IT Security Helpdesk
          </a>
        </div>

        <p class="auth-alternative" style="margin-top: 16px; text-align: center;">
          <a href="/oidc/login" class="auth-link">← Return to standard sign in</a>
        </p>
      </div>
    </div>
  `;
}

// ── REG-002: Identity & OTP Verification ────────────────────────────────
export function renderRegisterVerifyOtp(opts: PortalViewBaseOpts & { email?: string; timerSeconds?: number }): string {
  return `
    <div class="auth-container" style="max-width: 480px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow">Step 2 of 4 — Identity Verification</span>
          <h1>Verify your identity</h1>
          <p>Enter the 6-digit cryptographic verification code sent to <strong>${escapeHtml(opts.email || "your work email")}</strong>.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/register/verify-otp">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="email" value="${escapeHtml(opts.email || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo || "/")}"/>

          <div class="mfa-pin-grid">
            <input type="text" class="mfa-pin-box" maxlength="1" autofocus data-otp-index="0"/>
            <input type="text" class="mfa-pin-box" maxlength="1" data-otp-index="1"/>
            <input type="text" class="mfa-pin-box" maxlength="1" data-otp-index="2"/>
            <input type="text" class="mfa-pin-box" maxlength="1" data-otp-index="3"/>
            <input type="text" class="mfa-pin-box" maxlength="1" data-otp-index="4"/>
            <input type="text" class="mfa-pin-box" maxlength="1" data-otp-index="5"/>
          </div>
          <input type="hidden" id="otp-combined" name="otp_code"/>

          <div style="text-align: center; font-size: 0.78rem; color: var(--text-muted); margin-bottom: 16px;">
            Didn't receive the verification code? <a href="#" class="auth-link" id="resend-link">Resend in 45s</a>
          </div>

          <button type="submit" class="btn-submit">
            <span>Confirm Identity & Provision Cloud →</span>
          </button>
        </form>

        <p class="auth-alternative" style="margin-top: 16px; text-align: center;">
          <a href="/oidc/register" class="auth-link">← Change email address</a>
        </p>
      </div>
    </div>
    <script>
      (function() {
        var boxes = document.querySelectorAll('.mfa-pin-box');
        var combined = document.getElementById('otp-combined');
        boxes.forEach(function(box, i) {
          box.addEventListener('input', function(e) {
            if (box.value && i < 5) boxes[i + 1].focus();
            update();
          });
          box.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' && !box.value && i > 0) boxes[i - 1].focus();
          });
        });
        function update() {
          var code = '';
          boxes.forEach(function(b) { code += b.value; });
          combined.value = code;
          if (code.length === 6) combined.form.submit();
        }
      })();
    </script>
  `;
}

// ── REG-003: Sovereign Provisioning Engine ──────────────────────────────
export function renderProvisioningStatus(opts: PortalViewBaseOpts & { progress?: number; subdomain?: string }): string {
  const progress = opts.progress || 78;
  const subdomain = opts.subdomain || "acme";
  return `
    <div class="auth-container" style="max-width: 640px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow">Step 3 of 4 — Sovereign Cloud Provisioning</span>
          <h1>Provisioning sovereign partition</h1>
          <p>Deploying enterprise database shards, tenant schema, and KMS cryptographic boundaries.</p>
        </div>

        <!-- Progress ring container -->
        <div style="display: flex; justify-content: center; margin: 20px 0;">
          <div style="width: 96px; height: 96px; border-radius: 50%; border: 6px solid var(--border-card); border-top-color: var(--brand-primary); display: flex; align-items: center; justify-content: center; font-size: 1.5rem; font-weight: 800; font-family: monospace; animation: spinRing 2s linear infinite;">
            ${progress}%
          </div>
        </div>

        <!-- Checklist -->
        <div style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 20px;">
          <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-hero); border-radius: 6px; font-size: 0.78rem;">
            <span>Initializing Tenant Vault & Dedicated Envelope Keys</span>
            <span style="color: var(--success-solid); font-weight: 700;">✓ Done</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-hero); border-radius: 6px; font-size: 0.78rem;">
            <span>Allocating Isolated PostgreSQL RLS Partition & Schema Migrations</span>
            <span style="color: var(--success-solid); font-weight: 700;">✓ Done</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-hero); border-radius: 6px; font-size: 0.78rem;">
            <span>Generating Root OIDC Client Credentials & mTLS Certificates</span>
            <span style="color: var(--brand-primary); font-weight: 700;">⟳ Provisioning</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-hero); border-radius: 6px; font-size: 0.78rem; opacity: 0.6;">
            <span>Registering Admin Security Principal & Seeding RBAC Matrix</span>
            <span style="color: var(--text-muted);">Pending</span>
          </div>
          <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-hero); border-radius: 6px; font-size: 0.78rem; opacity: 0.6;">
            <span>Deploying Edge CDN Route & DNS Provisioning</span>
            <span style="color: var(--text-muted);">Pending</span>
          </div>
        </div>

        <div style="text-align: center;">
          <a href="https://${escapeHtml(subdomain)}.unierp.cloud" class="btn-submit" style="text-decoration: none; display: inline-flex;">
            <span>🚀 Launch Workspace (${escapeHtml(subdomain)}.unierp.cloud)</span>
          </a>
        </div>
      </div>
    </div>
  `;
}

// ── REG-004: Domain Collision & SSO Redirection ──────────────────────────
export function renderDomainCollision(opts: PortalViewBaseOpts & { domain?: string; orgName?: string; idpName?: string }): string {
  const domain = opts.domain || "enterprise.com";
  const orgName = opts.orgName || "Acme Global Technologies";
  const idpName = opts.idpName || "Okta SSO";

  return `
    <div class="auth-container" style="max-width: 480px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="radar-ring" style="color: var(--brand-primary); background: var(--brand-light);">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
          </svg>
        </div>

        <div class="auth-header" style="text-align: center;">
          <span class="auth-eyebrow">Enterprise Domain Policy</span>
          <h1>Organization already registered</h1>
          <p>Your email domain <strong>@${escapeHtml(domain)}</strong> is managed by <strong>${escapeHtml(orgName)}</strong>.</p>
        </div>

        <div style="padding: 14px; background: var(--bg-hero); border: 1px solid var(--border-card); border-radius: 8px; margin: 16px 0; font-size: 0.78rem; line-height: 1.5; color: var(--text-secondary);">
          <div><strong>Workspace:</strong> acme.unierp.cloud</div>
          <div><strong>SSO Provider:</strong> ${escapeHtml(idpName)} Mandatory</div>
          <div><strong>Policy:</strong> Self-service workspace registration is restricted. All team members must authenticate via your corporate identity provider.</div>
        </div>

        <div style="display: flex; flex-direction: column; gap: 8px;">
          <a href="/oidc/sso?domain=${encodeURIComponent(domain)}" class="btn-submit" style="text-decoration: none; text-align: center;">
            <span>Sign In via ${escapeHtml(idpName)} →</span>
          </a>
          <a href="/support/request-workspace-access" class="social-btn" style="justify-content: center; text-decoration: none;">
            Request Access from Workspace Administrator
          </a>
        </div>

        <p class="auth-alternative" style="margin-top: 16px; text-align: center;">
          <a href="/oidc/register" class="auth-link">Use a different email address</a>
        </p>
      </div>
    </div>
  `;
}
