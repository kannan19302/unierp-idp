import { describe, it, expect } from "vitest";
import {
  escapeHtml,
  renderEmailTemplate,
  renderVerificationEmail,
  renderWelcomeEmail,
  renderPasswordResetEmail,
  renderLoginAlertEmail,
  renderOtpEmail,
  SYSTEM_EMAIL_TEMPLATES,
} from "../index";

describe("Email Templates Engine", () => {
  describe("escapeHtml", () => {
    it("escapes dangerous HTML characters", () => {
      const malicious = '<script>alert("xss")</script> & \'test\'';
      const escaped = escapeHtml(malicious);
      expect(escaped).not.toContain("<script>");
      expect(escaped).toContain("&lt;script&gt;");
      expect(escaped).toContain("&amp;");
      expect(escaped).toContain("&quot;xss&quot;");
      expect(escaped).toContain("&#039;test&#039;");
    });

    it("handles null and undefined safely", () => {
      expect(escapeHtml(null)).toBe("");
      expect(escapeHtml(undefined)).toBe("");
    });
  });

  describe("renderVerificationEmail", () => {
    it("renders verification email with button link and text fallback", () => {
      const res = renderVerificationEmail({
        firstName: "Jordan",
        verificationLink: "https://auth.unierp.com/verify?token=abc123xyz",
        expiresInHours: 48,
      });

      expect(res.subject).toBe("Verify your UniERP email address");
      expect(res.html).toContain("Hello Jordan,");
      expect(res.html).toContain("https://auth.unierp.com/verify?token=abc123xyz");
      expect(res.html).toContain("48 hours");
      expect(res.html).toContain("Verify Email Address");
      expect(res.text).toContain("https://auth.unierp.com/verify?token=abc123xyz");
    });

    it("defaults to 'there' when firstName is not provided", () => {
      const res = renderVerificationEmail({
        verificationLink: "https://auth.unierp.com/verify",
      });
      expect(res.html).toContain("Hello there,");
      expect(res.html).toContain("24 hours");
    });
  });

  describe("renderWelcomeEmail", () => {
    it("renders welcome email with organization name and quick-start steps", () => {
      const res = renderWelcomeEmail({
        firstName: "Sarah",
        organizationName: "Global Corp",
        workspaceUrl: "https://app.unierp.com",
        setupUrl: "https://app.unierp.com/setup",
      });

      expect(res.subject).toContain("Global Corp");
      expect(res.html).toContain("Hello Sarah,");
      expect(res.html).toContain("Global Corp");
      expect(res.html).toContain("Complete Setup Wizard");
      expect(res.html).toContain("Invite Your Team");
      expect(res.html).toContain("https://app.unierp.com/setup");
      expect(res.text).toContain("Launch your workspace now");
    });
  });

  describe("renderPasswordResetEmail", () => {
    it("renders password reset email with expiry and security warnings", () => {
      const res = renderPasswordResetEmail({
        firstName: "Alex",
        resetLink: "https://auth.unierp.com/reset?token=xyz",
        expiresInMinutes: 15,
        ipAddress: "203.0.113.195",
      });

      expect(res.subject).toBe("Reset your UniERP password");
      expect(res.html).toContain("Hello Alex,");
      expect(res.html).toContain("15 minutes");
      expect(res.html).toContain("203.0.113.195");
      expect(res.html).toContain("Reset Password");
    });
  });

  describe("renderLoginAlertEmail", () => {
    it("renders security alert with device, location, and IP table", () => {
      const res = renderLoginAlertEmail({
        firstName: "Taylor",
        device: "Safari on iPhone",
        location: "London, UK",
        ipAddress: "198.51.100.2",
        securityUrl: "https://app.unierp.com/security",
      });

      expect(res.subject).toContain("Security Alert");
      expect(res.html).toContain("Safari on iPhone");
      expect(res.html).toContain("London, UK");
      expect(res.html).toContain("198.51.100.2");
      expect(res.html).toContain("Review Account Security");
    });
  });

  describe("renderOtpEmail", () => {
    it("renders 6-digit OTP code in prominent styled box", () => {
      const res = renderOtpEmail({
        code: "749281",
        expiresInMinutes: 5,
      });

      expect(res.subject).toBe("Your UniERP verification code");
      expect(res.html).toContain("749281");
      expect(res.html).toContain("5 minutes");
      expect(res.text).toContain("749281");
    });
  });

  describe("renderEmailTemplate universal dispatcher", () => {
    it("dispatches all registered templates successfully", () => {
      for (const meta of SYSTEM_EMAIL_TEMPLATES) {
        const result = renderEmailTemplate(meta.key, meta.sampleVariables);
        expect(result.subject).toBeTruthy();
        expect(result.html).toContain("UniERP");
        expect(result.text).toBeTruthy();
      }
    });

    it("throws error for unknown template key", () => {
      expect(() =>
        renderEmailTemplate("non_existent" as any, {}),
      ).toThrowError(/Unknown email template/);
    });
  });
});
