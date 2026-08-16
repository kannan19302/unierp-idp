// =============================================================================
// UniERP Global Authentication Gateway — Login Controller
// =============================================================================

(function () {
  'use strict';

  // DOM Elements
  const elThemeSelect = document.getElementById('themeSelect');
  const elBtnDensityToggle = document.getElementById('btnDensityToggle');
  const elDensityLabel = document.getElementById('densityLabel');
  const elAuthTabs = document.querySelectorAll('.auth-tab');
  const elTabPanes = {
    persona: document.getElementById('panePersona'),
    credentials: document.getElementById('paneCredentials'),
    sso: document.getElementById('paneSSO')
  };
  const elLoginForm = document.getElementById('loginForm');
  const elInputEmail = document.getElementById('inputEmail');
  const elInputPassword = document.getElementById('inputPassword');
  const elBtnTogglePw = document.getElementById('btnTogglePw');
  const elBtnDemoFill = document.getElementById('btnDemoFill');
  const elSelectTargetPlatform = document.getElementById('selectTargetPlatform');
  const elRealmIndicator = document.getElementById('realmIndicator');
  const elRealmText = document.getElementById('realmText');
  const elBtnSubmitAuth = document.getElementById('btnSubmitAuth');
  const elBtnSubmitText = document.getElementById('btnSubmitText');
  const elLoginToast = document.getElementById('loginToast');
  const elToastTitle = document.getElementById('toastTitle');
  const elToastMsg = document.getElementById('toastMsg');
  const elToastIcon = document.getElementById('toastIcon');

  // URL Params (e.g. ?redirect=/&targetPlatform=p3&role=tenant_admin)
  const urlParams = new URLSearchParams(window.location.search);
  const redirectTarget = urlParams.get('redirect') || '/';
  const initialPlatform = urlParams.get('targetPlatform') || 'wizard';

  // ── Initialize ─────────────────────────────────────────────────────────────
  function init() {
    initThemeAndDensity();
    setupEventListeners();
    checkExistingSession();

    if (initialPlatform && elSelectTargetPlatform) {
      elSelectTargetPlatform.value = initialPlatform;
    }
  }

  // ── Theme & Density Management ─────────────────────────────────────────────
  function initThemeAndDensity() {
    const savedTheme = localStorage.getItem('unierp_theme') || 'dark';
    const savedDensity = localStorage.getItem('unierp_density') || 'comfortable';

    applyTheme(savedTheme);
    applyDensity(savedDensity);

    if (elThemeSelect) elThemeSelect.value = savedTheme;
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.setAttribute('data-theme', theme);
    localStorage.setItem('unierp_theme', theme);
  }

  function applyDensity(density) {
    document.documentElement.setAttribute('data-density', density);
    document.body.setAttribute('data-density', density);
    localStorage.setItem('unierp_density', density);
    if (elDensityLabel) {
      elDensityLabel.textContent = density === 'compact' ? 'Comfortable' : 'Compact';
    }
  }

  // ── Setup Event Listeners ──────────────────────────────────────────────────
  function setupEventListeners() {
    // Theme Select
    if (elThemeSelect) {
      elThemeSelect.addEventListener('change', (e) => applyTheme(e.target.value));
    }

    // Density Toggle
    if (elBtnDensityToggle) {
      elBtnDensityToggle.addEventListener('click', () => {
        const currentDensity = document.documentElement.getAttribute('data-density') || 'comfortable';
        const nextDensity = currentDensity === 'compact' ? 'comfortable' : 'compact';
        applyDensity(nextDensity);
      });
    }

    // Auth Tabs
    elAuthTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const tabKey = tab.dataset.tab;
        elAuthTabs.forEach(t => {
          t.classList.remove('active');
          t.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');

        Object.keys(elTabPanes).forEach(k => {
          if (elTabPanes[k]) {
            elTabPanes[k].classList.toggle('active', k === tabKey);
          }
        });
      });
    });

    // 1-Click Persona Cards & Buttons
    document.querySelectorAll('.btn-persona-select, .persona-card').forEach(elem => {
      elem.addEventListener('click', (e) => {
        const role = elem.dataset.role || elem.closest('.persona-card')?.dataset.role;
        if (role) {
          authenticateWithRole(role);
        }
      });
    });

    // Live Email Domain & Realm Detection
    if (elInputEmail) {
      elInputEmail.addEventListener('input', handleEmailInput);
    }

    // Password Show/Hide Toggle
    if (elBtnTogglePw && elInputPassword) {
      elBtnTogglePw.addEventListener('click', () => {
        const isPassword = elInputPassword.type === 'password';
        elInputPassword.type = isPassword ? 'text' : 'password';
        elBtnTogglePw.textContent = isPassword ? '🔒' : '👁️';
      });
    }

    // Autofill Demo Password
    if (elBtnDemoFill && elInputPassword && elInputEmail) {
      elBtnDemoFill.addEventListener('click', (e) => {
        e.preventDefault();
        elInputEmail.value = 'alex.rivera@acme-corp.com';
        elInputPassword.value = 'unierp2026-secure';
        handleEmailInput();
      });
    }

    // Credentials Form Submit
    if (elLoginForm) {
      elLoginForm.addEventListener('submit', handleCredentialSubmit);
    }

    // Enterprise SSO Provider Buttons
    document.querySelectorAll('.btn-sso-provider').forEach(btn => {
      btn.addEventListener('click', () => {
        const ssoType = btn.dataset.sso;
        showToast('Initiating Enterprise SSO', `Connecting to ${ssoType.toUpperCase()} Identity Provider...`, '🔷');
        setTimeout(() => {
          authenticateWithRole('customer_employee');
        }, 800);
      });
    });
  }

  // ── Live Email Input & Tenant Realm Detection ──────────────────────────────
  function handleEmailInput() {
    const val = elInputEmail.value.trim().toLowerCase();
    if (!val || !val.includes('@')) {
      elRealmIndicator.style.display = 'none';
      return;
    }

    const domain = val.split('@')[1];
    if (domain === 'unierp.internal' || val.includes('kannan')) {
      elRealmIndicator.style.display = 'flex';
      elRealmText.innerHTML = `Provider Realm: <strong>UniERP Core Platform Team (SuperAdmin)</strong>`;
      elRealmIndicator.className = 'realm-indicator realm-team';
    } else if (domain === 'acme-corp.com') {
      elRealmIndicator.style.display = 'flex';
      elRealmText.innerHTML = `Detected Tenant: <strong>Acme Global Ltd (Tenant #104)</strong>`;
      elRealmIndicator.className = 'realm-indicator realm-tenant';
    } else if (domain) {
      elRealmIndicator.style.display = 'flex';
      elRealmText.innerHTML = `Dedicated Tenant Realm: <strong>${domain}</strong>`;
      elRealmIndicator.className = 'realm-indicator realm-tenant';
    } else {
      elRealmIndicator.style.display = 'none';
    }
  }

  // ── Authenticate via Selected Persona Role ─────────────────────────────────
  async function authenticateWithRole(role) {
    showToast('Authenticating Session', `Issuing signed SSO delegation token for role '${role}'...`, '🔑');
    try {
      const targetPlatform = elSelectTargetPlatform ? elSelectTargetPlatform.value : 'wizard';
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role, targetPlatform })
      });
      const data = await res.json();

      if (data.success) {
        showToast('Authentication Verified', `Welcome back, ${data.user.name}! Routing...`, '✨');
        
        setTimeout(() => {
          if (targetPlatform && targetPlatform !== 'wizard') {
            window.location.href = `/api/sso/launch/${targetPlatform}?format=redirect`;
          } else {
            window.location.href = redirectTarget;
          }
        }, 500);
      } else {
        showToast('Login Failed', data.error || 'Authentication error', '❌');
      }
    } catch (e) {
      console.error('Login error:', e);
      showToast('Network Error', 'Could not reach UniERP Auth Gateway', '❌');
    }
  }

  // ── Handle Credential Form Submission ──────────────────────────────────────
  async function handleCredentialSubmit(e) {
    e.preventDefault();
    const email = elInputEmail.value.trim();
    const password = elInputPassword.value;
    const targetPlatform = elSelectTargetPlatform.value;

    if (!email || !password) {
      showToast('Validation Error', 'Email and password are required', '⚠️');
      return;
    }

    elBtnSubmitAuth.disabled = true;
    elBtnSubmitText.textContent = 'Verifying Credentials...';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, targetPlatform })
      });
      const data = await res.json();

      if (data.success) {
        showToast('Sign-In Successful', `Signed in as ${data.user.name}. Redirecting...`, '✨');
        setTimeout(() => {
          if (targetPlatform && targetPlatform !== 'wizard') {
            window.location.href = `/api/sso/launch/${targetPlatform}?format=redirect`;
          } else {
            window.location.href = redirectTarget;
          }
        }, 500);
      } else {
        showToast('Authentication Denied', data.error || 'Invalid email or password', '❌');
        elBtnSubmitAuth.disabled = false;
        elBtnSubmitText.textContent = 'Authenticate & Launch Gateway';
      }
    } catch (err) {
      showToast('Connection Error', err.message, '❌');
      elBtnSubmitAuth.disabled = false;
      elBtnSubmitText.textContent = 'Authenticate & Launch Gateway';
    }
  }

  // ── Check if already logged in ─────────────────────────────────────────────
  async function checkExistingSession() {
    try {
      const res = await fetch('/api/auth/session');
      const data = await res.json();
      if (data.authenticated && data.user) {
        showToast('Active Session Detected', `Signed in as ${data.user.name} (${data.user.role})`, '👤');
      }
    } catch (e) {}
  }

  // ── Toast Notification Helper ──────────────────────────────────────────────
  let toastTimer = null;
  function showToast(title, msg, icon = '✨') {
    if (!elLoginToast) return;
    elToastTitle.textContent = title;
    elToastMsg.textContent = msg;
    if (elToastIcon) elToastIcon.textContent = icon;
    elLoginToast.classList.add('show');

    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      elLoginToast.classList.remove('show');
    }, 4000);
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
