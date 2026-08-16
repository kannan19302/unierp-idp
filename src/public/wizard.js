// =============================================================================
// UniERP Master SSO Platform Wizard & Gateway — Client Controller
// =============================================================================

(function () {
  'use strict';

  // State
  let currentRole = 'guest';
  let currentUser = null;
  let platforms = [];
  let healthMatrix = [];
  let activeFilter = 'all';
  let searchQuery = '';
  let currentView = 'grid'; // 'grid' | 'table' | 'topology'

  // SVG Icons Map
  const ICONS = {
    'globe': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`,
    'shield-alert': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`,
    'layout-grid': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>`,
    'store': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>`,
    'palette': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="13.5" cy="6.5" r=".5"></circle><circle cx="17.5" cy="10.5" r=".5"></circle><circle cx="8.5" cy="7.5" r=".5"></circle><circle cx="6.5" cy="12.5" r=".5"></circle><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"></path></svg>`,
    'settings-2': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 7h-9"></path><path d="M14 17H5"></path><circle cx="17" cy="17" r="3"></circle><circle cx="7" cy="7" r="3"></circle></svg>`,
    'shopping-bag': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4Z"></path><path d="M3 6h18"></path><path d="M16 10a4 4 0 0 1-8 0"></path></svg>`,
    'code-2': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
    'smartphone': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>`,
    'monitor': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>`
  };

  // DOM Elements
  const elCatalogContainer = document.getElementById('catalogContainer');
  const elInfraGrid = document.getElementById('infraGrid');
  const elPersonaPills = document.getElementById('personaPills');
  const elUserName = document.getElementById('userName');
  const elUserAvatar = document.getElementById('userAvatar');
  const elUserRoleBadge = document.getElementById('userRoleBadge');
  const elDevControlDeck = document.getElementById('devControlDeck');
  const elHeroBadgeText = document.getElementById('heroBadgeText');
  const elHeroTitle = document.getElementById('heroTitle');
  const elHeroDesc = document.getElementById('heroDesc');
  const elSectionRoleDesc = document.getElementById('sectionRoleDesc');
  const elStatPlatformsCount = document.getElementById('statPlatformsCount');
  const elStatOnlineCount = document.getElementById('statOnlineCount');
  const elStatAvgLatency = document.getElementById('statAvgLatency');
  const elHealthText = document.getElementById('healthText');
  const elBtnRefresh = document.getElementById('btnRefresh');
  const elThemeSelect = document.getElementById('themeSelect');
  const elBtnDensityToggle = document.getElementById('btnDensityToggle');
  const elDensityLabel = document.getElementById('densityLabel');
  const elPlatformSearchInput = document.getElementById('platformSearchInput');
  const elBtnRunE2E = document.getElementById('btnRunE2E');
  const elTestTerminal = document.getElementById('testTerminal');
  const elTerminalOutput = document.getElementById('terminalOutput');
  const elBtnCloseTerminal = document.getElementById('btnCloseTerminal');
  const elSsoToast = document.getElementById('ssoToast');
  const elToastTitle = document.getElementById('toastTitle');
  const elToastMsg = document.getElementById('toastMsg');
  const elBtnCmdPalette = document.getElementById('btnCmdPalette');
  const elCmdPaletteBackdrop = document.getElementById('commandPaletteBackdrop');
  const elPaletteSearchInput = document.getElementById('paletteSearchInput');
  const elPaletteResultsList = document.getElementById('paletteResultsList');

  // ── Initialize App ─────────────────────────────────────────────────────────
  async function init() {
    initThemeAndDensity();
    setupEventListeners();
    await fetchSession();
    await fetchPlatforms();
    await fetchHealthMatrix();

    // Auto-refresh cluster health matrix every 10 seconds
    setInterval(fetchHealthMatrix, 10000);
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
    // Theme Select Change
    if (elThemeSelect) {
      elThemeSelect.addEventListener('change', (e) => applyTheme(e.target.value));
    }

    // Density Toggle Button
    if (elBtnDensityToggle) {
      elBtnDensityToggle.addEventListener('click', () => {
        const currentDensity = document.documentElement.getAttribute('data-density') || 'comfortable';
        const nextDensity = currentDensity === 'compact' ? 'comfortable' : 'compact';
        applyDensity(nextDensity);
      });
    }

    // Persona Pills Click
    if (elPersonaPills) {
      elPersonaPills.addEventListener('click', async (e) => {
        const pill = e.target.closest('.pill');
        if (!pill) return;
        const role = pill.dataset.role;
        if (role === currentRole) return;

        elPersonaPills.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');

        await switchPersona(role);
      });
    }

    // Refresh Button Click
    if (elBtnRefresh) {
      elBtnRefresh.addEventListener('click', async () => {
        elBtnRefresh.style.transform = 'rotate(180deg)';
        await fetchHealthMatrix();
        await fetchPlatforms();
        setTimeout(() => elBtnRefresh.style.transform = 'none', 300);
      });
    }

    // Filter Buttons Click
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.dataset.filter;
        renderActiveView();
      });
    });

    // View Mode Switcher Click
    document.querySelectorAll('.btn-view-mode').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.btn-view-mode').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentView = btn.dataset.view;
        renderActiveView();
      });
    });

    // Search Input in Catalog Toolbar
    if (elPlatformSearchInput) {
      elPlatformSearchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.toLowerCase().trim();
        renderActiveView();
      });
    }

    // Command Palette Trigger & Keyboard Shortcut (Ctrl+K / Cmd+K)
    if (elBtnCmdPalette) {
      elBtnCmdPalette.addEventListener('click', openCommandPalette);
    }

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        openCommandPalette();
      } else if (e.key === 'Escape') {
        closeCommandPalette();
      }
    });

    if (elCmdPaletteBackdrop) {
      elCmdPaletteBackdrop.addEventListener('click', (e) => {
        if (e.target === elCmdPaletteBackdrop) closeCommandPalette();
      });
    }

    if (elPaletteSearchInput) {
      elPaletteSearchInput.addEventListener('input', renderCommandPaletteResults);
    }

    // E2E Test Suite Runner Button
    if (elBtnRunE2E) {
      elBtnRunE2E.addEventListener('click', runE2ETests);
    }

    if (elBtnCloseTerminal) {
      elBtnCloseTerminal.addEventListener('click', () => {
        elTestTerminal.style.display = 'none';
      });
    }
  }

  // ── Fetch Session & User Profile ───────────────────────────────────────────
  async function fetchSession() {
    try {
      const res = await fetch('/api/auth/session');
      const data = await res.json();
      currentUser = data.user;
      currentRole = currentUser.role || 'guest';
      updateUserUI();
    } catch (e) {
      console.error('Session fetch error:', e);
    }
  }

  // ── Switch Persona ─────────────────────────────────────────────────────────
  async function switchPersona(role) {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role })
      });
      const data = await res.json();
      if (data.success) {
        currentUser = data.user;
        currentRole = role;
        updateUserUI();
        await fetchPlatforms();
        showToast('Persona Switched', `Active role changed to ${currentUser.badge}`);
      }
    } catch (e) {
      console.error('Persona switch error:', e);
    }
  }

  // ── Update User & Hero UI for Active Role ──────────────────────────────────
  function updateUserUI() {
    if (!currentUser) return;

    if (elUserName) elUserName.textContent = currentUser.name;
    if (elUserRoleBadge) elUserRoleBadge.textContent = currentUser.badge;
    if (elUserAvatar) elUserAvatar.textContent = (currentUser.avatar || currentUser.name.charAt(0)).toUpperCase();

    // Update Persona Pills Active State
    if (elPersonaPills) {
      elPersonaPills.querySelectorAll('.pill').forEach(p => {
        p.classList.toggle('active', p.dataset.role === currentRole);
      });
    }

    // Role-specific Header Adjustments
    if (currentRole === 'guest') {
      if (elHeroBadgeText) elHeroBadgeText.textContent = 'Public Access Mode — Zero Login Required for Public Platforms';
      if (elHeroTitle) elHeroTitle.textContent = 'Global Platform Switcher & Gateway';
      if (elHeroDesc) elHeroDesc.textContent = 'Browse public UniERP platforms freely without credentials. Sign in to access your organization\'s business ERP, web builder, and admin consoles.';
      if (elSectionRoleDesc) elSectionRoleDesc.textContent = 'Displaying public storefronts, marketing sites, open marketplace, and developer docs.';
      if (elDevControlDeck) elDevControlDeck.style.display = 'none';
    } else if (currentRole === 'customer_employee') {
      if (elHeroBadgeText) elHeroBadgeText.textContent = `Tenant Staff Workspace — ${currentUser.tenant}`;
      if (elHeroTitle) elHeroTitle.textContent = 'Tenant Business Applications Switcher';
      if (elHeroDesc) elHeroDesc.textContent = '1-Click Single Sign-On into your assigned business applications. Move between ERP, Mobile, and Desktop clients without re-authenticating.';
      if (elSectionRoleDesc) elSectionRoleDesc.textContent = 'Displaying business core apps and client platforms authorized for staff.';
      if (elDevControlDeck) elDevControlDeck.style.display = 'none';
    } else if (currentRole === 'tenant_admin') {
      if (elHeroBadgeText) elHeroBadgeText.textContent = `Tenant Administrator Launchpad — ${currentUser.tenant}`;
      if (elHeroTitle) elHeroTitle.textContent = 'Organization Control & Applications Launchpad';
      if (elHeroDesc) elHeroDesc.textContent = 'Master control for your organization. Launch ERP, visual Web Studio builder, Tenant Admin console, and Marketplace with instant SSO handoff.';
      if (elSectionRoleDesc) elSectionRoleDesc.textContent = 'Displaying all tenant applications, builders, and admin consoles (Provider OS hidden).';
      if (elDevControlDeck) elDevControlDeck.style.display = 'none';
    } else if (currentRole === 'unierp_team') {
      if (elHeroBadgeText) elHeroBadgeText.textContent = 'UniERP Core Team & SuperAdmin Master Deck';
      if (elHeroTitle) elHeroTitle.textContent = '10-Platform Master Control & Diagnostics';
      if (elHeroDesc) elHeroDesc.textContent = 'Full access to all 10 platforms including Provider Admin OS (P2), real-time Docker container telemetry, and automated End-to-End test suites.';
      if (elSectionRoleDesc) elSectionRoleDesc.textContent = 'Displaying all 10 presentation & client platforms + backend monitoring.';
      if (elDevControlDeck) elDevControlDeck.style.display = 'block';
    }
  }

  // ── Fetch Platforms for Active Role ────────────────────────────────────────
  async function fetchPlatforms() {
    try {
      const res = await fetch(`/api/platforms?role=${currentRole}`);
      const data = await res.json();
      platforms = data.platforms || [];
      if (elStatPlatformsCount) {
        elStatPlatformsCount.textContent = `${platforms.length} / ${data.totalAvailable || 10}`;
      }
      renderActiveView();
    } catch (e) {
      console.error('Platforms fetch error:', e);
      if (elCatalogContainer) {
        elCatalogContainer.innerHTML = `<div class="error-placeholder">Failed to load platform catalog</div>`;
      }
    }
  }

  // ── Fetch Live Health Matrix ───────────────────────────────────────────────
  async function fetchHealthMatrix() {
    try {
      const res = await fetch('/api/health/matrix');
      const data = await res.json();
      healthMatrix = data.matrix || [];

      if (elStatOnlineCount) {
        elStatOnlineCount.textContent = `${data.onlineCount} / ${data.totalCount}`;
      }
      if (elHealthText) {
        elHealthText.textContent = `${data.onlineCount}/${data.totalCount} Services Online`;
      }

      const onlineServices = healthMatrix.filter(h => h.status === 'online');
      if (onlineServices.length > 0 && elStatAvgLatency) {
        const avg = Math.round(onlineServices.reduce((sum, s) => sum + s.latency, 0) / onlineServices.length);
        elStatAvgLatency.textContent = `${avg} ms`;
      }

      renderActiveView();
      renderInfraMatrix();
    } catch (e) {
      console.error('Health matrix fetch error:', e);
      if (elHealthText) elHealthText.textContent = 'Health check paused';
    }
  }

  // ── Get Filtered Platforms ─────────────────────────────────────────────────
  function getFilteredPlatforms() {
    let list = platforms;

    // Category Filter
    if (activeFilter === 'public') {
      list = list.filter(p => p.isPublic);
    } else if (activeFilter === 'business') {
      list = list.filter(p => ['p3', 'p5', 'p6', 'p9', 'p10'].includes(p.id));
    } else if (activeFilter === 'L4 Presentation') {
      list = list.filter(p => p.layer.includes('L4'));
    } else if (activeFilter === 'L5 Client') {
      list = list.filter(p => p.layer.includes('L5'));
    }

    // Search Query Filter
    if (searchQuery) {
      list = list.filter(p => 
        p.name.toLowerCase().includes(searchQuery) ||
        p.code.toLowerCase().includes(searchQuery) ||
        p.description.toLowerCase().includes(searchQuery) ||
        p.port.toString().includes(searchQuery) ||
        (p.tags && p.tags.some(t => t.toLowerCase().includes(searchQuery)))
      );
    }

    return list;
  }

  // ── Multi-View Render Dispatcher ───────────────────────────────────────────
  function renderActiveView() {
    if (!elCatalogContainer) return;
    const filtered = getFilteredPlatforms();

    if (currentView === 'table') {
      renderTableView(filtered);
    } else if (currentView === 'topology') {
      renderTopologyView(filtered);
    } else {
      renderGridView(filtered);
    }
  }

  // ── View 1: Card Grid View ─────────────────────────────────────────────────
  function renderGridView(filtered) {
    if (!filtered || filtered.length === 0) {
      elCatalogContainer.innerHTML = `<div class="empty-state" style="padding: 2rem; text-align: center; color: var(--color-text-tertiary);">No platforms found matching current filter or search criteria.</div>`;
      return;
    }

    const html = `
      <div class="platforms-grid" id="platformsGrid">
        ${filtered.map(p => {
          const health = healthMatrix.find(h => h.id === p.id) || { status: 'checking', latency: 0 };
          const isOnline = health.status === 'online';
          const iconSvg = ICONS[p.icon] || ICONS['globe'];
          const isInternal = p.id === 'p2';
          const isGuest = currentRole === 'guest';

          let buttonHtml = '';
          if (p.isPublic && isGuest) {
            buttonHtml = `
              <a href="${p.url}" target="_blank" class="btn-launch-sso" style="background: var(--color-success);">
                <span>Open Public Portal</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
              </a>
            `;
          } else {
            buttonHtml = `
              <button class="btn-launch-sso" onclick="window.UniERPWizard.launchSSO('${p.id}', '${p.name}')">
                <span>1-Click SSO Launch</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
              </button>
            `;
          }

          const tagsHtml = (p.tags || []).slice(0, 3).map(t => `<span class="feature-chip">${t}</span>`).join('');

          return `
            <div class="platform-card ${isInternal ? 'card-internal' : ''}">
              <div class="card-top">
                <div class="card-title-group">
                  <div class="card-icon">${iconSvg}</div>
                  <div>
                    <span class="platform-code">${p.code} &middot; ${p.layer}</span>
                    <h3 class="platform-name">${p.name}</h3>
                  </div>
                </div>
                <div class="card-badges">
                  <span class="badge-port">:${p.port}</span>
                  <span class="badge-tag ${isInternal ? 'tag-internal' : (p.isPublic ? 'tag-public' : '')}">${p.badge}</span>
                </div>
              </div>

              <div class="card-body">
                <p class="platform-desc">${p.description}</p>
                ${tagsHtml ? `<div class="card-feature-tags">${tagsHtml}</div>` : ''}
                <div class="card-telemetry">
                  <span>
                    <span class="status-dot ${isOnline ? 'online' : 'offline'}"></span>
                    ${isOnline ? 'Online &amp; Healthy' : 'Service Offline / Starting'}
                  </span>
                  <span>${isOnline ? `${health.latency}ms` : '--'}</span>
                </div>
              </div>

              <div class="card-footer">
                ${buttonHtml}
                <a href="${p.url}" target="_blank" class="btn-direct-link" title="Open Standalone Direct URL (${p.url})">
                  Direct :${p.port}
                </a>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;

    elCatalogContainer.innerHTML = html;
  }

  // ── View 2: Enterprise Data Table View ─────────────────────────────────────
  function renderTableView(filtered) {
    if (!filtered || filtered.length === 0) {
      elCatalogContainer.innerHTML = `<div class="empty-state" style="padding: 2rem; text-align: center; color: var(--color-text-tertiary);">No platforms match the current filter.</div>`;
      return;
    }

    const html = `
      <div class="platforms-table-container">
        <table class="enterprise-table">
          <thead>
            <tr>
              <th style="width: 70px;">Code</th>
              <th>Platform Name</th>
              <th>Layer Architecture</th>
              <th>Port</th>
              <th>Access Tier</th>
              <th>Telemetry</th>
              <th style="text-align: right;">Launch Actions</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.map(p => {
              const health = healthMatrix.find(h => h.id === p.id) || { status: 'checking', latency: 0 };
              const isOnline = health.status === 'online';
              const isInternal = p.id === 'p2';

              return `
                <tr>
                  <td class="table-code">${p.code}</td>
                  <td class="table-name">
                    <span>${p.name}</span>
                  </td>
                  <td><span class="feature-chip">${p.layer}</span></td>
                  <td class="table-port">:${p.port}</td>
                  <td>
                    <span class="badge-tag ${isInternal ? 'tag-internal' : (p.isPublic ? 'tag-public' : '')}">
                      ${p.badge}
                    </span>
                  </td>
                  <td>
                    <span class="status-dot ${isOnline ? 'online' : 'offline'}"></span>
                    <span style="font-family: var(--font-mono); font-variant-numeric: tabular-nums;">
                      ${isOnline ? `${health.latency}ms (200 OK)` : 'Offline'}
                    </span>
                  </td>
                  <td style="text-align: right;">
                    <div class="table-actions" style="justify-content: flex-end;">
                      <button class="btn-launch-sso" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;" onclick="window.UniERPWizard.launchSSO('${p.id}', '${p.name}')">
                        Launch SSO
                      </button>
                      <a href="${p.url}" target="_blank" class="btn-direct-link" style="padding: 0.35rem 0.6rem; font-size: 0.75rem;">
                        :${p.port}
                      </a>
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;

    elCatalogContainer.innerHTML = html;
  }

  // ── View 3: Architecture Topology Map View ─────────────────────────────────
  function renderTopologyView(filtered) {
    const l4Platforms = filtered.filter(p => p.layer.includes('L4'));
    const l5Platforms = filtered.filter(p => p.layer.includes('L5'));
    const l3Services = healthMatrix.filter(h => !h.isPlatform);

    const html = `
      <div class="topology-map-container">
        <!-- Layer 5: Clients -->
        <div class="topology-layer-card">
          <div class="topology-layer-header">
            <span class="topology-layer-title">
              <span>📱 Layer 5 — Clients (Mobile &amp; Desktop)</span>
            </span>
            <span class="feature-chip">Touch &amp; Native Shells</span>
          </div>
          <div class="topology-nodes-grid">
            ${l5Platforms.map(p => renderTopologyNode(p)).join('')}
          </div>
        </div>

        <!-- Layer 4: Presentation -->
        <div class="topology-layer-card">
          <div class="topology-layer-header">
            <span class="topology-layer-title">
              <span>🌐 Layer 4 — Presentation Platforms (Web Applications)</span>
            </span>
            <span class="feature-chip">React &middot; Next.js &middot; Astro</span>
          </div>
          <div class="topology-nodes-grid">
            ${l4Platforms.map(p => renderTopologyNode(p)).join('')}
          </div>
        </div>

        <!-- Layer 3: Services & API Gateway -->
        <div class="topology-layer-card">
          <div class="topology-layer-header">
            <span class="topology-layer-title">
              <span>⚡ Layer 3 — Service Monolith &amp; Identity Provider</span>
            </span>
            <span class="feature-chip">Fastify &middot; IdP &middot; Postgres RLS</span>
          </div>
          <div class="topology-nodes-grid">
            ${l3Services.map(s => `
              <div class="topology-node" onclick="window.open('${s.url}', '_blank')">
                <div class="node-meta">
                  <span class="node-title">${s.name}</span>
                  <span class="node-port">${s.layer} &middot; Port :${s.port}</span>
                </div>
                <div>
                  <span class="status-dot ${s.status === 'online' ? 'online' : 'offline'}"></span>
                  <span style="font-size: 0.72rem; font-family: var(--font-mono);">${s.status === 'online' ? `${s.latency}ms` : 'Offline'}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Layer 0-2: Foundation & Runtime -->
        <div class="topology-layer-card" style="background: var(--color-bg-sunken);">
          <div class="topology-layer-header">
            <span class="topology-layer-title" style="color: var(--color-text-secondary);">
              <span>🧱 Layer 0–2 — Contracts, Foundation &amp; Runtime Libraries</span>
            </span>
            <span class="feature-chip">@kannan19302/* Design System &middot; SDK &middot; Data</span>
          </div>
          <p style="font-size: var(--text-xs); color: var(--color-text-tertiary); line-height: 1.5;">
            Hierarchical dependency contract: L7 Operations &rarr; L5 Clients &rarr; L4 Presentation &rarr; L3 Service &rarr; L2 Runtime &rarr; L1 Foundation &rarr; L0 Contracts. A layer depends only on published artifacts of strictly lower layers.
          </p>
        </div>
      </div>
    `;

    elCatalogContainer.innerHTML = html;
  }

  function renderTopologyNode(p) {
    const health = healthMatrix.find(h => h.id === p.id) || { status: 'checking', latency: 0 };
    const isOnline = health.status === 'online';

    return `
      <div class="topology-node" onclick="window.UniERPWizard.launchSSO('${p.id}', '${p.name}')">
        <div class="node-meta">
          <span class="node-title">${p.code} &middot; ${p.name}</span>
          <span class="node-port">Port :${p.port} &middot; ${p.badge}</span>
        </div>
        <div>
          <span class="status-dot ${isOnline ? 'online' : 'offline'}"></span>
          <span style="font-size: 0.72rem; font-family: var(--font-mono);">${isOnline ? `${health.latency}ms` : 'Offline'}</span>
        </div>
      </div>
    `;
  }

  // ── Render Infrastructure Matrix ───────────────────────────────────────────
  function renderInfraMatrix() {
    if (!elInfraGrid) return;
    const infraServices = healthMatrix.filter(h => !h.isPlatform);
    if (!infraServices || infraServices.length === 0) return;

    elInfraGrid.innerHTML = infraServices.map(s => {
      const isOnline = s.status === 'online';
      return `
        <div class="infra-card">
          <div class="infra-meta">
            <span class="infra-name">${s.name}</span>
            <span class="infra-layer">${s.layer} &middot; Port :${s.port}</span>
          </div>
          <div class="infra-status-chip">
            <span class="status-dot ${isOnline ? 'online' : 'offline'}"></span>
            <span>${isOnline ? `${s.latency}ms` : 'Offline'}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  // ── 1-Click Launch SSO Handoff ─────────────────────────────────────────────
  async function launchSSO(platformId, platformName) {
    try {
      showToast('Authenticating SSO', `Issuing signed delegation token for ${platformName}...`);
      const res = await fetch(`/api/sso/launch/${platformId}`);
      const data = await res.json();

      if (data.error) {
        showToast('Access Denied', data.error);
        return;
      }

      showToast('SSO Handshake Complete', `Opening ${platformName} with active session.`);
      setTimeout(() => {
        window.open(data.ssoUrl, '_blank');
      }, 350);
    } catch (e) {
      console.error('SSO Launch error:', e);
      showToast('Launch Error', 'Could not establish SSO session');
    }
  }

  // ── Command Palette (Ctrl+K) ───────────────────────────────────────────────
  function openCommandPalette() {
    if (!elCmdPaletteBackdrop) return;
    elCmdPaletteBackdrop.classList.add('active');
    if (elPaletteSearchInput) {
      elPaletteSearchInput.value = '';
      elPaletteSearchInput.focus();
    }
    renderCommandPaletteResults();
  }

  function closeCommandPalette() {
    if (!elCmdPaletteBackdrop) return;
    elCmdPaletteBackdrop.classList.remove('active');
  }

  function renderCommandPaletteResults() {
    if (!elPaletteResultsList) return;
    const query = (elPaletteSearchInput?.value || '').toLowerCase().trim();

    let items = [];

    // 1. Platform Items
    platforms.forEach(p => {
      if (!query || p.name.toLowerCase().includes(query) || p.code.toLowerCase().includes(query) || p.port.toString().includes(query)) {
        items.push({
          type: 'platform',
          title: `Launch ${p.code} — ${p.name}`,
          subtitle: `Port :${p.port} &middot; ${p.layer} &middot; ${p.badge}`,
          badge: `:${p.port}`,
          action: () => {
            closeCommandPalette();
            launchSSO(p.id, p.name);
          }
        });
      }
    });

    // 2. Persona Switch Items
    const personas = [
      { role: 'guest', name: 'Public Guest' },
      { role: 'customer_employee', name: 'Tenant Staff (Sarah Chen)' },
      { role: 'tenant_admin', name: 'Tenant Admin (Alex Rivera)' },
      { role: 'unierp_team', name: 'UniERP Team (Kannan)' }
    ];
    personas.forEach(ps => {
      if (!query || ps.name.toLowerCase().includes(query) || ps.role.toLowerCase().includes(query)) {
        items.push({
          type: 'persona',
          title: `Switch Persona: ${ps.name}`,
          subtitle: `Role: ${ps.role}`,
          badge: 'ROLE',
          action: () => {
            closeCommandPalette();
            switchPersona(ps.role);
          }
        });
      }
    });

    // 3. Action Items
    const actions = [
      { title: 'Open Global Sign-In Gateway', subtitle: '/login portal', badge: 'AUTH', action: () => window.location.href = '/login' },
      { title: 'Switch Theme to Light', subtitle: 'Light Theme', badge: 'THEME', action: () => { applyTheme('light'); if (elThemeSelect) elThemeSelect.value = 'light'; } },
      { title: 'Switch Theme to Dark', subtitle: 'Dark Theme', badge: 'THEME', action: () => { applyTheme('dark'); if (elThemeSelect) elThemeSelect.value = 'dark'; } },
      { title: 'Switch Theme to Enterprise', subtitle: 'Enterprise Theme', badge: 'THEME', action: () => { applyTheme('enterprise'); if (elThemeSelect) elThemeSelect.value = 'enterprise'; } }
    ];
    actions.forEach(act => {
      if (!query || act.title.toLowerCase().includes(query)) {
        items.push(act);
      }
    });

    if (items.length === 0) {
      elPaletteResultsList.innerHTML = `<div style="padding: 1.5rem; text-align: center; color: var(--color-text-tertiary); font-size: var(--text-xs);">No matching platforms or actions found.</div>`;
      return;
    }

    elPaletteResultsList.innerHTML = items.slice(0, 10).map((item, idx) => `
      <div class="palette-item ${idx === 0 ? 'selected' : ''}" data-idx="${idx}">
        <div class="palette-item-left">
          <div>
            <div class="palette-item-title">${item.title}</div>
            <div class="palette-item-sub">${item.subtitle}</div>
          </div>
        </div>
        <span class="palette-item-badge">${item.badge}</span>
      </div>
    `).join('');

    // Attach click listeners to palette items
    elPaletteResultsList.querySelectorAll('.palette-item').forEach((el, idx) => {
      el.addEventListener('click', () => {
        if (items[idx] && items[idx].action) {
          items[idx].action();
        }
      });
    });
  }

  // ── Run Automated E2E Navigation Tests ─────────────────────────────────────
  async function runE2ETests() {
    if (!elTestTerminal || !elTerminalOutput) return;
    elTestTerminal.style.display = 'block';
    elTerminalOutput.textContent = '🚀 Starting UniERP Automated End-to-End Navigation & SSO Suite...\nProbing all 10 presentation platforms, API Monolith, and IdP...\n\n';

    try {
      const res = await fetch('/api/test/run-e2e', { method: 'POST' });
      const data = await res.json();
      elTerminalOutput.textContent += (data.output || '') + '\n';
      if (data.errorOutput) {
        elTerminalOutput.textContent += `STDERR:\n${data.errorOutput}\n`;
      }
      elTerminalOutput.textContent += `\n[E2E Suite Finished with Exit Code: ${data.exitCode}]`;
      elTerminalOutput.scrollTop = elTerminalOutput.scrollHeight;
    } catch (e) {
      elTerminalOutput.textContent += `\n[Test execution error: ${e.message}]`;
    }
  }

  // ── Toast Notification Helper ──────────────────────────────────────────────
  let toastTimer = null;
  function showToast(title, msg) {
    if (!elSsoToast) return;
    if (elToastTitle) elToastTitle.textContent = title;
    if (elToastMsg) elToastMsg.textContent = msg;
    elSsoToast.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      elSsoToast.classList.remove('show');
    }, 3800);
  }

  // Global namespace for inline triggers
  window.UniERPWizard = {
    launchSSO,
    switchPersona,
    openCommandPalette
  };

  // Run on DOM Ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
