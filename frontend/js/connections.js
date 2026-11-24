/**
 * NetSentry - Live Connections Explorer Controller
 * Real-time socket monitoring, sorting, multi-filtering (including Public/WAN vs Local/LAN), and inspector drawer.
 * Developer: Mohsin
 */

class ConnectionsController {
  constructor() {
    this.refreshTimer = null;
    this.refreshInterval = 1500;
    this.rawConnections = [];
    this.init();
  }

  init() {
    this.setupEvents();
    this.startAutoRefresh();
  }

  setupEvents() {
    // Search input with debounce
    let debounceTimer;
    document.getElementById('conn-search-proc')?.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => this.applyFiltersAndRender(), 150);
    });

    document.getElementById('conn-filter-ip')?.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => this.applyFiltersAndRender(), 150);
    });

    // Instant filter changes
    document.getElementById('conn-filter-scope')?.addEventListener('change', () => {
      this.applyFiltersAndRender();
      this.fetchConnections(true);
    });

    document.getElementById('conn-filter-proto')?.addEventListener('change', () => this.applyFiltersAndRender());
    document.getElementById('conn-filter-state')?.addEventListener('change', () => this.applyFiltersAndRender());
    document.getElementById('conn-filter-risk')?.addEventListener('change', () => this.applyFiltersAndRender());
    document.getElementById('conn-sort-by')?.addEventListener('change', () => this.applyFiltersAndRender());

    // Auto-refresh interval change
    document.getElementById('conn-auto-refresh-interval')?.addEventListener('change', (e) => {
      const val = parseInt(e.target.value, 10);
      this.refreshInterval = val;
      this.startAutoRefresh();
    });
  }

  startAutoRefresh() {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    if (this.refreshInterval > 0) {
      this.refreshTimer = setInterval(() => {
        if (window.app && window.app.currentTab === 'connections') {
          this.fetchConnections(true);
        }
      }, this.refreshInterval);
    }
  }

  isLocalOrPrivate(c) {
    if (!c) return true;
    const ip = c.remote_ip ? String(c.remote_ip).trim() : '';
    const state = c.connection_state ? String(c.connection_state).toUpperCase() : '';

    // Listeners and empty remote endpoints are local
    if (state === 'LISTEN' || !ip || ip === '0.0.0.0' || ip === '::' || ip === '*' || ip === '127.0.0.1' || ip === '::1') {
      return true;
    }

    // Check intelligence precomputed flag
    if (c.intelligence && c.intelligence.is_private === true) {
      return true;
    }

    // IPv6 link-local
    if (ip.toLowerCase().startsWith('fe80:') || ip.toLowerCase().startsWith('fd')) {
      return true;
    }

    // IPv4 RFC 1918 & Loopback
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.')) {
      return true;
    }

    // 172.16.0.0 - 172.31.255.255
    const match = ip.match(/^172\.(\d+)\./);
    if (match) {
      const secondOctet = parseInt(match[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) {
        return true;
      }
    }

    return false;
  }

  async fetchConnections(isBackground = false) {
    const search = (document.getElementById('conn-search-proc')?.value || '').trim();
    const ip = (document.getElementById('conn-filter-ip')?.value || '').trim();
    const proto = document.getElementById('conn-filter-proto')?.value || 'ALL';
    const scope = document.getElementById('conn-filter-scope')?.value || 'ALL';
    const state = document.getElementById('conn-filter-state')?.value || 'ALL';
    const risk = document.getElementById('conn-filter-risk')?.value || 'ALL';
    const sort = document.getElementById('conn-sort-by')?.value || 'duration';

    const params = new URLSearchParams({
      search,
      remote_ip: ip,
      protocol: proto,
      network_scope: scope,
      state,
      risk,
      sort_by: sort,
      limit: '500'
    });

    try {
      const res = await fetch(`/api/connections?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      this.rawConnections = data.connections || [];
      this.applyFiltersAndRender();
    } catch (e) {
      if (!isBackground) {
        console.error('Error fetching connections:', e);
      }
    }
  }

  applyFiltersAndRender() {
    if (!this.rawConnections) return;
    const search = (document.getElementById('conn-search-proc')?.value || '').toLowerCase().trim();
    const ip = (document.getElementById('conn-filter-ip')?.value || '').trim();
    const proto = document.getElementById('conn-filter-proto')?.value || 'ALL';
    const scope = document.getElementById('conn-filter-scope')?.value || 'ALL';
    const state = document.getElementById('conn-filter-state')?.value || 'ALL';
    const risk = document.getElementById('conn-filter-risk')?.value || 'ALL';
    const sort = document.getElementById('conn-sort-by')?.value || 'duration';

    let list = [...this.rawConnections];

    // 1. Network Scope Filter: Public / WAN vs Local / LAN
    if (scope === 'PUBLIC_ONLY') {
      list = list.filter(c => !this.isLocalOrPrivate(c));
    } else if (scope === 'LOCAL_ONLY') {
      list = list.filter(c => this.isLocalOrPrivate(c));
    }

    // 2. Search
    if (search) {
      list = list.filter(c => 
        (c.process_name && c.process_name.toLowerCase().includes(search)) ||
        (c.exe_path && c.exe_path.toLowerCase().includes(search))
      );
    }

    // 3. Protocol
    if (proto !== 'ALL') {
      list = list.filter(c => c.protocol && c.protocol.toUpperCase() === proto.toUpperCase());
    }

    // 4. State
    if (state !== 'ALL') {
      list = list.filter(c => c.connection_state && c.connection_state.toUpperCase() === state.toUpperCase());
    }

    // 5. Remote IP
    if (ip) {
      list = list.filter(c => c.remote_ip && c.remote_ip.includes(ip));
    }

    // 6. Risk Level
    if (risk !== 'ALL') {
      list = list.filter(c => c.risk_level && c.risk_level.toUpperCase() === risk.toUpperCase());
    }

    // 7. Sort
    if (sort === 'duration') {
      list.sort((a, b) => (b.duration_seconds || 0) - (a.duration_seconds || 0));
    } else if (sort === 'risk') {
      list.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
    } else if (sort === 'name') {
      list.sort((a, b) => (a.process_name || '').localeCompare(b.process_name || ''));
    } else if (sort === 'pid') {
      list.sort((a, b) => (b.pid || 0) - (a.pid || 0));
    }

    this.renderTable(list, this.rawConnections.length);
  }

  renderTable(conns, totalRaw) {
    const tbody = document.getElementById('connections-tbody');
    const summary = document.getElementById('conn-table-summary');
    if (!tbody) return;

    const scope = document.getElementById('conn-filter-scope')?.value || 'ALL';
    let scopeLabel = '';
    if (scope === 'PUBLIC_ONLY') scopeLabel = ' (Public WAN Only)';
    else if (scope === 'LOCAL_ONLY') scopeLabel = ' (Local LAN Only)';

    if (summary) {
      if (conns.length !== totalRaw && totalRaw > 0) {
        summary.innerText = `Showing ${conns.length} of ${totalRaw} active network sockets${scopeLabel}`;
      } else {
        summary.innerText = `Showing ${conns.length} active network sockets${scopeLabel}`;
      }
    }

    if (conns.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="11" style="text-align:center; padding:40px; color:var(--text-secondary);">
            No network connections matching your filter parameters${scopeLabel}.
          </td>
        </tr>`;
      return;
    }

    let html = '';
    conns.forEach(c => {
      const riskClass = (c.risk_level || 'safe').toLowerCase();
      const stateClass = this.getStateClass(c.connection_state);
      const protoClass = (c.protocol || 'tcp').toLowerCase();

      // IP formatting with LAN/WAN
      const isLan = this.isLocalOrPrivate(c);
      const remoteBadge = isLan 
        ? `<span class="state-pill" style="font-size:10px; margin-left:4px;">LAN</span>`
        : `<span class="state-pill" style="background:#e8f0fe; color:#1a73e8; font-size:10px; margin-left:4px;">${c.intelligence?.country_code || 'WAN'}</span>`;

      const ispName = isLan ? 'Local Subnet' : (c.intelligence?.isp || c.intelligence?.org || 'Resolving...');

      html += `
        <tr onclick="connectionsController.inspectConnection('${c.connection_key}')">
          <td>
            <div style="font-weight:600; display:flex; align-items:center; gap:6px;">
              <span class="truncate-text" title="${window.app.escapeHtml(c.process_name)}">${window.app.escapeHtml(c.process_name)}</span>
            </div>
          </td>
          <td><span style="font-family:monospace; color:var(--text-secondary);">${c.pid || 'N/A'}</span></td>
          <td><span class="proto-pill proto-${protoClass}">${c.protocol}</span></td>
          <td style="font-family:monospace; font-size:12.5px;">${c.local_ip}:${c.local_port}</td>
          <td style="font-family:monospace; font-size:12.5px;">
            ${c.remote_ip ? `${c.remote_ip}:${c.remote_port}` : '<span style="color:var(--text-tertiary);">&mdash;</span>'}
            ${remoteBadge}
          </td>
          <td>
            <span class="truncate-text" style="max-width:160px; display:inline-block; font-size:12px; font-weight:500;" title="${window.app.escapeHtml(ispName)}">
              ${window.app.escapeHtml(ispName)}
            </span>
          </td>
          <td><span class="state-pill ${stateClass}">${c.connection_state}</span></td>
          <td style="font-weight:500;">${c.duration_formatted || '0s'}</td>
          <td style="font-size:12px; color:var(--text-secondary);">
            &uarr; ${window.app.formatBytes(c.bytes_sent)} | &darr; ${window.app.formatBytes(c.bytes_received)}
          </td>
          <td>
            <span class="status-pill pill-${riskClass}">${c.risk_level}</span>
          </td>
          <td style="text-align:right;">
            <button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); connectionsController.inspectConnection('${c.connection_key}')" title="Inspect Connection">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            </button>
          </td>
        </tr>`;
    });

    tbody.innerHTML = html;
  }

  getStateClass(st) {
    if (!st) return 'state-close';
    const s = st.toUpperCase();
    if (s.includes('ESTABLISHED')) return 'state-established';
    if (s.includes('LISTEN')) return 'state-listen';
    if (s.includes('SYN')) return 'state-syn';
    return 'state-close';
  }

  // ----------------- Detailed Connection Inspector -----------------
  async inspectConnection(key) {
    try {
      const res = await fetch(`/api/connections/details?key=${encodeURIComponent(key)}`);
      if (!res.ok) {
        window.app.showToast('Could not retrieve connection details.', 'danger');
        return;
      }
      const data = await res.json();
      const c = data.connection;
      const p = data.process || {};
      const intel = data.intelligence || c.intelligence || {};

      window.app.currentInspectedConnection = c;

      // Populate Drawer Header
      document.getElementById('drawer-title').innerText = c.process_name;
      document.getElementById('drawer-subtitle').innerText = `PID: ${c.pid || 'N/A'} • ${c.protocol} Socket`;

      const riskClass = (c.risk_level || 'safe').toLowerCase();

      // Build Alerts Section HTML
      let alertsHtml = '<div style="font-size:12.5px; color:var(--status-safe-text); font-weight:500;">✓ No threat heuristics triggered. Connection is assessed as SAFE.</div>';
      if (c.alerts && c.alerts.length > 0) {
        alertsHtml = '';
        c.alerts.forEach(a => {
          const sev = (a.severity || 'low').toLowerCase();
          alertsHtml += `
            <div style="background:#fff; border:1px solid #dadce0; border-left:3px solid var(--status-${sev}-text); border-radius:4px; padding:10px; margin-bottom:8px;">
              <div style="display:flex; align-items:center; gap:6px;">
                <span class="status-pill pill-${sev}">${a.severity}</span>
                <strong style="font-size:12.5px;">${window.app.escapeHtml(a.rule_name)}</strong>
              </div>
              <div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">${window.app.escapeHtml(a.reason)}</div>
              ${a.recommendation ? `<div style="font-size:11.5px; color:var(--text-tertiary); margin-top:4px; font-style:italic;">Guidance: ${window.app.escapeHtml(a.recommendation)}</div>` : ''}
            </div>`;
        });
      }

      // Build Drawer Content HTML
      const drawerBody = document.getElementById('drawer-content');
      drawerBody.innerHTML = `
        <!-- Risk Status Card -->
        <div class="detail-section-card" style="border-left: 4px solid var(--status-${riskClass}-text);">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
              <span class="status-pill pill-${riskClass}" style="font-size:12px; padding:3px 10px;">${c.risk_level} RISK</span>
              <span style="font-size:12px; color:var(--text-secondary); margin-left:8px;">Risk Score: <strong>${c.risk_score || 0}/100</strong></span>
            </div>
            <span class="state-pill ${this.getStateClass(c.connection_state)}">${c.connection_state}</span>
          </div>
          <div style="margin-top:12px;">
            ${alertsHtml}
          </div>
        </div>

        <!-- Endpoints & Socket -->
        <div class="detail-section-card">
          <div class="detail-section-title">Network Endpoints</div>
          <div class="key-value-row">
            <span class="key-label">Protocol</span>
            <span class="key-val"><span class="proto-pill proto-${(c.protocol||'tcp').toLowerCase()}">${c.protocol}</span></span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Local Endpoint</span>
            <span class="key-val" style="font-family:monospace;">${c.local_ip}:${c.local_port}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Remote Endpoint</span>
            <span class="key-val" style="font-family:monospace;" id="drawer-remote-ip-val">${c.remote_ip || 'None'}:${c.remote_port || 0}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">First Observed</span>
            <span class="key-val">${c.first_seen || 'Recently'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Connection Duration</span>
            <span class="key-val">${c.duration_formatted || '0s'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Traffic Volume</span>
            <span class="key-val">&uarr; ${window.app.formatBytes(c.bytes_sent)} &bull; &darr; ${window.app.formatBytes(c.bytes_received)}</span>
          </div>
        </div>

        <!-- IP Geolocation & ASN Intelligence -->
        <div class="detail-section-card">
          <div class="detail-section-title">IP Intelligence & Provider Attribution</div>
          <div class="key-value-row">
            <span class="key-label">Destination Type</span>
            <span class="key-val">${intel.is_private ? 'Private Subnet (RFC 1918 / Loopback)' : 'Public WAN Endpoint'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Country / Region</span>
            <span class="key-val">${intel.country || 'Unknown'} (${intel.region || 'N/A'})</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">City</span>
            <span class="key-val">${intel.city || 'Unknown'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">ISP / Organization</span>
            <span class="key-val">${intel.isp || intel.org || 'Local Network'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Autonomous System (ASN)</span>
            <span class="key-val">${intel.asn || 'N/A'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Approx Coordinates</span>
            <span class="key-val">${intel.latitude ? `${intel.latitude}, ${intel.longitude}` : 'N/A'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Timezone</span>
            <span class="key-val">${intel.timezone || 'N/A'}</span>
          </div>
          <div style="font-size:11px; color:var(--text-tertiary); margin-top:8px; line-height:1.4;">
            * ${intel.disclaimer || 'Approximate geolocation estimates provided by routing registry.'}
          </div>
        </div>

        <!-- Owning Process Information -->
        <div class="detail-section-card">
          <div class="detail-section-title">Owning Windows Process</div>
          <div class="key-value-row">
            <span class="key-label">Process Name</span>
            <span class="key-val">${window.app.escapeHtml(c.process_name)}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">PID / Parent PID</span>
            <span class="key-val">${c.pid || 'N/A'} (Parent: ${p.ppid || 'N/A'})</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Executable File Path</span>
            <span class="key-val" style="font-size:11.5px; font-family:monospace;">${window.app.escapeHtml(c.exe_path || p.exe || 'Access Denied')}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">User Account</span>
            <span class="key-val">${p.username || 'SYSTEM / Local'}</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">CPU / Memory</span>
            <span class="key-val">${p.cpu_percent || 0}% CPU &bull; ${p.memory_mb || 0} MB RAM</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">Digital Signature</span>
            <span class="key-val">${p.signature?.status || 'Unknown'} (${p.signature?.signer || 'Unverified'})</span>
          </div>
          <div class="key-value-row">
            <span class="key-label">OS Protection Status</span>
            <span class="key-val">${p.is_critical ? '<span style="color:#a50e0e; font-weight:700;">Critical System Process</span>' : 'Standard Application'}</span>
          </div>
        </div>
      `;

      window.app.openDrawer();
    } catch (err) {
      console.error('Error opening connection inspector:', err);
    }
  }
}

window.connectionsController = new ConnectionsController();
