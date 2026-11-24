/**
 * NetSentry - Main Application Controller
 * Developer: Mohsin
 */

class NetSentryApp {
  constructor() {
    this.currentTab = 'dashboard';
    this.ws = null;
    this.wsConnected = false;
    this.selectedConnectionKey = null;
    this.selectedPID = null;
    this.selectedProcessName = null;
    this.selectedProcessExe = null;

    this.init();
  }

  init() {
    this.setupNavigation();
    this.setupGlobalControls();
    this.setupWebSocket();
  }

  // ----------------- Tab Navigation -----------------
  setupNavigation() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const tabTarget = tab.getAttribute('data-tab');
        this.switchTab(tabTarget);
      });
    });
  }

  switchTab(tabId) {
    this.currentTab = tabId;
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));

    const tabEl = document.querySelector(`.nav-tab[data-tab="${tabId}"]`);
    const viewEl = document.getElementById(`view-${tabId}`);

    if (tabEl) tabEl.classList.add('active');
    if (viewEl) viewEl.classList.add('active');

    // Trigger on-demand loads per view
    if (tabId === 'connections' && window.connectionsController) {
      window.connectionsController.fetchConnections();
    } else if (tabId === 'processes' && window.processController) {
      window.processController.fetchProcesses();
    } else if (tabId === 'intelligence' && window.intelController) {
      window.intelController.fetchCachedIPs();
    } else if (tabId === 'map' && window.worldMapController) {
      window.worldMapController.fetchMapData();
    } else if (tabId === 'dns' && window.dnsController) {
      window.dnsController.fetchQueries();
    } else if (tabId === 'alerts' && window.app) {
      this.loadAlertsView();
    } else if (tabId === 'history' && window.historyController) {
      window.historyController.searchHistory();
    }
  }

  // ----------------- Global Controls & Modals -----------------
  setupGlobalControls() {
    // Export dropdown toggle
    const btnExport = document.getElementById('btn-export-dropdown');
    const menuExport = document.getElementById('export-menu');
    btnExport.addEventListener('click', (e) => {
      e.stopPropagation();
      menuExport.style.display = menuExport.style.display === 'none' ? 'block' : 'none';
    });
    document.addEventListener('click', () => {
      if (menuExport) menuExport.style.display = 'none';
    });

    // Refresh All Button
    document.getElementById('btn-refresh-all').addEventListener('click', () => {
      this.refreshCurrentView();
      this.showToast('Refreshed monitoring telemetry', 'info');
    });

    // Drawer close events
    const drawerOverlay = document.getElementById('drawer-overlay');
    const btnCloseDrawer = document.getElementById('btn-close-drawer');
    drawerOverlay.addEventListener('click', () => this.closeDrawer());
    btnCloseDrawer.addEventListener('click', () => this.closeDrawer());

    // Drawer actions
    document.getElementById('drawer-btn-copy-ip').addEventListener('click', () => {
      const ip = document.getElementById('drawer-remote-ip-val')?.innerText;
      if (ip && ip !== 'None' && ip !== '--') {
        this.copyToClipboard(ip, `Remote IP ${ip} copied to clipboard!`);
      }
    });

    document.getElementById('drawer-btn-copy-json').addEventListener('click', () => {
      if (this.currentInspectedConnection) {
        this.copyToClipboard(JSON.stringify(this.currentInspectedConnection, null, 2), 'Connection details JSON copied!');
      }
    });

    document.getElementById('drawer-btn-terminate').addEventListener('click', () => {
      if (this.currentInspectedConnection) {
        const c = this.currentInspectedConnection;
        this.confirmTerminate(c.pid, c.process_name, c.exe_path);
      }
    });

    // Confirm terminate modal button
    document.getElementById('btn-confirm-terminate').addEventListener('click', () => {
      this.executeTerminateProcess();
    });

    // Retention cleanup modal events
    document.getElementById('btn-open-cleanup-modal').addEventListener('click', () => {
      this.openModal('modal-cleanup');
    });

    document.getElementById('btn-execute-cleanup').addEventListener('click', () => {
      const days = document.getElementById('cleanup-days-select').value;
      if (window.historyController) {
        window.historyController.runCleanup(days);
      }
    });
  }

  refreshCurrentView() {
    if (this.currentTab === 'dashboard' && window.dashboardController) {
      window.dashboardController.fetchOverview();
    } else if (this.currentTab === 'connections' && window.connectionsController) {
      window.connectionsController.fetchConnections();
    } else if (this.currentTab === 'processes' && window.processController) {
      window.processController.fetchProcesses();
    } else if (this.currentTab === 'intelligence' && window.intelController) {
      window.intelController.fetchCachedIPs();
    } else if (this.currentTab === 'map' && window.worldMapController) {
      window.worldMapController.fetchMapData();
    } else if (this.currentTab === 'dns' && window.dnsController) {
      window.dnsController.fetchQueries();
    } else if (this.currentTab === 'alerts') {
      this.loadAlertsView();
    } else if (this.currentTab === 'history' && window.historyController) {
      window.historyController.searchHistory();
    }
  }

  // ----------------- WebSocket Live Stream -----------------
  setupWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/live`;

    const statusEl = document.getElementById('telemetry-status');
    const textEl = document.getElementById('telemetry-text');

    const connect = () => {
      try {
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          this.wsConnected = true;
          statusEl.style.background = 'var(--status-safe-bg)';
          statusEl.style.color = 'var(--status-safe-text)';
          textEl.innerText = 'LIVE STREAMING';
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'telemetry_update') {
              this.handleTelemetryUpdate(data);
            }
          } catch (e) {
            console.error('WS parse error:', e);
          }
        };

        this.ws.onclose = () => {
          this.wsConnected = false;
          statusEl.style.background = 'var(--status-med-bg)';
          statusEl.style.color = 'var(--status-med-text)';
          textEl.innerText = 'RECONNECTING...';
          setTimeout(connect, 3000);
        };

        this.ws.onerror = () => {
          this.wsConnected = false;
        };
      } catch (err) {
        setTimeout(connect, 3000);
      }
    };

    connect();
  }

  handleTelemetryUpdate(data) {
    // Forward update to dashboard controller
    if (window.dashboardController) {
      window.dashboardController.updateTelemetry(data);
    }
    // Update navigation badge counts
    const badgeConn = document.getElementById('nav-badge-connections');
    if (badgeConn) badgeConn.innerText = data.total_connections || 0;

    const badgeAlerts = document.getElementById('nav-badge-alerts');
    if (badgeAlerts && data.stats) {
      badgeAlerts.innerText = data.stats.suspicious_connections || 0;
    }
  }

  // ----------------- Drawer & Modals -----------------
  openDrawer() {
    document.getElementById('drawer-overlay').classList.add('active');
    document.getElementById('connection-drawer').classList.add('open');
  }

  closeDrawer() {
    document.getElementById('drawer-overlay').classList.remove('active');
    document.getElementById('connection-drawer').classList.remove('open');
  }

  openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.add('active');
  }

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('active');
  }

  // ----------------- Process Termination -----------------
  confirmTerminate(pid, name, exe) {
    this.selectedPID = pid;
    this.selectedProcessName = name;
    this.selectedProcessExe = exe;

    document.getElementById('term-proc-name').innerText = name || 'Unknown';
    document.getElementById('term-proc-pid').innerText = pid || '--';
    document.getElementById('term-proc-exe').innerText = exe || 'N/A';

    this.openModal('modal-terminate');
  }

  async executeTerminateProcess() {
    const pid = this.selectedPID;
    if (!pid) return;

    try {
      const res = await fetch(`/api/processes/${pid}/terminate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true })
      });

      const data = await res.json();
      this.closeModal('modal-terminate');

      if (res.ok && data.success) {
        this.showToast(data.message, 'success');
        this.closeDrawer();
        this.refreshCurrentView();
      } else {
        this.showToast(data.detail || data.message || 'Termination failed.', 'danger');
      }
    } catch (err) {
      this.closeModal('modal-terminate');
      this.showToast('Network error terminating process: ' + err.message, 'danger');
    }
  }

  // ----------------- Alert View Loader -----------------
  async loadAlertsView(severity = 'ALL') {
    const container = document.getElementById('alerts-full-feed');
    try {
      const url = severity === 'ALL' ? '/api/history/alerts?limit=100' : `/api/history/alerts?severity=${severity}&limit=100`;
      const res = await fetch(url);
      const data = await res.json();
      const alerts = data.alerts || [];

      if (alerts.length === 0) {
        container.innerHTML = `
          <div style="background:#fff; border:1px solid #dadce0; border-radius:8px; padding:40px; text-align:center; color:var(--text-secondary);">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#34a853" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>
            <div style="font-size:15px; font-weight:600; color:var(--text-primary); margin-top:10px;">Zero Threats Detected</div>
            <div style="font-size:13px; margin-top:4px;">No suspicious activity matches your current severity filter.</div>
          </div>`;
        return;
      }

      let html = '';
      alerts.forEach(a => {
        const sevClass = a.severity.toLowerCase();
        html += `
          <div class="alert-card-item sev-${sevClass}">
            <div style="flex:1;">
              <div class="alert-info-title">
                <span class="status-pill pill-${sevClass}">${a.severity}</span>
                <span>${this.escapeHtml(a.rule_name)}</span>
              </div>
              <div class="alert-info-desc"><strong>Reason:</strong> ${this.escapeHtml(a.reason)}</div>
              <div class="key-value-row" style="margin-top:8px; font-size:12px; background:#f8f9fa; padding:6px 10px; border-radius:4px;">
                <span><strong>Process:</strong> ${this.escapeHtml(a.process_name)} (PID: ${a.pid || 'N/A'})</span>
                <span><strong>Endpoint:</strong> ${a.remote_ip || 'None'}:${a.remote_port || 0} (${a.protocol || 'TCP'})</span>
                <span><strong>Logged:</strong> ${a.timestamp}</span>
              </div>
            </div>
            <div>
              <button class="btn btn-outline btn-sm" onclick="app.inspectAlertContext('${a.remote_ip}')">Inspect IP</button>
            </div>
          </div>`;
      });
      container.innerHTML = html;
    } catch (e) {
      container.innerHTML = `<div style="color:var(--status-high-text); text-align:center; padding:30px;">Error loading threat alerts: ${e.message}</div>`;
    }
  }

  inspectAlertContext(ip) {
    this.switchTab('intelligence');
    if (window.intelController) {
      document.getElementById('intel-input-ip').value = ip;
      window.intelController.lookupIP(ip);
    }
  }

  // ----------------- Utilities -----------------
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    
    let iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#1a73e8" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    if (type === 'success') {
      iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#34a853" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="9 11 12 14 22 4"></polyline></svg>';
    } else if (type === 'danger') {
      iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#d93025" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    }

    toast.innerHTML = `${iconSvg} <span>${this.escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.25s ease';
      setTimeout(() => toast.remove(), 250);
    }, 3500);
  }

  copyToClipboard(text, successMsg = 'Copied to clipboard!') {
    navigator.clipboard.writeText(text).then(() => {
      this.showToast(successMsg, 'success');
    }).catch(err => {
      this.showToast('Could not copy: ' + err, 'danger');
    });
  }

  formatBytes(b) {
    if (!b || b === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let idx = 0;
    while (b >= 1024 && idx < units.length - 1) {
      b /= 1024;
      idx++;
    }
    return `${b.toFixed(1)} ${units[idx]}`;
  }

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}

// Global App Instance
window.app = new NetSentryApp();

// Alert severity filter clicks
document.querySelectorAll('.alert-filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.alert-filter-btn').forEach(b => {
      b.classList.remove('btn-primary');
      b.classList.add('btn-outline');
    });
    btn.classList.add('btn-primary');
    btn.classList.remove('btn-outline');
    const sev = btn.getAttribute('data-severity');
    window.app.loadAlertsView(sev);
  });
});

