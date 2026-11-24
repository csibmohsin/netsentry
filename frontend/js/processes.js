/**
 * NetSentry - Process Explorer Controller
 * Real-time Windows process inspection, digital signatures, and safe termination workflows.
 * Developer: Mohsin
 */

class ProcessController {
  constructor() {
    this.processes = [];
    this.init();
  }

  init() {
    this.setupEvents();
  }

  setupEvents() {
    let debounce;
    document.getElementById('proc-search')?.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => this.fetchProcesses(), 300);
    });

    document.getElementById('btn-refresh-processes')?.addEventListener('click', () => {
      this.fetchProcesses();
      window.app.showToast('Refreshed Windows process list', 'info');
    });
  }

  async fetchProcesses() {
    const search = document.getElementById('proc-search')?.value || '';
    const params = new URLSearchParams();
    if (search) params.append('search', search);

    try {
      const res = await fetch(`/api/processes?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      this.processes = data.processes || [];
      this.renderTable(this.processes);
    } catch (e) {
      console.error('Error fetching processes:', e);
    }
  }

  renderTable(procs) {
    const tbody = document.getElementById('processes-tbody');
    if (!tbody) return;

    if (procs.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align:center; padding:36px; color:var(--text-secondary);">
            No running processes match your search filter.
          </td>
        </tr>`;
      return;
    }

    const maxCpu = Math.max(...procs.map(p => p.cpu_percent || 0), 10);
    const maxMem = Math.max(...procs.map(p => p.memory_mb || 0), 200);

    let html = '';
    procs.forEach(p => {
      const cpuPct = Math.min(100, Math.round(((p.cpu_percent || 0) / maxCpu) * 100));
      const memPct = Math.min(100, Math.round(((p.memory_mb || 0) / maxMem) * 100));
      const isCritical = p.is_critical || false;

      // Security / OS status badge
      let secBadge = '';
      if (isCritical) {
        secBadge = `<span class="status-pill" style="background:#fce8e6; color:#a50e0e; font-weight:700;">Critical OS Process</span>`;
      } else {
        secBadge = `<span class="status-pill pill-safe">User / Service</span>`;
      }

      // Sockets badge
      const socketsBadge = p.active_sockets > 0 
        ? `<span class="status-pill pill-low" style="font-size:11.5px; cursor:pointer;" onclick="processController.filterConnectionsForProcess('${p.name}')">${p.active_sockets} active socket(s)</span>`
        : `<span style="color:var(--text-tertiary); font-size:12px;">0</span>`;

      // Terminate button state
      let terminateBtn = '';
      if (isCritical) {
        terminateBtn = `<button class="btn btn-outline btn-sm" disabled style="opacity:0.4; cursor:not-allowed;" title="Protected System Process: Cannot be terminated">Protected</button>`;
      } else {
        terminateBtn = `
          <button class="btn btn-danger btn-sm" onclick="app.confirmTerminate(${p.pid}, '${window.app.escapeHtml(p.name)}', '${window.app.escapeHtml(p.exe || '')}')">
            Terminate
          </button>`;
      }

      html += `
        <tr>
          <td>
            <div style="font-weight:600; display:flex; align-items:center; gap:6px;">
              <span class="truncate-text" title="${window.app.escapeHtml(p.name)}">${window.app.escapeHtml(p.name)}</span>
            </div>
          </td>
          <td><span style="font-family:monospace; font-weight:600; color:var(--text-secondary);">${p.pid}</span></td>
          <td><span style="font-family:monospace; color:var(--text-tertiary);">${p.ppid || 'N/A'}</span></td>
          <td>
            <span class="truncate-text" style="max-width:240px; display:inline-block; font-size:12px; font-family:monospace;" title="${window.app.escapeHtml(p.exe || 'Access Denied')}">
              ${window.app.escapeHtml(p.exe || 'Access Denied')}
            </span>
          </td>
          <td>
            <div class="mini-bar-wrap">
              <span style="width:36px; font-size:12px;">${p.cpu_percent || 0}%</span>
              <div class="mini-bar-track"><div class="mini-bar-fill" style="width:${cpuPct}%;"></div></div>
            </div>
          </td>
          <td>
            <div class="mini-bar-wrap">
              <span style="width:55px; font-size:12px;">${p.memory_mb || 0} MB</span>
              <div class="mini-bar-track"><div class="mini-bar-fill" style="width:${memPct}%; background:#34a853;"></div></div>
            </div>
          </td>
          <td>${socketsBadge}</td>
          <td>${secBadge}</td>
          <td style="text-align:right;">
            <div style="display:flex; justify-content:flex-end; gap:6px;">
              ${terminateBtn}
            </div>
          </td>
        </tr>`;
    });

    tbody.innerHTML = html;
  }

  filterConnectionsForProcess(pname) {
    window.app.switchTab('connections');
    const searchInput = document.getElementById('conn-search-proc');
    if (searchInput) {
      searchInput.value = pname;
      if (window.connectionsController) {
        window.connectionsController.fetchConnections();
      }
    }
  }
}

window.processController = new ProcessController();

