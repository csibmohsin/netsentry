/**
 * NetSentry - Historical Analytics Controller
 * Persistent SQLite history queries, time-based filters, timeline inspection, and maintenance.
 * Developer: Mohsin
 */

class HistoryController {
  constructor() {
    this.limit = 50;
    this.offset = 0;
    this.total = 0;
    this.init();
  }

  init() {
    this.setupEvents();
  }

  setupEvents() {
    document.getElementById('btn-search-history')?.addEventListener('click', () => {
      this.offset = 0;
      this.searchHistory();
    });

    document.getElementById('btn-reset-history')?.addEventListener('click', () => {
      document.getElementById('hist-filter-proc').value = '';
      document.getElementById('hist-filter-ip').value = '';
      document.getElementById('hist-filter-risk').value = 'ALL';
      this.offset = 0;
      this.searchHistory();
    });

    document.getElementById('btn-hist-prev')?.addEventListener('click', () => {
      if (this.offset >= this.limit) {
        this.offset -= this.limit;
        this.searchHistory();
      }
    });

    document.getElementById('btn-hist-next')?.addEventListener('click', () => {
      if (this.offset + this.limit < this.total) {
        this.offset += this.limit;
        this.searchHistory();
      }
    });
  }

  async searchHistory() {
    const proc = document.getElementById('hist-filter-proc')?.value || '';
    const ip = document.getElementById('hist-filter-ip')?.value || '';
    const risk = document.getElementById('hist-filter-risk')?.value || 'ALL';

    const params = new URLSearchParams({
      limit: String(this.limit),
      offset: String(this.offset)
    });

    if (proc) params.append('process_name', proc);
    if (ip) params.append('remote_ip', ip);
    if (risk && risk !== 'ALL') params.append('risk_level', risk);

    const tbody = document.getElementById('history-tbody');
    const summary = document.getElementById('history-summary');
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="11" style="text-align:center; padding:30px; color:var(--text-secondary);">Querying SQLite history logs...</td></tr>`;

    try {
      const res = await fetch(`/api/history/connections?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      
      this.total = data.total || 0;
      const records = data.records || [];

      if (summary) {
        const start = this.total > 0 ? this.offset + 1 : 0;
        const end = Math.min(this.offset + this.limit, this.total);
        summary.innerText = `Showing ${start} - ${end} of ${this.total} historical connection records`;
      }

      // Update button states
      const btnPrev = document.getElementById('btn-hist-prev');
      const btnNext = document.getElementById('btn-hist-next');
      if (btnPrev) btnPrev.disabled = this.offset === 0;
      if (btnNext) btnNext.disabled = this.offset + this.limit >= this.total;

      if (records.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="11" style="text-align:center; padding:36px; color:var(--text-secondary);">
              No historical connection records found for the selected query.
            </td>
          </tr>`;
        return;
      }

      let html = '';
      records.forEach(r => {
        const riskClass = (r.risk_level || 'safe').toLowerCase();
        const durationFmt = this.formatDuration(r.duration_seconds || 0.0);
        html += `
          <tr onclick="historyController.inspectHistoryRecord('${r.connection_key}')">
            <td><strong>${window.app.escapeHtml(r.process_name)}</strong></td>
            <td><span style="font-family:monospace; color:var(--text-secondary);">${r.pid || 'N/A'}</span></td>
            <td><span class="proto-pill proto-${(r.protocol||'tcp').toLowerCase()}">${r.protocol}</span></td>
            <td style="font-family:monospace; font-size:12px;">${r.local_ip}:${r.local_port}</td>
            <td style="font-family:monospace; font-size:12px;">${r.remote_ip || 'None'}:${r.remote_port || 0}</td>
            <td><span class="state-pill">${r.connection_state}</span></td>
            <td style="font-size:12px; color:var(--text-secondary);">${r.first_seen ? r.first_seen.replace('T', ' ') : 'N/A'}</td>
            <td style="font-size:12px; color:var(--text-secondary);">${r.last_seen ? r.last_seen.replace('T', ' ') : 'N/A'}</td>
            <td style="font-weight:500;">${durationFmt}</td>
            <td><span class="status-pill pill-${riskClass}">${r.risk_level}</span></td>
            <td style="text-align:right;">
              <button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); historyController.inspectHistoryRecord('${r.connection_key}')">Details</button>
            </td>
          </tr>`;
      });
      tbody.innerHTML = html;
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="11" style="color:var(--status-high-text); text-align:center; padding:20px;">Error searching history: ${e.message}</td></tr>`;
    }
  }

  inspectHistoryRecord(key) {
    if (window.connectionsController) {
      window.connectionsController.inspectConnection(key);
    }
  }

  async runCleanup(days) {
    try {
      const res = await fetch(`/api/history/cleanup?days=${days}`, { method: 'POST' });
      const data = await res.json();
      window.app.closeModal('modal-cleanup');

      if (res.ok) {
        const resObj = data.result || {};
        window.app.showToast(`Database maintenance complete. Cleaned ${resObj.deleted_connections || 0} older records.`, 'success');
        this.searchHistory();
      } else {
        window.app.showToast('Cleanup failed: ' + (data.detail || 'Server error'), 'danger');
      }
    } catch (err) {
      window.app.closeModal('modal-cleanup');
      window.app.showToast('Network error during cleanup: ' + err.message, 'danger');
    }
  }

  formatDuration(seconds) {
    const sec = Math.round(seconds);
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  }
}

window.historyController = new HistoryController();

