/**
 * NetSentry - Live DNS Query Sniffer Controller
 * Real-time packet-level DNS capture, search, and tunneling anomaly detection.
 * Developer: Mohsin
 */

class DNSController {
  constructor() {
    this.refreshTimer = null;
    this.isPaused = false;
    this.queries = [];
    this.init();
  }

  init() {
    this.setupEvents();
    this.startStreaming();
  }

  setupEvents() {
    let debounce;
    document.getElementById('dns-search')?.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => this.fetchQueries(), 300);
    });

    document.getElementById('dns-filter-suspicious')?.addEventListener('change', () => {
      this.fetchQueries();
    });

    // Pause / Resume toggle
    const btnPause = document.getElementById('btn-dns-pause-stream');
    btnPause?.addEventListener('click', () => {
      this.isPaused = !this.isPaused;
      if (this.isPaused) {
        btnPause.innerText = 'Resume Stream';
        btnPause.classList.add('btn-primary');
        btnPause.classList.remove('btn-outline');
      } else {
        btnPause.innerText = 'Pause Stream';
        btnPause.classList.remove('btn-primary');
        btnPause.classList.add('btn-outline');
        this.fetchQueries();
      }
    });

    // Clear queries
    document.getElementById('btn-dns-clear')?.addEventListener('click', async () => {
      try {
        await fetch('/api/dns/clear', { method: 'POST' });
        this.queries = [];
        this.renderTable([]);
        window.app.showToast('DNS query stream cleared', 'info');
      } catch (err) {
        console.error('Error clearing DNS logs:', err);
      }
    });
  }

  startStreaming() {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    this.refreshTimer = setInterval(() => {
      if (window.app.currentTab === 'dns' && !this.isPaused) {
        this.fetchQueries(true);
      }
    }, 1500);
  }

  async fetchQueries(isBackground = false) {
    const search = document.getElementById('dns-search')?.value || '';
    const suspOnly = document.getElementById('dns-filter-suspicious')?.checked || false;

    const params = new URLSearchParams({
      limit: '150'
    });
    if (search) params.append('search', search);
    if (suspOnly) params.append('suspicious_only', 'true');

    try {
      const res = await fetch(`/api/dns/queries?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      this.queries = data.queries || [];
      this.renderTable(this.queries);

      // Update badge
      const badge = document.getElementById('nav-badge-dns');
      if (badge) {
        badge.innerText = this.queries.length;
      }
    } catch (e) {
      if (!isBackground) {
        console.error('Error fetching DNS queries:', e);
      }
    }
  }

  renderTable(queries) {
    const tbody = document.getElementById('dns-tbody');
    const summary = document.getElementById('dns-table-summary');
    if (!tbody) return;

    if (summary) {
      summary.innerText = `Captured ${queries.length} DNS resolution events`;
    }

    if (queries.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:36px; color:var(--text-secondary);">
            No DNS queries match your filter criteria or no traffic detected yet on port 53.
          </td>
        </tr>`;
      return;
    }

    let html = '';
    queries.forEach(q => {
      let threatBadge = '';
      if (q.is_suspicious) {
        threatBadge = `
          <span class="status-pill pill-high" title="${window.app.escapeHtml(q.suspicious_reason)}">
            THREAT: ${window.app.escapeHtml(q.suspicious_reason)}
          </span>`;
      } else {
        threatBadge = `<span class="status-pill pill-safe">NORMAL</span>`;
      }

      // Format answers
      let answersHtml = '<span style="color:var(--text-tertiary);">&mdash;</span>';
      if (q.answers && q.answers.length > 0) {
        answersHtml = `<span style="font-family:monospace; font-size:12px;">${q.answers.join(', ')}</span>`;
      }

      html += `
        <tr>
          <td>
            <strong style="font-size:13px; color:var(--text-primary); font-family:monospace;">
              ${window.app.escapeHtml(q.domain)}
            </strong>
          </td>
          <td><span class="proto-pill proto-tcp" style="font-size:11px;">${q.qtype || 'A'}</span></td>
          <td style="font-family:monospace; font-size:12px; color:var(--text-secondary);">${q.client_ip}</td>
          <td style="font-family:monospace; font-size:12px;">${q.dns_server}</td>
          <td>${answersHtml}</td>
          <td style="font-size:12px; color:var(--text-tertiary);">${q.timestamp}</td>
          <td>${threatBadge}</td>
        </tr>`;
    });

    tbody.innerHTML = html;
  }
}

window.dnsController = new DNSController();

