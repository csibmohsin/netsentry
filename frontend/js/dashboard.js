/**
 * NetSentry - Dashboard Controller
 * Handles KPI cards, real-time Chart.js traffic graph, and quick alert feeds.
 * Developer: Mohsin
 */

class DashboardController {
  constructor() {
    this.chart = null;
    this.maxChartPoints = 30;
    this.chartLabels = [];
    this.chartDataIn = [];
    this.chartDataOut = [];

    this.init();
  }

  init() {
    this.initChart();
    this.fetchOverview();
  }

  initChart() {
    const ctx = document.getElementById('trafficChart')?.getContext('2d');
    if (!ctx || typeof Chart === 'undefined') return;

    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: this.chartLabels,
        datasets: [
          {
            label: 'Inbound (KB/s)',
            data: this.chartDataIn,
            borderColor: '#1a73e8',
            backgroundColor: 'rgba(26, 115, 232, 0.08)',
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointRadius: 2,
            pointHoverRadius: 5
          },
          {
            label: 'Outbound (KB/s)',
            data: this.chartDataOut,
            borderColor: '#34a853',
            backgroundColor: 'rgba(52, 168, 83, 0.08)',
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointRadius: 2,
            pointHoverRadius: 5
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            backgroundColor: 'rgba(32, 33, 36, 0.9)',
            padding: 10,
            titleFont: { size: 12 },
            bodyFont: { size: 12 },
            callbacks: {
              label: (context) => `${context.dataset.label}: ${context.raw} KB/s`
            }
          }
        },
        scales: {
          x: {
            grid: { color: '#f1f3f4' },
            ticks: { font: { size: 11 }, color: '#80868b' }
          },
          y: {
            beginAtZero: true,
            grid: { color: '#f1f3f4' },
            ticks: {
              font: { size: 11 },
              color: '#80868b',
              callback: (val) => `${val} KB/s`
            }
          }
        }
      }
    });
  }

  async fetchOverview() {
    try {
      const res = await fetch('/api/overview');
      if (!res.ok) return;
      const data = await res.json();

      this.updateKPIs(data.stats);
      this.updateTopProcesses(data.top_processes || []);
      this.updateAlertsFeed(data.recent_alerts || []);

      if (data.traffic_history && data.traffic_history.length > 0) {
        this.populateInitialChart(data.traffic_history);
      }
    } catch (e) {
      console.error('Error fetching dashboard overview:', e);
    }
  }

  updateTelemetry(telemetry) {
    if (telemetry.stats) {
      this.updateKPIs(telemetry.stats);
    }

    if (telemetry.traffic) {
      this.appendTrafficPoint(telemetry.traffic);
    }

    if (telemetry.recent_alerts) {
      this.updateAlertsFeed(telemetry.recent_alerts);
    }
  }

  updateKPIs(stats) {
    if (!stats) return;
    document.getElementById('kpi-total-conns').innerText = stats.total_connections ?? 0;
    document.getElementById('kpi-established').innerText = stats.established_tcp ?? 0;
    document.getElementById('kpi-listening').innerText = stats.listening_ports ?? 0;
    document.getElementById('kpi-remote-ips').innerText = stats.unique_remote_ips ?? 0;
    document.getElementById('kpi-active-procs').innerText = stats.active_processes ?? 0;
    
    const suspEl = document.getElementById('kpi-suspicious');
    const count = stats.suspicious_connections ?? 0;
    suspEl.innerText = count;

    const suspCard = document.getElementById('kpi-suspicious-card');
    if (count > 0) {
      suspCard.style.borderLeftColor = 'var(--status-high-text)';
      suspEl.style.color = 'var(--status-high-text)';
    } else {
      suspCard.style.borderLeftColor = 'var(--border-subtle)';
      suspEl.style.color = 'var(--text-primary)';
    }
  }

  populateInitialChart(history) {
    if (!this.chart) return;
    this.chartLabels.length = 0;
    this.chartDataIn.length = 0;
    this.chartDataOut.length = 0;

    const recent = history.slice(-this.maxChartPoints);
    recent.forEach(pt => {
      this.chartLabels.push(pt.timestamp || '');
      this.chartDataIn.push(pt.recv_rate_kb || 0.0);
      this.chartDataOut.push(pt.sent_rate_kb || 0.0);
    });

    if (recent.length > 0) {
      const last = recent[recent.length - 1];
      document.getElementById('rate-inbound').innerText = `${last.recv_rate_kb || 0} KB/s`;
      document.getElementById('rate-outbound').innerText = `${last.sent_rate_kb || 0} KB/s`;
    }

    this.chart.update('none');
  }

  appendTrafficPoint(point) {
    if (!this.chart || !point) return;
    const timeLabel = point.timestamp || new Date().toLocaleTimeString();
    const recvKb = point.recv_rate_kb || 0.0;
    const sentKb = point.sent_rate_kb || 0.0;

    document.getElementById('rate-inbound').innerText = `${recvKb} KB/s`;
    document.getElementById('rate-outbound').innerText = `${sentKb} KB/s`;

    if (this.chartLabels.length >= this.maxChartPoints) {
      this.chartLabels.shift();
      this.chartDataIn.shift();
      this.chartDataOut.shift();
    }

    this.chartLabels.push(timeLabel);
    this.chartDataIn.push(recvKb);
    this.chartDataOut.push(sentKb);

    this.chart.update('none');
  }

  updateAlertsFeed(alerts) {
    const feed = document.getElementById('dashboard-alerts-feed');
    if (!feed) return;

    if (!alerts || alerts.length === 0) {
      feed.innerHTML = `
        <div style="color:var(--status-safe-text); background:var(--status-safe-bg); border-radius:6px; padding:18px; text-align:center; font-size:13px; font-weight:500;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle; margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          No active threats detected. All monitored connections comply with baseline heuristics.
        </div>`;
      return;
    }

    let html = '';
    alerts.slice(0, 5).forEach(a => {
      const sevClass = (a.severity || 'low').toLowerCase();
      html += `
        <div class="alert-card-item sev-${sevClass}" style="margin-bottom:8px; padding:10px 14px;">
          <div style="flex:1;">
            <div style="display:flex; align-items:center; gap:8px;">
              <span class="status-pill pill-${sevClass}">${a.severity}</span>
              <strong style="font-size:13px;">${window.app.escapeHtml(a.rule_name)}</strong>
              <span style="font-size:11px; color:var(--text-tertiary); margin-left:auto;">${a.timestamp}</span>
            </div>
            <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
              ${window.app.escapeHtml(a.reason)}
            </div>
            <div style="font-size:11.5px; color:var(--text-primary); margin-top:4px;">
              ${window.app.escapeHtml(a.process_name)} (PID: ${a.pid || 'N/A'}) &rarr; ${a.remote_ip || 'None'}:${a.remote_port || 0}
            </div>
          </div>
        </div>`;
    });
    feed.innerHTML = html;
  }

  updateTopProcesses(procs) {
    const container = document.getElementById('dashboard-top-processes');
    if (!container) return;

    if (!procs || procs.length === 0) {
      container.innerHTML = `<div style="color:var(--text-tertiary); text-align:center; padding:24px;">No active network processes found.</div>`;
      return;
    }

    const maxConns = Math.max(...procs.map(p => p.connections), 1);
    let html = '<div style="display:flex; flex-direction:column; gap:10px;">';

    procs.slice(0, 7).forEach(p => {
      const pct = Math.min(100, Math.round((p.connections / maxConns) * 100));
      html += `
        <div style="display:flex; align-items:center; justify-content:space-between; font-size:13px;">
          <div style="width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:500;">
            ${window.app.escapeHtml(p.name)}
          </div>
          <div style="flex:1; margin: 0 14px;">
            <div style="height:6px; background:#f1f3f4; border-radius:3px; overflow:hidden;">
              <div style="width:${pct}%; height:100%; background:var(--accent-blue); border-radius:3px;"></div>
            </div>
          </div>
          <div style="font-weight:600; width:60px; text-align:right; font-size:12px;">
            ${p.connections} <span style="font-weight:400; color:var(--text-secondary);">conns</span>
          </div>
        </div>`;
    });
    html += '</div>';
    container.innerHTML = html;
  }
}

window.dashboardController = new DashboardController();

