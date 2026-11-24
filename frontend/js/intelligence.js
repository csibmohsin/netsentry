/**
 * NetSentry - IP Intelligence Controller
 * Integrates ipwho.is with geolocation attribution, ASN lookup, and caching.
 * Developer: Mohsin
 */

class IntelligenceController {
  constructor() {
    this.init();
  }

  init() {
    this.setupEvents();
  }

  setupEvents() {
    const btnLookup = document.getElementById('btn-intel-lookup');
    const inputIP = document.getElementById('intel-input-ip');

    btnLookup?.addEventListener('click', () => {
      const ip = inputIP?.value.trim();
      if (ip) {
        this.lookupIP(ip);
      }
    });

    inputIP?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        const ip = inputIP.value.trim();
        if (ip) {
          this.lookupIP(ip);
        }
      }
    });
  }

  async lookupIP(ip) {
    const resultBox = document.getElementById('intel-search-result');
    const gridEl = document.getElementById('intel-grid-details');
    const disclaimerText = document.getElementById('intel-disclaimer-text');
    if (!resultBox || !gridEl) return;

    resultBox.style.display = 'block';
    gridEl.innerHTML = `<div style="padding:24px; color:var(--text-secondary); text-align:center;">Querying intelligence provider for ${window.app.escapeHtml(ip)}...</div>`;

    try {
      const res = await fetch(`/api/intelligence/${encodeURIComponent(ip)}`);
      if (!res.ok) {
        gridEl.innerHTML = `<div style="color:var(--status-high-text); padding:20px;">Lookup failed: ${res.statusText}</div>`;
        return;
      }
      const data = await res.json();
      
      if (disclaimerText && data.disclaimer) {
        disclaimerText.innerText = data.disclaimer;
      }

      const mapLink = data.latitude && data.longitude
        ? `<a href="https://www.openstreetmap.org/?mlat=${data.latitude}&mlon=${data.longitude}&zoom=11" target="_blank" style="color:var(--accent-blue); text-decoration:none; margin-left:6px; font-size:12px;">View Map &nearr;</a>`
        : '';

      gridEl.innerHTML = `
        <div class="intel-metric-box">
          <div class="label">IP Address & Network Class</div>
          <div class="val">${data.ip || ip} (${data.ip_version || 'IPv4'})</div>
        </div>

        <div class="intel-metric-box">
          <div class="label">Country / Territory</div>
          <div class="val">${data.country || 'Unknown'} ${data.country_code ? `(${data.country_code})` : ''}</div>
        </div>

        <div class="intel-metric-box">
          <div class="label">Region & City</div>
          <div class="val">${data.city || 'Unknown'}, ${data.region || 'Unknown'}</div>
        </div>

        <div class="intel-metric-box">
          <div class="label">Internet Service Provider (ISP)</div>
          <div class="val">${data.isp || 'N/A'}</div>
        </div>

        <div class="intel-metric-box">
          <div class="label">Autonomous System (ASN)</div>
          <div class="val">${data.asn || 'N/A'} ${data.org ? `(${data.org})` : ''}</div>
        </div>

        <div class="intel-metric-box">
          <div class="label">ISP Domain</div>
          <div class="val">${data.domain || 'N/A'}</div>
        </div>

        <div class="intel-metric-box">
          <div class="label">Approx Coordinates (Routing Center)</div>
          <div class="val">${data.latitude ? `${data.latitude}, ${data.longitude}` : 'N/A'} ${mapLink}</div>
        </div>

        <div class="intel-metric-box">
          <div class="label">Timezone</div>
          <div class="val">${data.timezone || 'UTC'}</div>
        </div>
      `;

      // Refresh cached list
      this.fetchCachedIPs();

    } catch (err) {
      gridEl.innerHTML = `<div style="color:var(--status-high-text); padding:20px;">Error communicating with IP intelligence endpoint: ${err.message}</div>`;
    }
  }

  async fetchCachedIPs() {
    const tbody = document.getElementById('cached-ips-tbody');
    const countEl = document.getElementById('cached-ips-count');
    if (!tbody) return;

    try {
      const res = await fetch('/api/intelligence/cache/all?limit=100');
      if (!res.ok) return;
      const data = await res.json();
      const list = data.cached_ips || [];

      if (countEl) countEl.innerText = `${list.length} IPs cached in SQLite`;

      if (list.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" style="text-align:center; padding:30px; color:var(--text-secondary);">
              No external IP addresses have been cached yet.
            </td>
          </tr>`;
        return;
      }

      let html = '';
      list.forEach(item => {
        const coords = item.latitude && item.longitude ? `${item.latitude}, ${item.longitude}` : 'N/A';
        html += `
          <tr>
            <td><strong style="font-family:monospace; font-size:13px;">${item.ip}</strong></td>
            <td>${item.country || 'Unknown'}</td>
            <td>${item.city || ''} ${item.region ? `(${item.region})` : ''}</td>
            <td><span class="truncate-text" style="max-width:180px; display:inline-block;" title="${window.app.escapeHtml(item.isp || '')}">${window.app.escapeHtml(item.isp || 'N/A')}</span></td>
            <td><span style="font-family:monospace; font-size:12px;">${item.asn || 'N/A'}</span></td>
            <td>${item.timezone || 'N/A'}</td>
            <td style="font-size:12px; font-family:monospace;">${coords}</td>
            <td style="text-align:right;">
              <button class="btn btn-outline btn-sm" onclick="intelController.inspectFromCache('${item.ip}')">View</button>
            </td>
          </tr>`;
      });
      tbody.innerHTML = html;
    } catch (e) {
      console.error('Error fetching cached IPs:', e);
    }
  }

  inspectFromCache(ip) {
    document.getElementById('intel-input-ip').value = ip;
    this.lookupIP(ip);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

window.intelController = new IntelligenceController();

