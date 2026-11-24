/**
 * NetSentry - Interactive World Threat Map Controller
 * Leaflet.js-powered real-time geolocation of active remote connections.
 * Developer: Mohsin
 */

class WorldMapController {
  constructor() {
    this.map = null;
    this.markersLayer = null;
    this.isInitialized = false;
    this.refreshTimer = null;
    this.init();
  }

  init() {
    this.setupEvents();
  }

  setupEvents() {
    document.getElementById('btn-refresh-map')?.addEventListener('click', () => {
      this.fetchMapData();
      window.app.showToast('Refreshed World Threat Map', 'info');
    });
  }

  initMap() {
    if (this.isInitialized || typeof L === 'undefined') return;

    const mapContainer = document.getElementById('threat-world-map');
    if (!mapContainer) return;

    // Initialize Leaflet map
    this.map = L.map('threat-world-map', {
      center: [22, 10],
      zoom: 2,
      minZoom: 1.5,
      maxZoom: 18,
      zoomControl: true,
      attributionControl: true
    });

    // Clean Google-style light map tiles (CartoDB Positron / OSM)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19
    }).addTo(this.map);

    this.markersLayer = L.layerGroup().addTo(this.map);
    this.isInitialized = true;

    // Force tile recalculation after rendering
    setTimeout(() => {
      if (this.map) this.map.invalidateSize();
    }, 200);
  }

  async fetchMapData() {
    if (!this.isInitialized) {
      this.initMap();
    } else if (this.map) {
      this.map.invalidateSize();
    }

    try {
      const res = await fetch('/api/map/endpoints');
      if (!res.ok) return;
      const data = await res.json();

      this.updateKPIs(data);
      this.renderMarkers(data.endpoints || []);
    } catch (e) {
      console.error('Error fetching threat map data:', e);
    }
  }

  updateKPIs(data) {
    document.getElementById('map-total-endpoints').innerText = data.total_endpoints ?? 0;
    
    const highRiskEl = document.getElementById('map-high-risk-count');
    if (highRiskEl) highRiskEl.innerText = data.high_risk_count ?? 0;

    const topCountriesContainer = document.getElementById('map-top-countries');
    if (topCountriesContainer && data.top_countries) {
      if (data.top_countries.length === 0) {
        topCountriesContainer.innerHTML = `<span style="color:var(--text-tertiary);">No active public external destinations.</span>`;
        return;
      }
      let html = '';
      data.top_countries.forEach(c => {
        html += `<span class="state-pill" style="font-size:12px; padding:3px 8px; background:#e8f0fe; color:#1a73e8;"><strong>${c.country}:</strong> ${c.count}</span>`;
      });
      topCountriesContainer.innerHTML = html;
    }
  }

  renderMarkers(endpoints) {
    if (!this.markersLayer) return;
    this.markersLayer.clearLayers();

    endpoints.forEach(pt => {
      const riskColor = this.getRiskColor(pt.risk_level);
      const riskClass = (pt.risk_level || 'safe').toLowerCase();

      // Pulsing Circle Marker
      const marker = L.circleMarker([pt.latitude, pt.longitude], {
        radius: 8,
        fillColor: riskColor,
        color: '#ffffff',
        weight: 2,
        opacity: 1,
        fillOpacity: 0.85
      });

      // Interactive Popup
      const popupContent = `
        <div style="font-family: -apple-system, sans-serif; font-size:12.5px; line-height:1.5; min-width:240px; padding:2px;">
          <div style="border-bottom: 1px solid #dadce0; padding-bottom:6px; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
            <strong style="font-size:14px; color:#202124;">${window.app.escapeHtml(pt.country)}</strong>
            <span class="status-pill pill-${riskClass}">${pt.risk_level}</span>
          </div>

          <div style="margin-bottom:4px;">
            <span style="color:#5f6368;">Remote IP:</span> <strong style="font-family:monospace;">${pt.ip}:${pt.port}</strong>
          </div>
          <div style="margin-bottom:4px;">
            <span style="color:#5f6368;">City/Region:</span> <strong>${window.app.escapeHtml(pt.city)}</strong>
          </div>
          <div style="margin-bottom:4px;">
            <span style="color:#5f6368;">ISP / Org:</span> <strong>${window.app.escapeHtml(pt.isp)}</strong>
          </div>
          <div style="margin-bottom:4px;">
            <span style="color:#5f6368;">ASN:</span> <span style="font-family:monospace;">${pt.asn}</span>
          </div>
          <div style="margin-bottom:8px;">
            <span style="color:#5f6368;">Process:</span> <strong>${window.app.escapeHtml(pt.process_name)}</strong> (PID: ${pt.pid || 'N/A'})
          </div>

          <div style="border-top:1px solid #f1f3f4; padding-top:8px; text-align:right;">
            <button class="btn btn-primary btn-sm" style="font-size:11.5px; padding:3px 10px;" onclick="connectionsController.inspectConnection('${pt.connection_key}')">
              Inspect Connection &rarr;
            </button>
          </div>
        </div>
      `;

      marker.bindPopup(popupContent, { maxWidth: 300 });
      this.markersLayer.addLayer(marker);
    });
  }

  getRiskColor(risk) {
    if (!risk) return '#34a853';
    const r = risk.toUpperCase();
    if (r === 'CRITICAL') return '#a50e0e';
    if (r === 'HIGH') return '#d93025';
    if (r === 'MEDIUM') return '#f9ab00';
    if (r === 'LOW') return '#1a73e8';
    return '#34a853'; // SAFE
  }
}

window.worldMapController = new WorldMapController();

