// ============================================================
// SIH26106: Cyber SOC Analyst Dashboard Controller
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    initLeafletMap();
    initGauge();
    initWaveform();
    initRelationshipGraph();
    setupEventListeners();
    fetchStats();
    checkSupabaseStatus();
});

// Current active analysis state
let currentResult = window.INITIAL_RESULT || null;
let leafletMap = null;
let mapMarkers = [];

// ============================================================
// 1. GAUGE CONTROLLER (SPEEDOMETER)
// ============================================================

function initGauge() {
    updateGauge(currentResult ? currentResult.risk_score : 87, currentResult ? currentResult.threat : 'HIGH');
}

function updateGauge(score, threat) {
    const scoreVal = Math.min(Math.max(parseInt(score) || 0, 0), 100);
    const scoreElement = document.getElementById('gauge-score');
    const badgeElement = document.getElementById('gauge-badge');
    const arcElement = document.getElementById('gauge-progress-arc');

    if (scoreElement) scoreElement.textContent = scoreVal;

    // Arc radius = 80, length of semi-circle arc = PI * 80 ≈ 251.32
    const maxOffset = 251.32;
    const progress = (scoreVal / 100) * maxOffset;
    const offset = maxOffset - progress;

    if (arcElement) {
        arcElement.style.strokeDasharray = `${maxOffset}`;
        arcElement.style.strokeDashoffset = `${offset}`;
    }

    if (badgeElement) {
        let threatClass = 'medium';
        let threatText = threat || 'MEDIUM';
        if (scoreVal >= 70) {
            threatClass = 'high';
            threatText = 'HIGH';
        } else if (scoreVal < 40) {
            threatClass = 'low';
            threatText = 'LOW';
        }
        badgeElement.className = `threat-level-badge ${threatClass}`;
        badgeElement.textContent = threatText;
    }
}

// ============================================================
// 2. WAVEFORM / SPECTRUM VISUALIZER
// ============================================================

function initWaveform() {
    const wrapper = document.getElementById('waveform-container');
    if (!wrapper) return;
    wrapper.innerHTML = '';

    const barCount = 32;
    for (let i = 0; i < barCount; i++) {
        const bar = document.createElement('div');
        bar.className = 'wave-bar';
        
        // Random organic height
        let baseHeight = Math.sin((i / barCount) * Math.PI) * 45 + Math.random() * 20;
        if (i > 18 && i < 26) {
            bar.classList.add('peak');
            baseHeight = Math.min(baseHeight + 25, 65);
        }
        bar.style.height = `${Math.max(baseHeight, 6)}px`;
        wrapper.appendChild(bar);
    }
}

// ============================================================
// 3. LEAFLET DARK MAP & GEOLOCATION
// ============================================================

function initLeafletMap() {
    const mapEl = document.getElementById('map');
    if (!mapEl) return;

    try {
        leafletMap = L.map('map', {
            zoomControl: false,
            attributionControl: false
        }).setView([20, 0], 2);

        // Dark Matter tiles
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            maxZoom: 19,
            subdomains: 'abcd',
        }).addTo(leafletMap);

        if (currentResult && currentResult.ip_results) {
            plotIpLocations(currentResult.ip_results);
        } else {
            // Default sample pins (Netherlands & US)
            addPulsingMarker(52.3676, 4.9041, "Amsterdam, NL (Tor Relay)");
            addPulsingMarker(37.7749, -122.4194, "San Francisco, US (Recipient)");
        }
    } catch (e) {
        console.warn("Leaflet map initialization warning:", e);
    }
}

function addPulsingMarker(lat, lng, title) {
    if (!leafletMap) return;
    const customIcon = L.divIcon({
        className: 'custom-map-pin',
        html: `<div style="width:14px;height:14px;background:#06B6D4;border:2px solid #FFFFFF;border-radius:50%;box-shadow:0 0 12px #06B6D4;"></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7]
    });
    const marker = L.marker([lat, lng], { icon: customIcon }).addTo(leafletMap);
    marker.bindPopup(`<strong style="color:#0F172A;">${title}</strong>`);
    mapMarkers.push(marker);
}

function plotIpLocations(ipResults) {
    if (!leafletMap) return;
    
    // Clear old markers
    mapMarkers.forEach(m => leafletMap.removeLayer(m));
    mapMarkers = [];

    const coordinates = [];
    ipResults.forEach(item => {
        if (item.latitude && item.longitude) {
            coordinates.push([item.latitude, item.longitude]);
            const title = `${item.city || 'Unknown'}, ${item.country || 'Unknown'} (${item.ip})`;
            addPulsingMarker(item.latitude, item.longitude, title);
        }
    });

    if (coordinates.length > 0) {
        leafletMap.fitBounds(coordinates, { maxZoom: 5, padding: [20, 20] });
    } else {
        // Fallback default coordinates
        leafletMap.setView([45, 10], 2);
    }
}

// ============================================================
// 4. RELATIONSHIP GRAPH (SENDER -> DOMAIN -> IP -> URL -> ATT)
// ============================================================

function initRelationshipGraph() {
    const svg = document.getElementById('graph-svg');
    if (!svg) return;

    const data = currentResult && currentResult.graph ? currentResult.graph : {
        nodes: [
            { id: "sender", label: "accounts@paypa1.com", type: "sender" },
            { id: "domain", label: "paypa1.com", type: "domain" },
            { id: "ip", label: "185.220.101.1", type: "ip" },
            { id: "url", label: "fake-bank.com/login", type: "url" },
            { id: "attachment", label: "invoice.exe", type: "attachment" }
        ],
        edges: [
            { from: "sender", to: "domain" },
            { from: "domain", to: "ip" },
            { from: "ip", to: "url" },
            { from: "sender", to: "attachment" }
        ]
    };

    renderGraph(data);
}

function renderGraph(graphData) {
    const svg = document.getElementById('graph-svg');
    if (!svg) return;
    svg.innerHTML = '';

    const width = svg.clientWidth || 650;
    const height = 240;

    // Node layout positions
    const positions = {
        sender: { x: width * 0.12, y: height * 0.5 },
        domain: { x: width * 0.35, y: height * 0.35 },
        attachment: { x: width * 0.35, y: height * 0.75 },
        ip: { x: width * 0.60, y: height * 0.35 },
        url: { x: width * 0.85, y: height * 0.5 }
    };

    // Defs for arrows and gradients
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    defs.innerHTML = `
        <marker id="arrow" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#06B6D4"/>
        </marker>
    `;
    svg.appendChild(defs);

    // Draw Edges
    graphData.edges.forEach(edge => {
        const fromPos = positions[edge.from] || { x: width * 0.2, y: height * 0.5 };
        const toPos = positions[edge.to] || { x: width * 0.8, y: height * 0.5 };

        const path = document.createElementNS("http://www.w3.org/2000/svg", "line");
        path.setAttribute("x1", fromPos.x);
        path.setAttribute("y1", fromPos.y);
        path.setAttribute("x2", toPos.x);
        path.setAttribute("y2", toPos.y);
        path.setAttribute("class", "graph-link");
        path.setAttribute("marker-end", "url(#arrow)");
        svg.appendChild(path);
    });

    // Draw Nodes
    graphData.nodes.forEach(node => {
        const pos = positions[node.id] || { x: width * 0.5, y: height * 0.5 };

        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("class", "graph-node");
        g.setAttribute("transform", `translate(${pos.x}, ${pos.y})`);

        let strokeColor = "#06B6D4";
        let fillColor = "#131B2E";
        if (node.type === "attachment" || node.type === "url") {
            strokeColor = "#EF4444";
        } else if (node.type === "ip") {
            strokeColor = "#F59E0B";
        }

        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("x", "-55");
        rect.setAttribute("y", "-16");
        rect.setAttribute("width", "110");
        rect.setAttribute("height", "32");
        rect.setAttribute("rx", "16");
        rect.setAttribute("fill", fillColor);
        rect.setAttribute("stroke", strokeColor);
        rect.setAttribute("stroke-width", "2");

        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("dy", "5");
        text.setAttribute("fill", "#F8FAFC");
        text.setAttribute("font-size", "11");
        text.setAttribute("font-family", "JetBrains Mono, monospace");
        text.setAttribute("font-weight", "600");
        
        let label = node.label || node.id;
        if (label.length > 14) label = label.substring(0, 12) + "..";
        text.textContent = label;

        g.appendChild(rect);
        g.appendChild(text);

        // Tooltip title
        const titleEl = document.createElementNS("http://www.w3.org/2000/svg", "title");
        titleEl.textContent = `${node.type.toUpperCase()}: ${node.full || node.label}`;
        g.appendChild(titleEl);

        svg.appendChild(g);
    });
}

// ============================================================
// 5. UPDATE FULL DASHBOARD DATA DYNAMICALLY
// ============================================================

function updateDashboardUI(data) {
    if (!data) return;
    currentResult = data;

    // 1. Gauge
    updateGauge(data.risk_score, data.threat);

    // 2. Subject / Sender / Recipient / Domain / URL
    const forensics = data.forensics || {};
    const subjVal = (forensics.subject && forensics.subject !== 'Not Found')
        ? forensics.subject
        : (data.subject || 'SIMULATED PHISHING TEST — NO ACTION REQUIRED');
    const subjEl = document.getElementById('card-subject');
    const headerSubj = document.getElementById('header-subject');
    if (subjEl) subjEl.textContent = subjVal;
    if (headerSubj) headerSubj.textContent = subjVal;

    const senderEl = document.getElementById('card-sender');
    if (senderEl) senderEl.textContent = forensics.from || data.sender || 'Not Found';

    const recipientEl = document.getElementById('card-recipient');
    if (recipientEl) recipientEl.textContent = forensics.to || data.receiver || 'Not Found';

    const domainEl = document.getElementById('card-domain');
    let domainVal = "Not Found";
    if (forensics.from && forensics.from.includes("@")) {
        domainVal = forensics.from.split("@").pop().replace(">", "");
    }
    if (domainEl) domainEl.textContent = domainVal;

    const urlEl = document.getElementById('card-url');
    const firstUrl = (data.urls && data.urls.length > 0) ? data.urls[0].url : 'None Detected';
    if (urlEl) {
        urlEl.textContent = firstUrl;
        urlEl.title = firstUrl;
    }

    // 3. Phishing Probability
    const probVal = data.phishing_probability !== undefined ? data.phishing_probability : 92;
    const probEl = document.getElementById('phishing-prob-value');
    const probFill = document.getElementById('phishing-prob-fill');
    if (probEl) probEl.textContent = `${probVal}%`;
    if (probFill) probFill.style.width = `${probVal}%`;

    // 4. Indicators
    const indicatorsList = document.getElementById('threat-indicators-list');
    if (indicatorsList && data.threat_indicators) {
        indicatorsList.innerHTML = '';
        data.threat_indicators.forEach(ind => {
            const pill = document.createElement('div');
            pill.className = `indicator-pill ${ind.level === 'warning' ? 'warning' : ind.level === 'success' ? 'success' : ''}`;
            pill.innerHTML = `
                <span class="indicator-icon">${ind.level === 'success' ? '🛡️' : ind.level === 'warning' ? '⚠️' : '🔴'}</span>
                <span>${ind.label}</span>
            `;
            indicatorsList.appendChild(pill);
        });
    }

    // 5. IP Intelligence
    const ipVal = (data.ips && data.ips.length > 0) ? data.ips[0] : '185.220.101.1';
    const ipDisplay = document.getElementById('geo-ip');
    if (ipDisplay) ipDisplay.textContent = ipVal;

    if (data.ip_results && data.ip_results.length > 0) {
        const firstGeo = data.ip_results[0];
        const countryEl = document.getElementById('geo-country');
        if (countryEl) countryEl.textContent = firstGeo.country || 'Unknown';
        const orgEl = document.getElementById('geo-org');
        if (orgEl) orgEl.textContent = firstGeo.organization || firstGeo.org || 'Unknown Host';
        plotIpLocations(data.ip_results);
    }

    // 6. Timeline
    const timelineList = document.getElementById('forensic-timeline-list');
    if (timelineList && data.timeline) {
        timelineList.innerHTML = '';
        data.timeline.forEach((item, idx) => {
            const isDanger = item.description.toLowerCase().includes('fail') || item.description.toLowerCase().includes('suspicious') || item.description.toLowerCase().includes('high');
            const el = document.createElement('div');
            el.className = 'timeline-item';
            el.innerHTML = `
                <div class="timeline-dot ${isDanger ? 'danger' : ''}"></div>
                <div class="timeline-content">
                    <div class="timeline-header">
                        <span class="timeline-time">${item.timestamp ? item.timestamp.split(' ')[1] || item.timestamp : '09:00 AM'}</span>
                        <span class="timeline-event-name">${item.event}</span>
                    </div>
                    <p class="timeline-desc">${item.description}</p>
                </div>
            `;
            timelineList.appendChild(el);
        });
    }

    // 7. Relationship Graph
    if (data.graph) {
        renderGraph(data.graph);
    }

    // Refresh live stats
    fetchStats();
}

// ============================================================
// 6. PRESET RUNNER
// ============================================================

function runPreset(presetId) {
    if (!presetId) return;
    showLoading(true);

    fetch(`/api/preset/${presetId}`, { method: 'POST' })
        .then(res => res.json())
        .then(res => {
            showLoading(false);
            if (res.success && res.data) {
                updateDashboardUI(res.data);
            } else {
                alert("Error running preset: " + (res.error || "Unknown error"));
            }
        })
        .catch(err => {
            showLoading(false);
            alert("Failed to analyze preset: " + err);
        });
}

// ============================================================
// 7. EVENT LISTENERS & MODAL MANAGEMENT
// ============================================================

function setupEventListeners() {
    // Preset dropdown
    const presetSelect = document.getElementById('preset-select');
    if (presetSelect) {
        presetSelect.addEventListener('change', (e) => {
            runPreset(e.target.value);
        });
    }

    // Modal triggers
    const openAnalyzeBtn = document.getElementById('btn-open-analyze');
    const analyzeModal = document.getElementById('modal-analyze');
    if (openAnalyzeBtn && analyzeModal) {
        openAnalyzeBtn.addEventListener('click', () => {
            analyzeModal.classList.add('active');
        });
    }

    const openHistoryBtn = document.getElementById('nav-history');
    const historyModal = document.getElementById('modal-history');
    if (openHistoryBtn && historyModal) {
        openHistoryBtn.addEventListener('click', () => {
            loadHistory();
            historyModal.classList.add('active');
        });
    }

    const openSettingsBtn = document.getElementById('nav-settings');
    const settingsModal = document.getElementById('modal-settings');
    const statusPill = document.getElementById('supabase-status-pill');
    if (openSettingsBtn && settingsModal) {
        openSettingsBtn.addEventListener('click', () => {
            settingsModal.classList.add('active');
        });
    }
    if (statusPill && settingsModal) {
        statusPill.addEventListener('click', () => {
            settingsModal.classList.add('active');
        });
    }

    // Close buttons
    document.querySelectorAll('.modal-close-btn, .btn-modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
        });
    });

    // Form submit for email analysis
    const analyzeForm = document.getElementById('form-analyze-email');
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(analyzeForm);
            showLoading(true);

            fetch('/api/analyze', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(res => {
                showLoading(false);
                if (res.success && res.data) {
                    analyzeModal.classList.remove('active');
                    updateDashboardUI(res.data);
                } else {
                    alert("Analysis error: " + (res.error || "Failed to analyze"));
                }
            })
            .catch(err => {
                showLoading(false);
                alert("Network error: " + err);
            });
        });
    }

    // Drag and drop zone
    const dropzone = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('email-file-input');
    if (dropzone && fileInput) {
        dropzone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                dropzone.querySelector('p').textContent = `Selected: ${fileInput.files[0].name}`;
            }
        });
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });
        dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                dropzone.querySelector('p').textContent = `Selected: ${e.dataTransfer.files[0].name}`;
            }
        });
    }

    // Export PDF Report buttons
    document.querySelectorAll('.btn-export-report').forEach(btn => {
        btn.addEventListener('click', () => {
            if (currentResult && currentResult.case_id) {
                window.location.href = `/api/export-report?case_id=${encodeURIComponent(currentResult.case_id)}`;
            } else {
                window.location.href = '/api/export-report';
            }
        });
    });

    // Supabase Settings form
    const settingsForm = document.getElementById('form-supabase-settings');
    if (settingsForm) {
        settingsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const url = document.getElementById('supabase-url-input').value.trim();
            const key = document.getElementById('supabase-key-input').value.trim();
            
            fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ supabase_url: url, supabase_key: key })
            })
            .then(res => res.json())
            .then(res => {
                alert(res.message);
                checkSupabaseStatus();
            })
            .catch(err => alert("Error saving settings: " + err));
        });
    }

    // Supabase Sync button
    const syncBtn = document.getElementById('btn-sync-supabase');
    if (syncBtn) {
        syncBtn.addEventListener('click', () => {
            syncBtn.disabled = true;
            syncBtn.textContent = 'Syncing...';
            fetch('/api/sync-supabase', { method: 'POST' })
                .then(res => res.json())
                .then(res => {
                    syncBtn.disabled = false;
                    syncBtn.textContent = 'Sync Local Cases to Supabase';
                    alert(res.message || res.error);
                })
                .catch(err => {
                    syncBtn.disabled = false;
                    syncBtn.textContent = 'Sync Local Cases to Supabase';
                    alert("Sync failed: " + err);
                });
        });
    }
}

// ============================================================
// 8. HELPERS & STATUS CHECKS
// ============================================================

function showLoading(active) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        if (active) overlay.classList.add('active');
        else overlay.classList.remove('active');
    }
}

function fetchStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(res => {
            if (res.success && res.stats) {
                const s = res.stats;
                const el = document.getElementById('stat-total-cases');
                if (el) el.textContent = s.total;
            }
        })
        .catch(() => {});
}

function checkSupabaseStatus() {
    fetch('/api/supabase-status')
        .then(res => res.json())
        .then(res => {
            const dot = document.getElementById('status-dot');
            const text = document.getElementById('status-text');
            if (res.configured && res.connected) {
                if (dot) dot.className = 'status-dot active';
                if (text) text.textContent = 'Supabase Cloud Active';
            } else {
                if (dot) dot.className = 'status-dot sqlite';
                if (text) text.textContent = 'Local SQLite Mode';
            }
        })
        .catch(() => {});
}

function loadHistory() {
    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;">Loading investigation records...</td></tr>';

    fetch('/api/history')
        .then(res => res.json())
        .then(res => {
            if (res.success && res.investigations) {
                if (res.investigations.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;">No investigation cases found yet.</td></tr>';
                    return;
                }
                tbody.innerHTML = '';
                res.investigations.forEach(inv => {
                    const tr = document.createElement('tr');
                    const threat = inv.threat_level || 'UNKNOWN';
                    let badgeColor = '#EF4444';
                    if (threat.includes('LOW') || threat.includes('SAFE')) badgeColor = '#10B981';
                    else if (threat.includes('MEDIUM')) badgeColor = '#F59E0B';

                    tr.innerHTML = `
                        <td style="font-family:var(--font-mono);font-weight:700;color:#06B6D4;">${inv.case_id}</td>
                        <td>${inv.timestamp}</td>
                        <td style="word-break:break-all;">${inv.sender || 'Unknown'}</td>
                        <td><span style="color:${badgeColor};font-weight:700;">${threat} (${inv.risk_score || 0})</span></td>
                        <td>
                            <button class="btn btn-secondary" style="padding:4px 10px;font-size:11px;" onclick="loadCaseDetails('${inv.case_id}')">View</button>
                            <a class="btn btn-report" style="padding:4px 10px;font-size:11px;text-decoration:none;" href="/api/export-report?case_id=${inv.case_id}">PDF</a>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        })
        .catch(() => {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#EF4444;">Failed to load history.</td></tr>';
        });
}

function loadCaseDetails(caseId) {
    showLoading(true);
    fetch(`/api/case/${caseId}`)
        .then(res => res.json())
        .then(res => {
            showLoading(false);
            if (res.success && res.case) {
                document.getElementById('modal-history').classList.remove('active');
                updateDashboardUI(res.case);
            }
        })
        .catch(err => {
            showLoading(false);
            alert("Error loading case: " + err);
        });
}
