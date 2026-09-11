// ============================================================
// SIH26106: Cyber SOC Analyst Dashboard Controller
// ============================================================

if (!window.__SIH_DASHBOARD_INITIALIZED__) {
    window.__SIH_DASHBOARD_INITIALIZED__ = true;
    document.addEventListener('DOMContentLoaded', () => {
        initLeafletMap();
        initGauge();
        initWaveform();
        initRelationshipGraph();
        setupEventListeners();
        fetchStats();
        checkSupabaseStatus();
    });
}

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
    if (ipDisplay) {
        ipDisplay.textContent = ipVal;
        ipDisplay.title = ipVal;
    }

    if (data.ip_results && data.ip_results.length > 0) {
        const firstGeo = data.ip_results[0];
        const countryEl = document.getElementById('geo-country');
        if (countryEl) {
            countryEl.textContent = firstGeo.country || 'Unknown';
            countryEl.title = firstGeo.country || 'Unknown';
        }
        const orgEl = document.getElementById('geo-org');
        const orgVal = firstGeo.organization || firstGeo.org || 'Unknown Host';
        if (orgEl) {
            orgEl.textContent = orgVal;
            orgEl.title = orgVal;
        }
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
    // Mobile sidebar drawer handlers
    const sidebar = document.getElementById('app-sidebar');
    const sidebarToggleBtn = document.getElementById('btn-sidebar-toggle');
    const sidebarCloseBtn = document.getElementById('btn-sidebar-close');
    const sidebarBackdrop = document.getElementById('sidebar-backdrop');

    function openMobileSidebar() {
        if (sidebar) sidebar.classList.add('open');
        if (sidebarBackdrop) sidebarBackdrop.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function closeMobileSidebar() {
        if (sidebar) sidebar.classList.remove('open');
        if (sidebarBackdrop) sidebarBackdrop.classList.remove('active');
        document.body.style.overflow = '';
    }

    if (sidebarToggleBtn) {
        sidebarToggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (sidebar && sidebar.classList.contains('open')) {
                closeMobileSidebar();
            } else {
                openMobileSidebar();
            }
        });
    }

    if (sidebarCloseBtn) {
        sidebarCloseBtn.addEventListener('click', closeMobileSidebar);
    }

    if (sidebarBackdrop) {
        sidebarBackdrop.addEventListener('click', closeMobileSidebar);
    }

    // Auto-close sidebar on mobile when clicking navigation links or settings
    document.querySelectorAll('.nav-menu .nav-item, .sidebar-footer .nav-item, #supabase-status-pill').forEach(item => {
        item.addEventListener('click', () => {
            if (window.innerWidth <= 992) {
                closeMobileSidebar();
            }
        });
    });

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

    // ============================================================
    // DYNAMIC LIVE FILE VALIDATION & INGESTION CONTROLLER
    // ============================================================

    const DANGEROUS_EXTENSIONS = [
        'exe', 'dll', 'sys', 'com', 'scr', 'pif', 'bat', 'cmd', 'ps1', 'vbs',
        'vbe', 'js', 'jse', 'wsf', 'wsh', 'msc', 'msi', 'msp', 'reg', 'hta',
        'jar', 'app', 'dmg', 'pkg', 'deb', 'rpm', 'elf', 'bin', 'so', 'dylib',
        'sh', 'bash', 'csh', 'py', 'pl', 'php'
    ];

    function formatFileSize(bytes) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    async function validateEmailFileClient(file) {
        if (!file) {
            return { isValid: false, error: 'No file selected. Please choose a valid .eml file.' };
        }

        const fileName = file.name || 'unnamed_file';
        const lowerName = fileName.toLowerCase();

        // 1. Check empty file (0 bytes)
        if (file.size === 0) {
            return {
                isValid: false,
                error: `⛔ Empty File: "${fileName}" contains 0 bytes. Please upload a valid RFC 822 email file.`
            };
        }

        // 2. Check maximum size (15 MB)
        const MAX_SIZE = 15 * 1024 * 1024;
        if (file.size > MAX_SIZE) {
            return {
                isValid: false,
                error: `⛔ File Too Large: "${fileName}" is ${formatFileSize(file.size)}. Maximum allowed size is 15 MB.`
            };
        }

        // 3. Extension inspection
        const extMatch = lowerName.match(/\.([a-z0-9_-]+)$/);
        const ext = extMatch ? extMatch[1] : '';

        const IMAGE_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'tif', 'svg', 'ico', 'heic', 'jfif', 'avif'];
        const DOC_EXTS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'xml', 'csv', 'tsv', 'rtf', 'odt'];

        if (ext !== 'eml') {
            if (DANGEROUS_EXTENSIONS.includes(ext)) {
                return {
                    isValid: false,
                    error: `⛔ Security Violation: "${fileName}" is an executable or dangerous file type (.${ext}). Executable binaries cannot be analyzed as email files. Only RFC 822 (.eml) files are permitted.`
                };
            }
            if (IMAGE_EXTS.includes(ext)) {
                return {
                    isValid: false,
                    error: `🖼️ Image File Rejected: "${fileName}" is an image file (.${ext}). Aadhaar card photos, screenshots, and graphics cannot be analyzed as emails. Only RFC 822 (.eml) files are supported.`
                };
            }
            if (DOC_EXTS.includes(ext)) {
                return {
                    isValid: false,
                    error: `📄 Document Rejected: "${fileName}" is a document (.${ext}). Aadhaar card PDFs, identity files, and spreadsheets cannot be ingested. Only RFC 822 (.eml) files are supported.`
                };
            }
            return {
                isValid: false,
                error: `❌ Unsupported File Format: "${fileName}". Only RFC 822 email files (.eml) are supported for forensic investigation.`
            };
        }

        // 4. Double extension check (e.g. payload.exe.eml, aadhaar.pdf.eml)
        const tokens = lowerName.split('.');
        if (tokens.length > 2) {
            const innerExt = tokens[tokens.length - 2];
            if (DANGEROUS_EXTENSIONS.includes(innerExt)) {
                return {
                    isValid: false,
                    error: `⛔ Security Alert: Double extension detected with dangerous payload signature (.${innerExt}.${ext}). Disguised executable files are strictly prohibited.`
                };
            }
            if (DOC_EXTS.includes(innerExt) || IMAGE_EXTS.includes(innerExt)) {
                return {
                    isValid: false,
                    error: `⛔ Security Alert: Double extension detected with disguised document/image signature (.${innerExt}.${ext}). Disguised files are prohibited.`
                };
            }
        }

        // 5. Binary magic byte inspection via FileReader
        try {
            const buffer = await file.slice(0, 512).arrayBuffer();
            const bytes = new Uint8Array(buffer);

            // Windows PE / DOS Executable: 'MZ' (0x4D 0x5A)
            if (bytes.length >= 2 && bytes[0] === 0x4D && bytes[1] === 0x5A) {
                return {
                    isValid: false,
                    error: `⛔ Executable Binary Detected: "${fileName}" contains Windows PE / DOS executable magic bytes (MZ). Executables cannot be analyzed as emails.`
                };
            }

            // Linux ELF Executable: 0x7F 'E' 'L' 'F'
            if (bytes.length >= 4 && bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) {
                return {
                    isValid: false,
                    error: `⛔ Executable Binary Detected: "${fileName}" contains Linux ELF executable magic bytes. Executables cannot be analyzed as emails.`
                };
            }

            // Mach-O Executables
            if (bytes.length >= 4) {
                if ((bytes[0] === 0xFE && bytes[1] === 0xED && bytes[2] === 0xFA && (bytes[3] === 0xCE || bytes[3] === 0xCF)) ||
                    (bytes[0] === 0xCE && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE) ||
                    (bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE) ||
                    (bytes[0] === 0xCA && bytes[1] === 0xFE && bytes[2] === 0xBA && bytes[3] === 0xBE)) {
                    return {
                        isValid: false,
                        error: `⛔ Executable Binary Detected: "${fileName}" contains Mach-O binary magic bytes. Executables cannot be analyzed as emails.`
                    };
                }
            }

            // ZIP / Archive: 0x50 0x4B 0x03 0x04
            if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) {
                return {
                    isValid: false,
                    error: `📦 Archive File Detected: "${fileName}" is a compressed archive (.zip/.jar). Please extract the archive and upload the individual .eml file.`
                };
            }

            // PDF: %PDF-
            if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
                return {
                    isValid: false,
                    error: `📄 PDF Document Detected: "${fileName}" is a PDF file, not an email message. Only raw RFC 822 email files (.eml) can be ingested.`
                };
            }

            // JPEG image: 0xFF 0xD8 0xFF
            if (bytes.length >= 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
                return {
                    isValid: false,
                    error: `🖼️ JPEG Image Detected: "${fileName}" is a photo/scan, not an email message. Only RFC 822 (.eml) files are permitted.`
                };
            }

            // PNG image: 0x89 0x50 0x4E 0x47
            if (bytes.length >= 4 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
                return {
                    isValid: false,
                    error: `🖼️ PNG Image Detected: "${fileName}" is a graphics image, not an email message. Only RFC 822 (.eml) files are permitted.`
                };
            }

            // BMP image: 'BM'
            if (bytes.length >= 2 && bytes[0] === 0x42 && bytes[1] === 0x4D) {
                return {
                    isValid: false,
                    error: `🖼️ Bitmap Image Detected: "${fileName}" is a BMP image file. Only RFC 822 (.eml) files are permitted.`
                };
            }

            // Null-byte density check
            let nullCount = 0;
            for (let i = 0; i < bytes.length; i++) {
                if (bytes[i] === 0x00) nullCount++;
            }
            if (bytes.length > 0 && (nullCount / bytes.length) > 0.01) {
                return {
                    isValid: false,
                    error: `⛔ Binary File Rejected: "${fileName}" contains binary data sequences and is not a valid text-based email message.`
                };
            }
        } catch (e) {
            console.warn("Could not read file slice for magic byte inspection:", e);
        }

        // 6. Text RFC 822 header and Identity document inspection
        try {
            const textChunk = await file.slice(0, 2048).text();
            const lowerChunk = textChunk.toLowerCase();
            const headerRegex = /^(?:From|To|Subject|Date|Received|Message-ID|Return-Path|MIME-Version|Content-Type|Delivered-To|DKIM-Signature|Authentication-Results|X-[a-zA-Z0-9_-]+)\s*:/im;
            const hasHeader = headerRegex.test(textChunk);
            const hasFromEmail = /^From\s*:\s*.+@.+/im.test(textChunk);

            // Identity document inspection (Aadhaar, PAN)
            const isAadhaar = lowerChunk.includes('aadhaar') || lowerChunk.includes('uidai') || lowerChunk.includes('mera aadhaar') || lowerChunk.includes('help@uidai.gov.in') || /\b\d{4}\s\d{4}\s\d{4}\b/.test(textChunk);
            const isPan = lowerChunk.includes('income tax department') || lowerChunk.includes('permanent account number') || /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/.test(textChunk);

            if ((isAadhaar || isPan) && !hasFromEmail) {
                return {
                    isValid: false,
                    error: `🪪 Identity Document Detected: "${fileName}" appears to be an Indian Aadhaar Card or Identity document. Personal identity records cannot be analyzed as emails.`
                };
            }

            if (!hasHeader) {
                return {
                    isValid: false,
                    error: `⚠️ Invalid Email Structure: "${fileName}" does not contain standard RFC 822 email headers (e.g., From, To, Subject, Date). Non-email files cannot be analyzed.`
                };
            }
        } catch (e) {
            console.warn("Could not read text chunk for header inspection:", e);
        }

        return {
            isValid: true,
            file: file,
            name: fileName,
            size: file.size,
            formattedSize: formatFileSize(file.size)
        };
    }

    function showValidationFeedback(type, message) {
        const feedback = document.getElementById('file-validation-feedback');
        if (!feedback) return;
        feedback.className = `file-validation-feedback ${type}`;
        feedback.innerHTML = `<span>${message}</span>`;
        feedback.style.display = 'flex';
    }

    function clearValidationFeedback() {
        const feedback = document.getElementById('file-validation-feedback');
        if (!feedback) return;
        feedback.style.display = 'none';
        feedback.className = 'file-validation-feedback';
        feedback.innerHTML = '';
    }

    function setValidSelectedFile(fileValidation) {
        const dropzone = document.getElementById('file-dropzone');
        const defaultContent = document.getElementById('dropzone-default-content');
        const selectedCard = document.getElementById('file-selected-card');
        const selectedName = document.getElementById('file-selected-name');
        const selectedMeta = document.getElementById('file-selected-meta');

        if (dropzone) {
            dropzone.classList.remove('is-invalid');
            dropzone.classList.add('is-valid');
        }
        if (defaultContent) defaultContent.style.display = 'none';
        if (selectedCard) {
            if (selectedName) selectedName.textContent = fileValidation.name;
            if (selectedMeta) selectedMeta.textContent = `Verified RFC 822 Email • ${fileValidation.formattedSize}`;
            selectedCard.style.display = 'flex';
        }
        clearValidationFeedback();
    }

    function clearSelectedFile() {
        const fileInput = document.getElementById('email-file-input');
        const dropzone = document.getElementById('file-dropzone');
        const defaultContent = document.getElementById('dropzone-default-content');
        const selectedCard = document.getElementById('file-selected-card');

        if (fileInput) fileInput.value = '';
        if (dropzone) {
            dropzone.classList.remove('is-valid', 'is-invalid', 'dragover', 'dragover-valid', 'dragover-invalid');
        }
        if (defaultContent) defaultContent.style.display = 'block';
        if (selectedCard) selectedCard.style.display = 'none';
        clearValidationFeedback();
    }

    function triggerInvalidDropzone(errorMessage) {
        const fileInput = document.getElementById('email-file-input');
        const dropzone = document.getElementById('file-dropzone');
        const defaultContent = document.getElementById('dropzone-default-content');
        const selectedCard = document.getElementById('file-selected-card');

        if (fileInput) fileInput.value = '';
        if (selectedCard) selectedCard.style.display = 'none';
        if (defaultContent) defaultContent.style.display = 'block';

        if (dropzone) {
            dropzone.classList.remove('is-valid', 'dragover-valid', 'dragover-invalid');
            dropzone.classList.remove('is-invalid');
            // Trigger reflow to restart shake animation
            void dropzone.offsetWidth;
            dropzone.classList.add('is-invalid');
        }

        showValidationFeedback('error', errorMessage);
    }

    // Attach Dropzone & File Input Listeners
    const dropzone = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('email-file-input');
    const btnRemoveFile = document.getElementById('btn-remove-file');
    const emailTextInput = document.getElementById('email-text-input');
    const textareaFeedback = document.getElementById('textarea-validation-feedback');

    if (btnRemoveFile) {
        btnRemoveFile.addEventListener('click', (e) => {
            e.stopPropagation();
            clearSelectedFile();
        });
    }

    if (dropzone && fileInput) {
        dropzone.addEventListener('click', (e) => {
            if (e.target.closest('#file-selected-card') || e.target.closest('#btn-remove-file')) {
                return;
            }
            fileInput.click();
        });

        fileInput.addEventListener('change', async () => {
            if (fileInput.files && fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const validation = await validateEmailFileClient(file);
                if (validation.isValid) {
                    setValidSelectedFile(validation);
                } else {
                    triggerInvalidDropzone(validation.error);
                }
            }
        });

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();

            let hasInvalidItem = false;
            if (e.dataTransfer && e.dataTransfer.items) {
                for (let i = 0; i < e.dataTransfer.items.length; i++) {
                    const item = e.dataTransfer.items[i];
                    if (item.type && (item.type.includes('x-msdownload') || item.type.includes('x-dosexec') || item.type.includes('executable'))) {
                        hasInvalidItem = true;
                        break;
                    }
                }
            }

            if (hasInvalidItem) {
                dropzone.classList.remove('dragover-valid');
                dropzone.classList.add('dragover-invalid');
            } else {
                dropzone.classList.remove('dragover-invalid');
                dropzone.classList.add('dragover-valid');
            }
        });

        dropzone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover', 'dragover-valid', 'dragover-invalid');
        });

        dropzone.addEventListener('drop', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover', 'dragover-valid', 'dragover-invalid');

            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                const file = e.dataTransfer.files[0];
                const validation = await validateEmailFileClient(file);
                if (validation.isValid) {
                    fileInput.files = e.dataTransfer.files;
                    setValidSelectedFile(validation);
                } else {
                    triggerInvalidDropzone(validation.error);
                }
            }
        });
    }

    // Live Textarea Feedback
    if (emailTextInput) {
        emailTextInput.addEventListener('input', () => {
            const val = emailTextInput.value;
            const lowerVal = val.toLowerCase();
            const isAadhaar = lowerVal.includes('aadhaar') || lowerVal.includes('uidai') || lowerVal.includes('mera aadhaar') || lowerVal.includes('help@uidai.gov.in') || /\b\d{4}\s\d{4}\s\d{4}\b/.test(val);
            const isPan = lowerVal.includes('income tax department') || lowerVal.includes('permanent account number') || /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/.test(val);
            const hasFromEmail = /^From\s*:\s*.+@.+/im.test(val);

            if (val.includes('\x00')) {
                showValidationFeedback('error', '⛔ Binary data detected in text area. Executable payloads cannot be pasted.');
                if (textareaFeedback) {
                    textareaFeedback.innerHTML = '<span style="color:#ef4444;">Binary payload detected!</span>';
                }
            } else if ((isAadhaar || isPan) && !hasFromEmail) {
                showValidationFeedback('error', '🪪 Identity Document Detected: Pasted text appears to be an Indian Aadhaar / Identity document. The forensic engine analyzes RFC 822 emails.');
                if (textareaFeedback) {
                    textareaFeedback.innerHTML = '<span style="color:#ef4444;font-weight:600;">Identity document detected (Aadhaar/PAN)</span>';
                }
            } else if (val.trim().length > 0) {
                if (textareaFeedback) {
                    textareaFeedback.innerHTML = `<span>Pasted text: ${val.length} chars</span>`;
                }
                clearValidationFeedback();
            } else {
                if (textareaFeedback) textareaFeedback.innerHTML = '';
            }
        });
    }

    // Form submit for email analysis
    const analyzeForm = document.getElementById('form-analyze-email');
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
            const textVal = emailTextInput ? emailTextInput.value.trim() : '';

            // Pre-flight client verification
            if (hasFile) {
                const validation = await validateEmailFileClient(fileInput.files[0]);
                if (!validation.isValid) {
                    triggerInvalidDropzone(validation.error);
                    return;
                }
            } else if (textVal) {
                const lowerText = textVal.toLowerCase();
                const isAadhaar = lowerText.includes('aadhaar') || lowerText.includes('uidai') || lowerText.includes('mera aadhaar') || lowerText.includes('help@uidai.gov.in') || /\b\d{4}\s\d{4}\s\d{4}\b/.test(textVal);
                const isPan = lowerText.includes('income tax department') || lowerText.includes('permanent account number') || /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/.test(textVal);
                const hasFromEmail = /^From\s*:\s*.+@.+/im.test(textVal);

                if (textVal.includes('\x00')) {
                    showValidationFeedback('error', '⛔ Binary payload detected in text input. Cannot analyze binary executables.');
                    return;
                }
                if ((isAadhaar || isPan) && !hasFromEmail) {
                    showValidationFeedback('error', '🪪 Identity Document Rejected: Pasted text contains Aadhaar Card / Identity records. Personal documents cannot be ingested as email evidence.');
                    return;
                }
                if (textVal.length < 15) {
                    showValidationFeedback('warning', '⚠️ The provided email text is too short. Please provide complete headers and body.');
                    return;
                }
            } else {
                showValidationFeedback('warning', '⚠️ Please upload a valid .eml file or paste email headers and body to analyze.');
                if (dropzone) {
                    void dropzone.offsetWidth;
                    dropzone.classList.add('is-invalid');
                }
                return;
            }

            const formData = new FormData(analyzeForm);
            showLoading(true);

            fetch('/api/analyze', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json().then(data => ({ status: res.status, ok: res.ok, data: data })))
            .then(({ status, ok, data }) => {
                showLoading(false);
                if (ok && data.success && data.data) {
                    analyzeModal.classList.remove('active');
                    clearSelectedFile();
                    if (emailTextInput) emailTextInput.value = '';
                    updateDashboardUI(data.data);
                } else {
                    const errMsg = data.error || (data.details && data.details.code) || "Analysis failed";
                    showValidationFeedback('error', `❌ Analysis Error: ${errMsg}`);
                    triggerInvalidDropzone(errMsg);
                }
            })
            .catch(err => {
                showLoading(false);
                showValidationFeedback('error', `⚠️ Network Error: ${err.message || err}`);
            });
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
