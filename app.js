/* ThreatGrapher - Static Site Client-Side Logic
 * Replaces all Dash server-side callbacks with client-side fetch + render.
 */

let techniqueTree = null;
let currentView = 'techniques';
let currentTechnique = null;
let currentScenario = null;
let currentFile = null;
let graphViewMode = 'full';
let coverageLoaded = false;
let detectionsLoaded = false;

// ---- Initialization ----

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch('data/technique_tree.json');
        techniqueTree = await res.json();
        buildSidebar(techniqueTree);
        await loadStatsPanel();
    } catch (e) {
        console.error('Failed to load technique tree:', e);
    }
    initTables();
});

// ---- Stats Panel ----

async function loadStatsPanel() {
    try {
        const res = await fetch('data/dataset_stats.json');
        const stats = await res.json();
        const panel = document.getElementById('stats-panel');
        if (!panel || !stats) return;

        const sizeBytes = stats.total_size_bytes || 0;
        let sizeStr;
        if (sizeBytes >= 1024*1024*1024) sizeStr = (sizeBytes/(1024**3)).toFixed(1)+' GB';
        else if (sizeBytes >= 1024*1024) sizeStr = Math.round(sizeBytes/(1024**2))+' MB';
        else sizeStr = Math.round(sizeBytes/1024)+' KB';

        const topEids = stats.top_event_ids || {};
        let eidHtml = '';
        for (const [eid, count] of Object.entries(topEids).slice(0, 6)) {
            eidHtml += `<span style="margin-right:14px"><span style="color:#e0e0e0;font-size:11px;font-family:Share Tech Mono,monospace">EID ${eid}</span><span style="color:#555;font-size:10px;font-family:Share Tech Mono,monospace"> (${count.toLocaleString()})</span></span>`;
        }

        panel.innerHTML = `
            <div class="glow-card">
                <div style="font-size:10px;letter-spacing:3px;color:#555;margin-bottom:8px;font-family:Share Tech Mono,monospace">DATASET OVERVIEW</div>
                <div style="background:rgba(15,15,35,0.6);border:1px solid #1a1a2e;border-radius:4px;padding:12px 15px;margin-bottom:15px">
                    <div style="display:flex;justify-content:space-around;padding-bottom:10px;margin-bottom:10px;border-bottom:1px solid #1a1a2e">
                        ${statBox('TECHNIQUES', stats.technique_count||0, '#3498db')}
                        ${statBox('MITRE IDS', stats.mitre_technique_count||0, '#9b59b6')}
                        ${statBox('LOG FILES', stats.total_files||0, '#2ecc71')}
                        ${statBox('TOTAL SIZE', sizeStr, '#e74c3c')}
                        ${statBox('SAMPLED EVENTS', (stats.sample_event_count||0).toLocaleString(), '#f39c12')}
                    </div>
                    ${eidHtml ? `<div><span style="font-size:9px;letter-spacing:2px;color:#3498db;margin-right:10px;font-family:Share Tech Mono,monospace">TOP EVENT IDS  </span>${eidHtml}</div>` : ''}
                </div>
            </div>`;
    } catch (e) { /* stats panel is optional */ }
}

function statBox(label, value, color) {
    return `<div class="stat-box"><div class="stat-value" style="color:${color}">${value}</div><div class="stat-label">${label}</div></div>`;
}

// ---- Sidebar ----

function buildSidebar(tree) {
    const container = document.getElementById('sidebar-techniques');
    if (!container || !tree) return;
    const techniques = tree.techniques || {};
    const grouped = tree.grouped || {};
    let html = '';

    for (const parentId of Object.keys(grouped).sort()) {
        const subIds = grouped[parentId];
        const pData = techniques[parentId] || {};
        const desc = ((pData.yml_data||{}).description||'').substring(0, 57);
        const fileCount = (pData.files||[]).length;
        const scenarioCount = Object.keys(pData.scenarios||{}).length;
        const total = fileCount + scenarioCount + subIds.length;

        let inner = '';
        if (pData.files && pData.files.length) {
            inner += `<div style="margin-left:10px" class="sidebar-item" data-tid="${parentId}" data-scenario="__toplevel__" onclick="onSidebarClick(this)"><span style="font-size:12px">  Files (${fileCount})</span></div>`;
        }
        for (const [scName, scData] of Object.entries(pData.scenarios||{}).sort()) {
            const scFc = (scData.files||[]).length;
            inner += `<div style="margin-left:10px" class="sidebar-item" data-tid="${parentId}" data-scenario="${scName}" onclick="onSidebarClick(this)"><span style="font-size:12px">  ${scName}</span>${scFc?` <span style="font-size:9px;background:#6c757d;color:#fff;padding:1px 6px;border-radius:10px">${scFc}</span>`:''}</div>`;
        }

        for (const subId of subIds) {
            const sData = techniques[subId] || {};
            const subFc = (sData.files||[]).length;
            const subSc = Object.keys(sData.scenarios||{}).length;
            let subInner = '';
            if (sData.files && sData.files.length) {
                subInner += `<div style="margin-left:20px" class="sidebar-item" data-tid="${subId}" data-scenario="__toplevel__" onclick="onSidebarClick(this)"><span style="font-size:12px">    Files (${subFc})</span></div>`;
            }
            for (const [scn, scd] of Object.entries(sData.scenarios||{}).sort()) {
                const scfc = (scd.files||[]).length;
                subInner += `<div style="margin-left:20px" class="sidebar-item" data-tid="${subId}" data-scenario="${scn}" onclick="onSidebarClick(this)"><span style="font-size:12px">    ${scn}</span>${scfc?` <span style="font-size:9px;background:#6c757d;color:#fff;padding:1px 6px;border-radius:10px">${scfc}</span>`:''}</div>`;
            }
            inner += `<details style="margin-bottom:2px"><summary style="cursor:pointer;padding:4px 0;font-size:12px;color:#b0b0b0;margin-left:10px"><span style="font-weight:bold;color:#9b59b6">${subId}</span>${(subFc+subSc)?` <span style="font-size:9px;background:#6c757d;color:#fff;padding:1px 6px;border-radius:10px">${subFc+subSc}</span>`:''}</summary><div>${subInner}</div></details>`;
        }

        html += `<details style="margin-bottom:4px"><summary style="cursor:pointer;padding:6px 0;font-size:13px;border-bottom:1px solid #2a2a4a"><span style="font-weight:bold;color:#3498db">${parentId}</span><span style="font-size:11px;color:#888;margin-left:5px">${desc?` - ${desc}`:''}</span>${total?` <span style="font-size:9px;background:#17a2b8;color:#fff;padding:1px 6px;border-radius:10px">${total}</span>`:''}</summary><div style="padding-left:5px;padding-top:4px">${inner}</div></details>`;
    }
    container.innerHTML = html;
}

function filterSidebar(query) {
    const q = query.toLowerCase();
    const details = document.querySelectorAll('#sidebar-techniques > details');
    details.forEach(det => {
        const text = det.textContent.toLowerCase();
        det.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
}

// ---- Sidebar Click ----

async function onSidebarClick(el) {
    const tid = el.dataset.tid;
    const scenario = el.dataset.scenario;
    currentTechnique = tid;
    currentScenario = scenario;

    // Highlight active
    document.querySelectorAll('.sidebar-item').forEach(i => i.style.backgroundColor = '');
    el.style.backgroundColor = 'rgba(52,152,219,0.15)';

    const basePath = `techniques/${tid}/${scenario}`;

    // Load metadata
    try {
        const res = await fetch(`${basePath}/meta.html`);
        document.getElementById('metadata-panel').innerHTML = await res.text();
    } catch (e) {
        document.getElementById('metadata-panel').innerHTML = '<p style="color:#555">No metadata available.</p>';
    }

    // Load file tabs
    try {
        const res = await fetch(`${basePath}/files.json`);
        const files = await res.json();
        if (files.length === 0) {
            document.getElementById('file-tabs-container').innerHTML = '<p style="color:#555;font-size:13px;padding:10px">No parseable files in this location.</p>';
            return;
        }
        let tabsHtml = '<div style="margin-bottom:10px">';
        files.forEach((f, i) => {
            const has = (f.has || []).join(',');
            tabsHtml += `<span class="file-tab${i===0?' active':''}" data-file-id="${f.id}" data-has="${has}" onclick="onFileTabClick(this)">${f.name}</span>`;
        });
        tabsHtml += '</div>';
        document.getElementById('file-tabs-container').innerHTML = tabsHtml;

        // Auto-click first file
        onFileTabClick(document.querySelector('.file-tab'));
    } catch (e) {
        document.getElementById('file-tabs-container').innerHTML = '';
    }
}

// ---- File Tab Click ----

async function onFileTabClick(el) {
    if (!el) return;
    const fileId = el.dataset.fileId;
    const has = (el.dataset.has || '').split(',');
    currentFile = fileId;

    // Highlight active tab
    document.querySelectorAll('.file-tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');

    const basePath = `techniques/${currentTechnique}/${currentScenario}`;

    // Load info bar
    if (has.includes('info')) {
        try {
            const res = await fetch(`${basePath}/${fileId}.info.html`);
            document.getElementById('loading-info').innerHTML = await res.text();
        } catch (e) { document.getElementById('loading-info').innerHTML = ''; }
    } else {
        document.getElementById('loading-info').innerHTML = '';
    }

    // Load detection bar + graphs
    let graphHtml = '';

    // Detection bar
    if (has.includes('detection')) {
        try {
            const res = await fetch(`${basePath}/${fileId}.detection.html`);
            graphHtml += await res.text();
        } catch (e) {}
    }

    const hasGraphs = has.includes('full') || has.includes('simple');

    if (hasGraphs) {
        // Graph view controls
        graphHtml += `<div style="margin-bottom:10px">
            <button class="view-btn${graphViewMode==='full'?' active':''}" onclick="setGraphView('full')">FULL</button>
            <button class="view-btn${graphViewMode==='simple'?' active':''}" onclick="setGraphView('simple')">SIMPLIFIED</button>
            <button class="view-btn${graphViewMode==='scroll'?' active':''}" onclick="setGraphView('scroll')">SCROLL VIEW</button>
        </div>`;

        // Graph containers
        graphHtml += `<div id="graph-scroll-wrapper" style="overflow-x:hidden">
            <div id="graph-panel-full" style="display:${graphViewMode==='simple'?'none':'block'}"></div>
            <div id="graph-panel-simple" style="display:${graphViewMode==='full'?'none':'block'}"></div>
        </div>`;
    } else {
        graphHtml += '<p style="color:#444;font-size:13px;text-align:center;padding:40px;letter-spacing:1px">No graph entities could be extracted from this file.</p>';
    }

    document.getElementById('graph-container').innerHTML = graphHtml;

    // Load Plotly figures (only if they exist)
    if (has.includes('full')) {
        try {
            const res = await fetch(`${basePath}/${fileId}.full.json`);
            const figData = await res.json();
            const height = figData._height || 600;
            delete figData._height;
            const fullDiv = document.getElementById('graph-panel-full');
            fullDiv.style.height = height + 'px';
            Plotly.react(fullDiv, figData.data, figData.layout, {displayModeBar:true, scrollZoom:true, displaylogo:false});
        } catch (e) {
            document.getElementById('graph-panel-full').innerHTML = '<p style="color:#444;font-size:13px;text-align:center;padding:40px;letter-spacing:1px">Failed to load graph.</p>';
        }
    }

    if (has.includes('simple')) {
        try {
            const res = await fetch(`${basePath}/${fileId}.simple.json`);
            const figData = await res.json();
            const height = figData._height || 600;
            delete figData._height;
            const simpleDiv = document.getElementById('graph-panel-simple');
            simpleDiv.style.height = height + 'px';
            Plotly.react(simpleDiv, figData.data, figData.layout, {displayModeBar:true, scrollZoom:true, displaylogo:false});
        } catch (e) {
            document.getElementById('graph-panel-simple').innerHTML = '';
        }
    }

    // Apply current view mode
    if (hasGraphs) applyGraphView();

    // Load event table
    if (has.includes('table')) {
        try {
            const res = await fetch(`${basePath}/${fileId}.table.html`);
            document.getElementById('table-container').innerHTML = await res.text();
            initTables();
        } catch (e) { document.getElementById('table-container').innerHTML = ''; }
    } else {
        document.getElementById('table-container').innerHTML = '';
    }
}

// ---- Graph View Mode ----

function setGraphView(mode) {
    graphViewMode = mode;
    applyGraphView();
    document.querySelectorAll('#graph-container .view-btn').forEach(btn => {
        btn.classList.toggle('active', btn.textContent.trim().toLowerCase().replace(' ', '') === mode ||
            (mode === 'full' && btn.textContent.includes('FULL')) ||
            (mode === 'simple' && btn.textContent.includes('SIMPLIFIED')) ||
            (mode === 'scroll' && btn.textContent.includes('SCROLL')));
    });
}

function applyGraphView() {
    const full = document.getElementById('graph-panel-full');
    const simple = document.getElementById('graph-panel-simple');
    const wrapper = document.getElementById('graph-scroll-wrapper');
    if (!full || !simple || !wrapper) return;

    if (graphViewMode === 'simple') {
        full.style.display = 'none';
        simple.style.display = 'block';
        wrapper.style.overflowX = 'hidden';
    } else if (graphViewMode === 'scroll') {
        full.style.display = 'inline-block'; full.style.width = '100%';
        full.style.minWidth = '100%'; full.style.scrollSnapAlign = 'start';
        simple.style.display = 'inline-block'; simple.style.width = '100%';
        simple.style.minWidth = '100%'; simple.style.scrollSnapAlign = 'start';
        wrapper.style.overflowX = 'auto'; wrapper.style.whiteSpace = 'nowrap';
        wrapper.style.scrollSnapType = 'x mandatory';
    } else {
        full.style.display = 'block';
        simple.style.display = 'none';
        wrapper.style.overflowX = 'hidden';
    }
}

// ---- View Toggle (Techniques / Coverage / Detections) ----

async function switchView(view) {
    currentView = view;
    const tv = document.getElementById('techniques-view');
    const cv = document.getElementById('coverage-view');
    const dv = document.getElementById('detections-view');
    const sb = document.getElementById('sidebar-container');

    tv.style.display = view === 'techniques' ? '' : 'none';
    cv.style.display = view === 'coverage' ? 'block' : 'none';
    dv.style.display = view === 'detections' ? 'block' : 'none';
    sb.style.display = view === 'techniques' ? '' : 'none';

    document.querySelectorAll('.navbar-custom .view-btn').forEach(btn => {
        btn.classList.toggle('active', btn.id === 'btn-view-' + view);
    });

    // Lazy-load dashboard fragments
    if (view === 'coverage' && !coverageLoaded) {
        try {
            const res = await fetch('fragments/coverage.html');
            cv.innerHTML = await res.text();
            coverageLoaded = true;
            initTables();
        } catch (e) { cv.innerHTML = '<p style="color:#555;padding:20px">Failed to load coverage data.</p>'; }
    }
    if (view === 'detections' && !detectionsLoaded) {
        try {
            const res = await fetch('fragments/detections.html');
            dv.innerHTML = await res.text();
            detectionsLoaded = true;
            initTables();
        } catch (e) { dv.innerHTML = '<p style="color:#555;padding:20px">Failed to load detections data.</p>'; }
    }
}

// ---- Navigator Layer Download ----

async function downloadLayer(type) {
    try {
        const res = await fetch(`layers/${type}.json`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threatgrapher_${type}_layer.json`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) { console.error('Download failed:', e); }
}

// ---- DataTable: Sort + Paginate ----

function initTables() {
    document.querySelectorAll('.tg-table').forEach(table => {
        if (table.dataset.init) return;
        table.dataset.init = '1';
        const pageSize = parseInt(table.dataset.pageSize) || 20;
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        const rows = Array.from(tbody.querySelectorAll('tr'));
        if (rows.length === 0) return;

        let currentPage = 0;
        const totalPages = Math.ceil(rows.length / pageSize);

        // Pagination container
        const pagDiv = document.createElement('div');
        pagDiv.className = 'tg-pagination';
        table.parentNode.insertBefore(pagDiv, table.nextSibling);

        function showPage(page) {
            currentPage = page;
            rows.forEach((row, i) => {
                row.style.display = (i >= page*pageSize && i < (page+1)*pageSize) ? '' : 'none';
            });
            renderPagination();
        }

        function renderPagination() {
            if (totalPages <= 1) { pagDiv.innerHTML = ''; return; }
            let html = `<span style="color:#555">${currentPage*pageSize+1}-${Math.min((currentPage+1)*pageSize, rows.length)} of ${rows.length}</span>`;
            if (currentPage > 0) html += `<button onclick="this.closest('.tg-pagination').prevFunc()">Prev</button>`;
            if (currentPage < totalPages-1) html += `<button onclick="this.closest('.tg-pagination').nextFunc()">Next</button>`;
            pagDiv.innerHTML = html;
            pagDiv.prevFunc = () => showPage(currentPage-1);
            pagDiv.nextFunc = () => showPage(currentPage+1);
        }

        showPage(0);

        // Sort on header click
        const headers = table.querySelectorAll('th');
        headers.forEach((th, colIdx) => {
            let asc = true;
            th.style.cursor = 'pointer';
            th.innerHTML += ' <span class="sort-arrow">&#9650;</span>';
            th.addEventListener('click', () => {
                rows.sort((a, b) => {
                    const av = a.cells[colIdx]?.textContent || '';
                    const bv = b.cells[colIdx]?.textContent || '';
                    const an = parseFloat(av), bn = parseFloat(bv);
                    if (!isNaN(an) && !isNaN(bn)) return asc ? an-bn : bn-an;
                    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
                });
                asc = !asc;
                rows.forEach(r => tbody.appendChild(r));
                showPage(0);
                headers.forEach(h => h.querySelector('.sort-arrow').textContent = '\u25B2');
                th.querySelector('.sort-arrow').textContent = asc ? '\u25BC' : '\u25B2';
            });
        });
    });
}