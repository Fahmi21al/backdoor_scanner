const API_URL = '/api/v1';

// Projects
async function loadProjects() {
    const res = await fetch(`${API_URL}/projects`);
    const projects = await res.json();
    const tbody = document.getElementById('projects-body');
    tbody.innerHTML = '';
    
    if (projects) {
        projects.forEach(p => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${p.id}</td>
                <td style="font-weight: 600;">${p.name}</td>
                <td><span class="badge info">${p.targetType}</span></td>
                <td style="font-size: 0.85rem; color: var(--text-muted);">${p.targetPath}</td>
                <td style="font-size: 0.85rem; color: var(--text-muted);">${p.baselinePath}</td>
                <td>
                    <button onclick="startScan('${p.id}')">Scan</button>
                    <button class="danger" onclick="deleteProject('${p.id}')">Del</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }
}

async function pickPath(inputId, type) {
    try {
        const res = await fetch(`${API_URL}/system/pick-path?type=${type}`);
        if (res.ok) {
            const data = await res.json();
            if (data.path) {
                document.getElementById(inputId).value = data.path;
            }
        }
    } catch (e) {
        console.error("Error picking path", e);
    }
}

async function createProject() {
    const name = document.getElementById('p-name').value;
    const type = document.getElementById('p-type').value;
    const targetPath = document.getElementById('p-path').value;
    const baselinePath = document.getElementById('p-baseline').value;
    const dbDumpPath = document.getElementById('p-db').value;

    if (!name || !targetPath) return alert("Name and Target Path are required");

    const res = await fetch(`${API_URL}/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, targetType: type, targetPath, baselinePath, dbDumpPath })
    });

    if (res.ok) {
        loadProjects();
        document.getElementById('p-name').value = '';
        document.getElementById('p-path').value = '';
        document.getElementById('p-baseline').value = '';
        document.getElementById('p-db').value = '';
    } else {
        alert("Failed to create project");
    }
}

async function deleteProject(id) {
    if (!confirm("Are you sure?")) return;
    const res = await fetch(`${API_URL}/projects/${id}`, { method: 'DELETE' });
    if (res.ok) {
        loadProjects();
        loadBaselines();
    }
}

// Baselines
async function loadBaselines() {
    const res = await fetch(`${API_URL}/baselines`);
    const baselines = await res.json();
    const tbody = document.getElementById('baselines-body');
    tbody.innerHTML = '';
    
    if (baselines) {
        baselines.forEach(b => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${b.id}</td>
                <td>${b.projectId}</td>
                <td><span style="font-weight:600;">${b.name}</span></td>
                <td style="font-size: 0.85rem;">${b.sourcePath}</td>
                <td><span class="badge info">${b.version}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }
}

async function createBaseline() {
    const projectId = document.getElementById('b-project').value;
    const name = document.getElementById('b-name').value;
    const sourcePath = document.getElementById('b-path').value;
    const version = document.getElementById('b-version').value;

    if (!projectId || !name || !sourcePath) return alert("Project ID, Name, and Source Path required");

    const res = await fetch(`${API_URL}/baselines`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, name, sourcePath, version })
    });

    if (res.ok) {
        loadBaselines();
        document.getElementById('b-project').value = '';
        document.getElementById('b-name').value = '';
        document.getElementById('b-path').value = '';
        document.getElementById('b-version').value = '';
    } else {
        const error = await res.json();
        alert("Failed to create baseline: " + error.error);
    }
}

// Global scope for diffing
let scanData = null; 

// Severity mapping utilities
function getMalwareSeverity(matches) {
    const m = matches.join(" ").toLowerCase();
    if (m.includes("entropy") && !m.includes("yara") && !m.includes("eval")) return { lvl: 'Medium', val: 2, cls: 'medium' };
    return { lvl: 'High', val: 3, cls: 'high' }; // YARA, IOCs
}

// Scans
async function startScan(projectId) {
    const modal = document.getElementById('scanModal');
    const statusContainer = document.getElementById('scanStatusContainer');
    const statusText = document.getElementById('scanStatusText');
    const progressBar = document.getElementById('scanProgressBar');
    const progressText = document.getElementById('scanProgressText');
    const resArea = document.getElementById('scanResultsArea');
    const liveConsole = document.getElementById('scanLiveConsole');
    
    modal.style.display = "block";
    statusContainer.classList.remove('hidden');
    resArea.classList.add('hidden');
    liveConsole.classList.remove('hidden');
    
    liveConsole.innerText = "Connecting to scan stream...\n";
    statusText.innerText = "Analyzing file hashes and comparing baselines...";
    progressBar.style.width = "0%";
    progressText.innerText = "0%";
    progressBar.style.backgroundColor = "var(--primary)";

    let evtSource = new EventSource(`${API_URL}/scans/stream?projectId=${projectId}`);

    evtSource.onmessage = function(event) {
        const msg = event.data;

        // Progress bar simulation
        let currWidth = parseInt(progressBar.style.width) || 0;
        if (currWidth < 95) {
            let nW = currWidth + (Math.random() * 2);
            if (nW > 95) nW = 95;
            progressBar.style.width = nW + "%";
            progressText.innerText = Math.floor(nW) + "%";
        }

        if (msg.startsWith("RESULT:")) {
            evtSource.close();
            const dataStr = msg.substring(7);
            let data;
            try { data = JSON.parse(dataStr); } catch (e) {
                statusText.innerText = "Error parsing result JSON";
                progressBar.style.backgroundColor = "var(--danger)";
                return;
            }

            progressBar.style.width = "100%";
            progressText.innerText = "100%";
            
            setTimeout(() => {
                scanData = data;
                statusContainer.classList.add('hidden');
                resArea.classList.remove('hidden');
                
                // Process and Sort Data
                let allFindings = [];

                const dAdded = data.added || [];
                const dDeleted = data.deleted || [];
                const dModified = data.modified || [];
                const dMalware = data.malware || [];
                const dDbUsers = data.dbUsers || [];
                const dDbPayloads = data.dbPayloads || [];

                // 1. Payloads (Critical)
                dDbPayloads.forEach(p => {
                    allFindings.push({ sev: {lvl: 'Critical', val: 4, cls: 'critical'}, cat: 'DB Payload', path: p.table, details: p.matched, raw: p });
                });

                // 2. Malware (High/Medium)
                dMalware.forEach(m => {
                    const sev = getMalwareSeverity(m.matches);
                    allFindings.push({ sev: sev, cat: 'Malware / IOC', path: m.path, details: m.matches.join('<br>'), raw: m });
                });

                // 3. DB Users
                dDbUsers.forEach(u => {
                    if (u.suspicious) {
                        allFindings.push({ sev: {lvl: 'High', val: 3, cls: 'high'}, cat: 'Suspicious Admin', path: u.username, details: u.email, raw: u });
                    }
                });

                // 4. File Changes (Low/Info)
                dModified.forEach((m, idx) => {
                    // Check if this file is also in malware to avoid double listing as 'Low' if we already listed as 'High'
                    const isMalware = dMalware.some(mal => mal.path === m.file.path);
                    if(!isMalware) allFindings.push({ sev: {lvl: 'Low', val: 1, cls: 'low'}, cat: 'Modified File', path: m.file.path, details: 'File content altered', raw: m, diffIdx: idx });
                });
                
                dAdded.forEach(a => {
                    const isMalware = dMalware.some(mal => mal.path === a.path);
                    if(!isMalware) allFindings.push({ sev: {lvl: 'Info', val: 0, cls: 'info'}, cat: 'Added File', path: a.path, details: `${a.size} Bytes`, raw: a });
                });

                // Sort descending
                allFindings.sort((a, b) => b.sev.val - a.sev.val);

                // Stats
                let critHighCount = allFindings.filter(f => f.sev.val >= 3).length;
                let medCount = allFindings.filter(f => f.sev.val === 2).length;
                
                document.getElementById('count-critical-high').innerText = critHighCount;
                document.getElementById('count-medium').innerText = medCount;
                document.getElementById('count-modified').innerText = dModified.length;
                
                let trueAddedCount = data.totalAdded !== undefined ? data.totalAdded : dAdded.length;
                let trueDeletedCount = data.totalDeleted !== undefined ? data.totalDeleted : dDeleted.length;
                document.getElementById('count-added-deleted').innerText = trueAddedCount + trueDeletedCount;

                // Update Risk Banner
                const riskLevelEl = document.getElementById('risk-level');
                const riskScoreEl = document.getElementById('risk-score');
                const riskBanner = document.getElementById('risk-banner');
                
                let riskObj = data.risk || { score: 0, level: 'UNKNOWN' };
                riskLevelEl.innerText = riskObj.level;
                riskScoreEl.innerText = riskObj.score;
                
                // Clear previous classes
                riskBanner.className = '';
                riskBanner.style.backgroundColor = '';
                if (riskObj.level === 'CRITICAL') riskBanner.style.backgroundColor = 'var(--danger)';
                else if (riskObj.level === 'HIGH') riskBanner.style.backgroundColor = '#f97316';
                else if (riskObj.level === 'MEDIUM') riskBanner.style.backgroundColor = '#eab308';
                else if (riskObj.level === 'LOW') riskBanner.style.backgroundColor = '#3b82f6';
                else riskBanner.style.backgroundColor = '#10b981'; // INFO

                // Set Download Links
                window.currentReportHtml = data.htmlReport ? '/' + data.htmlReport.replace(/\\/g, '/') : null;
                window.currentReportJson = data.jsonReport ? '/' + data.jsonReport.replace(/\\/g, '/') : null;

                // Render "All" Tab
                const tbodyAll = document.getElementById('res-all-body');
                if (allFindings.length === 0) {
                    tbodyAll.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 2rem;">No findings to report.</td></tr>`;
                } else {
                    const MAX_ROWS = 500;
                    let html = allFindings.slice(0, MAX_ROWS).map(f => {
                        let actionHtml = '';
                        if (f.cat === 'Modified File') actionHtml = `<button class="outline" onclick="viewDiff(${f.diffIdx})" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;">Diff</button>`;
                        return `
                        <tr>
                            <td><span class="badge ${f.sev.cls}">${f.sev.lvl}</span></td>
                            <td style="font-weight: 500;">${f.cat}</td>
                            <td style="word-break: break-all; font-size: 0.85rem;">
                                ${f.path} ${actionHtml}
                            </td>
                            <td style="font-size: 0.85rem; color: var(--danger);">${f.details}</td>
                        </tr>
                        `;
                    }).join('');

                    if (allFindings.length > MAX_ROWS) {
                        html += `<tr><td colspan="4" style="text-align:center; padding:1rem; color:var(--text-muted); font-style:italic;">Showing top ${MAX_ROWS} of ${allFindings.length} findings to maintain browser performance.</td></tr>`;
                    }
                    tbodyAll.innerHTML = html;
                }

                // Function to safely render massive arrays
                const MAX_ROWS = 500;
                const renderRows = (arr, renderFn, cols = 4) => {
                    let html = arr.slice(0, MAX_ROWS).map(renderFn).join('');
                    if (arr.length > MAX_ROWS) {
                        html += `<tr><td colspan="${cols}" style="text-align:center; padding:1rem; color:var(--text-muted); font-style:italic;">Showing top ${MAX_ROWS} of ${arr.length} findings to maintain browser performance.</td></tr>`;
                    }
                    return html;
                };

                // Render Specific Tabs
                document.getElementById('res-db-payloads-body').innerHTML = renderRows(dDbPayloads, p => {
                    let safeContent = p.content.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    // Highlight dangerous patterns (script, eval, base64, system, etc)
                    safeContent = safeContent.replace(/(system|eval|base64_decode|gzinflate|&lt;script&gt;|&lt;\/script&gt;)/gi, '<span style="background-color: #fef2f2; color: #ef4444; font-weight: bold; padding: 2px 4px; border-radius: 3px;">$1</span>');
                    return `
                    <tr>
                        <td><span class="badge critical">CRITICAL</span></td>
                        <td style="font-weight:bold;">${p.table}</td>
                        <td style="color:var(--danger);">${p.matched}</td>
                        <td style="font-family:monospace; font-size:11px;">${safeContent}</td>
                    </tr>
                    `;
                }, 4);

                document.getElementById('res-malware-body').innerHTML = renderRows(dMalware, m => {
                    const sev = getMalwareSeverity(m.matches);
                    return `
                    <tr>
                        <td><span class="badge ${sev.cls}">${sev.lvl.toUpperCase()}</span></td>
                        <td style="font-weight:500; word-break:break-all;">${m.path}</td>
                        <td style="font-size: 0.85rem; color:var(--danger);">${m.matches.join('<br>')}</td>
                    </tr>
                `}, 3);

                document.getElementById('res-db-body').innerHTML = renderRows(dDbUsers, u => `
                    <tr>
                        <td><span class="badge ${u.suspicious ? 'high' : 'info'}">${u.suspicious ? 'HIGH' : 'INFO'}</span></td>
                        <td style="font-weight:${u.suspicious ? 'bold' : 'normal'};">${u.username}</td>
                        <td>${u.email}</td>
                        <td>${u.suspicious ? '⚠️ Suspicious/Admin' : 'Normal'}</td>
                    </tr>
                `, 4);

                document.getElementById('res-modified-body').innerHTML = renderRows(dModified, (m, idx) => `
                    <tr>
                        <td><span class="badge low">LOW</span></td>
                        <td style="word-break:break-all;">${m.file.path}</td>
                        <td><button class="outline" onclick="viewDiff(${idx})">View Diff</button></td>
                    </tr>
                `, 3);

                document.getElementById('res-added-body').innerHTML = renderRows(dAdded, a => `
                    <tr>
                        <td><span class="badge info">INFO</span></td>
                        <td style="word-break:break-all;">${a.path}</td>
                        <td>${a.size}</td>
                    </tr>
                `, 3);

                document.getElementById('res-deleted-body').innerHTML = renderRows(dDeleted, d => `
                    <tr>
                        <td><span class="badge warning">WARNING</span></td>
                        <td style="word-break:break-all;">${d.path}</td>
                        <td style="font-weight:bold;">Deleted</td>
                    </tr>
                `, 3);

                switchTab('tab-all');
            }, 500);

        } else if (msg.startsWith("[ERROR]")) {
            evtSource.close();
            statusText.innerText = "Error: " + msg;
            progressBar.style.backgroundColor = "var(--danger)";
            appendLog(msg);
        } else {
            appendLog(msg);
        }
    };

    function appendLog(txt) {
        const span = document.createElement('div');
        span.innerText = txt;
        liveConsole.appendChild(span);
        if (liveConsole.childNodes.length > 200) {
            liveConsole.removeChild(liveConsole.firstChild);
        }
        liveConsole.scrollTop = liveConsole.scrollHeight;
    }

    evtSource.onerror = function() {
        evtSource.close();
        if (progressText.innerText !== "100%") {
            statusText.innerText = "Error: Connection lost or stream ended abruptly";
            progressBar.style.backgroundColor = "var(--danger)";
        }
    };
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

    document.getElementById(tabId).classList.remove('hidden');
    document.getElementById('btn-' + tabId).classList.add('active');
}

function viewDiff(idx) {
    if (!scanData || !scanData.modified[idx]) return;
    const m = scanData.modified[idx];
    document.getElementById('diff-file-title').innerText = "Diff: " + m.file.path;
    
    let diffText = m.diff.unifiedDiff || m.diff.error || "No diff generated.";
    
    let lines = diffText.split('\n');
    let coloredDiff = lines.map(line => {
        const safeLine = line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        if (line.startsWith('+')) return `<span style="color: #10b981;">${safeLine}</span>`;
        if (line.startsWith('-')) return `<span style="color: #ef4444;">${safeLine}</span>`;
        if (line.startsWith('@@')) return `<span style="color: #3b82f6; font-weight:bold;">${safeLine}</span>`;
        return safeLine;
    }).join('\n');
    
    document.getElementById('diff-content').innerHTML = coloredDiff;
    document.getElementById('diffModal').style.display = "block";
}

function closeDiffModal() {
    document.getElementById('diffModal').style.display = "none";
}

function closeModal() {
    document.getElementById('scanModal').style.display = "none";
}

// ==========================================
// DAST Scanner (Katana + Nuclei)
// ==========================================
function appendDastLog(msg) {
    const consoleEl = document.getElementById('dast-live-console');
    if (!consoleEl) return;
    const time = new Date().toLocaleTimeString();
    consoleEl.innerText += `[${time}] ${msg}\n`;
    consoleEl.scrollTop = consoleEl.scrollHeight;
}
async function runDastScan() {
    const url = document.getElementById('dast-url').value;
    const depth = document.getElementById('dast-depth').value || 2;
    if (!url) return alert("Target URL is required");

    const statusContainer = document.getElementById('dast-status');
    const statusText = document.getElementById('dast-status-text');
    const resultsCard = document.getElementById('dast-results-card');
    const resultsBody = document.getElementById('dast-results-body');
    const totalBadge = document.getElementById('dast-total-badge');

    statusContainer.classList.remove('hidden');
    resultsCard.classList.add('hidden');
    statusText.innerText = "Phase 1: Crawling endpoints using Katana...";
    
    const consoleEl = document.getElementById('dast-live-console');
    if (consoleEl) consoleEl.innerText = ''; // Clear previous logs
    appendDastLog(`Initializing DAST Scan for target: ${url}`);
    appendDastLog(`Phase 1: Starting Katana discovery with max depth ${depth}...`);

    try {
        const discoverRes = await fetch(`${API_URL}/attack-surface/discover`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, max_depth: parseInt(depth) })
        });
        
        if (!discoverRes.ok) {
            appendDastLog("ERROR: Katana scan failed.");
            throw new Error("Katana scan failed");
        }
        
        appendDastLog("Katana discovery completed successfully.");
        const attackSurface = await discoverRes.json();
        const urlsToScan = attackSurface.CrawledURLs || [];
        
        appendDastLog(`Found ${urlsToScan.length} endpoints to scan.`);
        urlsToScan.forEach(u => appendDastLog(` - ${u}`));
        
        if (urlsToScan.length === 0) {
            statusText.innerText = "Katana finished: No endpoints discovered. Please check the URL.";
            appendDastLog("Aborting Nuclei scan due to 0 endpoints.");
            statusContainer.querySelector('.spinner').style.display = 'none';
            return;
        }

        statusText.innerText = `Phase 2: Scanning ${urlsToScan.length} endpoints using Nuclei Engine...`;
        appendDastLog("Phase 2: Starting Nuclei vulnerability scanner...");
        statusText.innerText = "Phase 2: Scanning vulnerabilities using Nuclei...";

        let allVulns = [];
        const chunkSize = 10;
        
        for (let i = 0; i < urlsToScan.length; i += chunkSize) {
            const chunk = urlsToScan.slice(i, i + chunkSize);
            appendDastLog(`\n[NUCLEI] Scanning chunk ${Math.floor(i/chunkSize)+1} (${chunk.length} URLs)...`);
            chunk.forEach(u => appendDastLog(` -> ${u}`));

            const scanRes = await fetch(`${API_URL}/vulnerability/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls: chunk })
            });

            if (!scanRes.ok) {
                appendDastLog(`ERROR: Nuclei scan failed for chunk ${Math.floor(i/chunkSize)+1}.`);
                continue;
            }

            const vulns = await scanRes.json();
            if (vulns && vulns.length > 0) {
                appendDastLog(` -> Found ${vulns.length} vulnerabilities in this chunk!`);
                allVulns = allVulns.concat(vulns);
            } else {
                appendDastLog(` -> No vulnerabilities found in this chunk.`);
            }
        }

        appendDastLog("\nNuclei scan completed successfully.");
        
        // Display Results
        statusText.innerText = "Scan Completed.";
        const vulnerabilities = allVulns;
        appendDastLog(`Found ${vulnerabilities ? vulnerabilities.length : 0} vulnerabilities.`);

        // Render DAST Results
        statusContainer.classList.add('hidden');
        resultsCard.classList.remove('hidden');
        statusContainer.querySelector('.spinner').style.display = 'block';

        totalBadge.innerText = `${vulnerabilities ? vulnerabilities.length : 0} Findings`;
        resultsBody.innerHTML = '';

        if (vulnerabilities && vulnerabilities.length > 0) {
            vulnerabilities.forEach(v => {
                let badgeClass = 'info';
                let sev = v.severity.toLowerCase();
                if (sev === 'critical') badgeClass = 'critical';
                else if (sev === 'high') badgeClass = 'high';
                else if (sev === 'medium') badgeClass = 'medium';
                else if (sev === 'low') badgeClass = 'low';

                resultsBody.innerHTML += `
                    <tr>
                        <td><span class="badge ${badgeClass}">${v.severity.toUpperCase()}</span></td>
                        <td style="font-weight: 500;">${v.info_name}</td>
                        <td style="color: var(--text-muted); font-size: 0.85rem;">${v.template_id}</td>
                        <td style="word-break: break-all; font-size: 0.85rem; max-width: 300px;">${v.matched}</td>
                    </tr>
                `;
            });
        } else {
            resultsBody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 2rem;">No vulnerabilities found. Target looks clean!</td></tr>`;
        }

    } catch (e) {
        statusText.innerText = "Error: " + e.message;
        appendDastLog(`Process terminated with error: ${e.message}`);
        statusContainer.querySelector('.spinner').style.display = 'none';
    }
}

// ==========================================
// Reporting (Sprint 8)
// ==========================================
function downloadHtmlReport() {
    if (window.currentReportHtml) {
        window.open(window.currentReportHtml, '_blank');
    } else {
        alert("Report not available.");
    }
}

function downloadJsonReport() {
    if (window.currentReportJson) {
        window.open(window.currentReportJson, '_blank');
    } else {
        alert("Report not available.");
    }
}

// Init
window.onload = () => {
    loadProjects();
    loadBaselines();
};
