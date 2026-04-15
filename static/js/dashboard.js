/* ═══════════════════════════════════════════════════════════════
   LOGIX SIEM — Dashboard JavaScript
   Multi-page SPA with hash routing, live data polling,
   incident management, log search, and entity timeline.
   ═══════════════════════════════════════════════════════════════ */

(function () {
    "use strict";

    const API = "/api";
    const POLL = 5000;
    let loginChart = null, procChart = null, sevChart = null;
    let alertOffset = 0, logOffset = 0;
    let currentIncidentId = null;

    // ── Routing ─────────────────────────────────────────────────
    const pages = ["overview", "alerts", "incidents", "logs", "entity"];
    const pageTitles = {
        overview: "Overview",
        alerts: "Alerts",
        incidents: "Incidents",
        logs: "Log Explorer",
        entity: "Entity Investigation",
    };

    function navigate(page) {
        if (!pages.includes(page)) page = "overview";
        pages.forEach(p => {
            document.getElementById("page-" + p).classList.toggle("hidden", p !== page);
        });
        document.querySelectorAll(".nav-item").forEach(el => {
            el.classList.toggle("active", el.dataset.page === page);
        });
        document.getElementById("pageTitle").textContent = pageTitles[page] || page;
        window.location.hash = page;

        // Trigger page-specific loads
        if (page === "alerts") loadAlerts(true);
        if (page === "incidents") { loadIncidents(); loadIncidentSummary(); }
        if (page === "logs") loadLogs(true);
    }

    // Hash routing
    window.addEventListener("hashchange", () => navigate(location.hash.slice(1)));
    document.querySelectorAll(".nav-item[data-page]").forEach(el => {
        el.addEventListener("click", e => {
            e.preventDefault();
            navigate(el.dataset.page);
        });
    });

    // ── Theme Toggle ────────────────────────────────────────────
    const html = document.documentElement;
    document.getElementById("themeToggle").addEventListener("click", () => {
        html.dataset.theme = html.dataset.theme === "dark" ? "light" : "dark";
        localStorage.setItem("logix-theme", html.dataset.theme);
    });
    const saved = localStorage.getItem("logix-theme");
    if (saved) html.dataset.theme = saved;

    // ── Global Search ───────────────────────────────────────────
    document.getElementById("globalSearch").addEventListener("keydown", e => {
        if (e.key === "Enter") {
            const q = e.target.value.trim();
            if (!q) return;
            navigate("logs");
            document.getElementById("logSearchInput").value = q;
            searchLogs(q);
        }
    });

    // ── API Helpers ─────────────────────────────────────────────
    async function get(path) {
        const r = await fetch(API + path);
        return r.json();
    }

    async function post(path, body) {
        const r = await fetch(API + path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        return r.json();
    }

    async function patch(path, body) {
        const r = await fetch(API + path, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        return r.json();
    }

    // ── Utility ─────────────────────────────────────────────────
    function sevBadge(sev) {
        return `<span class="sev sev-${sev}">${sev}</span>`;
    }

    function statusBadge(st) {
        return `<span class="status status-${st}">${st.replace("_"," ")}</span>`;
    }

    function mitreBadge(tech) {
        if (!tech) return "-";
        return `<span class="mitre-tag">${tech}</span>`;
    }

    function srcBadge(src) {
        if (!src) return "";
        return `<span class="src-badge">${src}</span>`;
    }

    function fmtTime(ts) {
        if (!ts) return "-";
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        } catch { return ts; }
    }

    function fmtDateTime(ts) {
        if (!ts) return "-";
        try {
            const d = new Date(ts);
            return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " +
                   d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        } catch { return ts; }
    }

    function truncate(s, len) {
        if (!s) return "";
        return s.length > len ? s.slice(0, len) + "..." : s;
    }

    // ── Overview Page ───────────────────────────────────────────
    async function loadOverview() {
        const data = await get("/stats/system-health");
        document.getElementById("oLogs").textContent = (data.total_logs || 0).toLocaleString();
        document.getElementById("oAlerts").textContent = (data.total_alerts || 0).toLocaleString();
        document.getElementById("oUptime").textContent = data.uptime || "0h 0m";

        // Open incidents count
        const ic = data.incident_counts || {};
        const open = (ic.new || 0) + (ic.in_progress || 0);
        document.getElementById("oIncidents").textContent = open;

        // Incident badge in sidebar
        const badge = document.getElementById("incidentBadge");
        badge.textContent = open;
        badge.style.display = open > 0 ? "inline" : "none";

        // Health grid
        const comps = data.components || {};
        const grid = document.getElementById("healthGrid");
        grid.innerHTML = Object.entries(comps).map(([name, status]) => {
            const dotClass = status === "operational" ? "ok" : status === "disabled" ? "off" : "warn";
            return `<div class="h-item">
                <span class="h-dot ${dotClass}"></span>
                <div><span class="h-label">${name.replace(/_/g, " ")}</span>
                <span class="h-val">${status}</span></div>
            </div>`;
        }).join("");

        // Severity chart
        const counts = data.alert_counts || {};
        updateSevChart(counts);
    }

    async function loadLoginChart() {
        const data = await get("/stats/login-failures?hours=24");
        const items = data.data || [];
        const labels = items.map(d => {
            try { return new Date(d.hour).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
            catch { return d.hour; }
        });
        const values = items.map(d => d.count);

        if (loginChart) loginChart.destroy();
        const ctx = document.getElementById("loginChart");
        if (!ctx) return;
        loginChart = new Chart(ctx, {
            type: "line",
            data: {
                labels,
                datasets: [{
                    label: "Failed Logins",
                    data: values,
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239,68,68,.1)",
                    borderWidth: 1.5,
                    fill: true,
                    tension: .3,
                    pointRadius: 0,
                }],
            },
            options: chartOpts(""),
        });
    }

    async function loadProcChart() {
        const data = await get("/stats/malicious-processes?limit=8");
        const items = data.data || [];
        const labels = items.map(d => d.process_name || "?");
        const values = items.map(d => d.count);

        if (procChart) procChart.destroy();
        const ctx = document.getElementById("procChart");
        if (!ctx) return;
        procChart = new Chart(ctx, {
            type: "bar",
            data: {
                labels,
                datasets: [{
                    label: "Detections",
                    data: values,
                    backgroundColor: "rgba(245,158,11,.6)",
                    borderColor: "#f59e0b",
                    borderWidth: 1,
                }],
            },
            options: chartOpts(""),
        });
    }

    function updateSevChart(counts) {
        const labels = ["critical", "high", "medium", "low"];
        const colors = ["#ef4444", "#f59e0b", "#3b82f6", "#6b7a94"];
        const values = labels.map(l => counts[l] || 0);

        if (sevChart) sevChart.destroy();
        const ctx = document.getElementById("sevChart");
        if (!ctx) return;
        sevChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderColor: "transparent",
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "65%",
                plugins: {
                    legend: { position: "right", labels: { color: "#a4adc0", font: { size: 11 }, boxWidth: 10 } },
                },
            },
        });
    }

    function chartOpts(title) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: "#6b7a94", font: { size: 10 } }, grid: { color: "rgba(100,120,150,.1)" } },
                y: { ticks: { color: "#6b7a94", font: { size: 10 } }, grid: { color: "rgba(100,120,150,.1)" }, beginAtZero: true },
            },
            plugins: {
                legend: { display: false },
                title: { display: !!title, text: title, color: "#a4adc0", font: { size: 12 } },
            },
        };
    }

    // ── MITRE ATT&CK Grid ───────────────────────────────────────
    const MITRE_MAP = {
        "T1110": { tactic: "Credential Access", name: "Brute Force" },
        "T1059": { tactic: "Execution", name: "Command & Scripting" },
        "T1021": { tactic: "Lateral Movement", name: "Remote Services" },
        "T1053": { tactic: "Persistence", name: "Scheduled Task" },
        "T1505": { tactic: "Persistence", name: "Server Software" },
        "T1548": { tactic: "Privilege Escalation", name: "Abuse Elevation" },
        "T1611": { tactic: "Privilege Escalation", name: "Escape to Host" },
        "T1046": { tactic: "Discovery", name: "Network Scanning" },
        "T1048": { tactic: "Exfiltration", name: "Exfiltration Over Alt" },
    };

    async function loadMitreGrid() {
        let alertData;
        try { alertData = await get("/alerts?limit=500"); } catch { return; }
        const alerts = alertData.alerts || [];
        const techCounts = {};
        alerts.forEach(a => {
            const t = a.mitre_technique;
            if (t) techCounts[t] = (techCounts[t] || 0) + 1;
        });

        const grid = document.getElementById("mitreGrid");
        if (!grid) return;
        grid.innerHTML = Object.entries(MITRE_MAP).map(([id, info]) => {
            const count = techCounts[id] || 0;
            const active = count > 0 ? "active" : "";
            return `<div class="mitre-cell ${active}">
                <div class="mitre-tactic">${info.tactic}</div>
                <div class="mitre-tech">${id}</div>
                <div>${info.name}</div>
                ${count > 0 ? `<div class="mitre-count">${count} alerts</div>` : ""}
            </div>`;
        }).join("");
    }

    // ── Alerts Page ─────────────────────────────────────────────
    async function loadAlerts(reset = false) {
        if (reset) alertOffset = 0;
        const sev = document.getElementById("sevFilter").value;
        const q = sev ? `&severity=${sev}` : "";
        const data = await get(`/alerts?limit=50&offset=${alertOffset}${q}`);
        const tbody = document.getElementById("alertBody");
        if (reset) tbody.innerHTML = "";
        (data.alerts || []).forEach(a => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${fmtTime(a.timestamp)}</td>
                <td>${sevBadge(a.severity)}</td>
                <td>${a.alert_type || ""}</td>
                <td><a href="#entity" class="entity-link" data-type="ip" data-value="${a.source_ip || ""}">${a.source_ip || "-"}</a></td>
                <td>${mitreBadge(a.mitre_technique)}</td>
                <td title="${a.description || ""}">${truncate(a.description, 60)}</td>`;
            tbody.appendChild(tr);
        });
        alertOffset += (data.alerts || []).length;
        bindEntityLinks();
    }

    document.getElementById("sevFilter").addEventListener("change", () => loadAlerts(true));
    document.getElementById("alertLoadMore").addEventListener("click", () => loadAlerts(false));

    // ── Incidents Page ──────────────────────────────────────────
    async function loadIncidentSummary() {
        const data = await get("/incidents/summary");
        const c = data.counts || {};
        document.getElementById("iNew").textContent = c.new || 0;
        document.getElementById("iProgress").textContent = c.in_progress || 0;
        document.getElementById("iResolved").textContent = c.resolved || 0;
        document.getElementById("iClosed").textContent = c.closed || 0;
    }

    async function loadIncidents() {
        const status = document.getElementById("incStatusFilter").value;
        const q = status ? `?status=${status}` : "";
        const data = await get(`/incidents${q}`);
        const tbody = document.getElementById("incidentBody");
        tbody.innerHTML = "";
        (data.incidents || []).forEach(inc => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>#${inc.id}</td>
                <td>${sevBadge(inc.severity)}</td>
                <td>${truncate(inc.title, 40)}</td>
                <td><a href="#entity" class="entity-link" data-type="${inc.entity_type}" data-value="${inc.entity_value || ""}">${inc.entity_value || "-"}</a></td>
                <td>${inc.alert_count || 0}</td>
                <td>${statusBadge(inc.status)}</td>
                <td>${fmtDateTime(inc.last_seen)}</td>
                <td><button class="btn-action view-incident" data-id="${inc.id}">View</button></td>`;
            tbody.appendChild(tr);
        });
        bindEntityLinks();
        document.querySelectorAll(".view-incident").forEach(btn => {
            btn.addEventListener("click", () => openIncident(parseInt(btn.dataset.id)));
        });
    }

    async function openIncident(id) {
        currentIncidentId = id;
        const data = await get(`/incidents/${id}`);
        const inc = data.incident;
        if (!inc) return;

        document.getElementById("incidentDetail").classList.remove("hidden");
        document.getElementById("incDetailTitle").textContent = `Incident #${inc.id}: ${inc.title}`;
        document.getElementById("incDetailMeta").innerHTML = `
            <div class="meta-item"><span class="meta-label">Severity</span><span class="meta-val">${sevBadge(inc.severity)}</span></div>
            <div class="meta-item"><span class="meta-label">Status</span><span class="meta-val">${statusBadge(inc.status)}</span></div>
            <div class="meta-item"><span class="meta-label">Entity</span><span class="meta-val">${inc.entity_value || "-"}</span></div>
            <div class="meta-item"><span class="meta-label">Alerts</span><span class="meta-val">${inc.alert_count}</span></div>`;
        document.getElementById("incDetailNotes").textContent = inc.notes || "No notes yet.";

        const atbody = document.getElementById("incAlertBody");
        atbody.innerHTML = "";
        (data.alerts || []).forEach(a => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${fmtTime(a.timestamp)}</td>
                <td>${sevBadge(a.severity)}</td>
                <td>${a.alert_type || ""}</td>
                <td title="${a.description || ""}">${truncate(a.description, 50)}</td>`;
            atbody.appendChild(tr);
        });
    }

    document.getElementById("closeIncDetail").addEventListener("click", () => {
        document.getElementById("incidentDetail").classList.add("hidden");
        currentIncidentId = null;
    });

    document.getElementById("incUpdateBtn").addEventListener("click", async () => {
        if (!currentIncidentId) return;
        const status = document.getElementById("incStatusChange").value;
        const notes = document.getElementById("incNote").value.trim();
        if (!status && !notes) return;
        const body = {};
        if (status) body.status = status;
        if (notes) body.notes = notes;
        await patch(`/incidents/${currentIncidentId}`, body);
        document.getElementById("incNote").value = "";
        document.getElementById("incStatusChange").value = "";
        openIncident(currentIncidentId);
        loadIncidents();
        loadIncidentSummary();
    });

    document.getElementById("incStatusFilter").addEventListener("change", loadIncidents);

    // ── Log Explorer ────────────────────────────────────────────
    async function loadLogs(reset = false) {
        if (reset) logOffset = 0;
        const type = document.getElementById("logTypeFilter").value;
        const q = type ? `&event_type=${type}` : "";
        const data = await get(`/logs/recent?limit=100&offset=${logOffset}${q}`);
        const tbody = document.getElementById("logBody");
        if (reset) tbody.innerHTML = "";
        (data.logs || []).forEach(l => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${fmtTime(l.timestamp)}</td>
                <td>${srcBadge(l.log_source)}</td>
                <td>${l.event_type || ""}</td>
                <td><a href="#entity" class="entity-link" data-type="ip" data-value="${l.source_ip || ""}">${l.source_ip || "-"}</a></td>
                <td><a href="#entity" class="entity-link" data-type="user" data-value="${l.username || ""}">${l.username || "-"}</a></td>
                <td title="${l.message || ""}">${truncate(l.message, 70)}</td>`;
            tbody.appendChild(tr);
        });
        logOffset += (data.logs || []).length;
        document.getElementById("logCount").textContent = `${logOffset} logs loaded`;
        bindEntityLinks();
    }

    async function searchLogs(query) {
        const data = await get(`/logs/search?q=${encodeURIComponent(query)}&limit=100`);
        const tbody = document.getElementById("logBody");
        tbody.innerHTML = "";
        (data.results || []).forEach(l => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${fmtTime(l.timestamp)}</td>
                <td>${srcBadge(l.log_source)}</td>
                <td>${l.event_type || ""}</td>
                <td>${l.source_ip || "-"}</td>
                <td>${l.username || "-"}</td>
                <td title="${l.message || ""}">${truncate(l.message, 70)}</td>`;
            tbody.appendChild(tr);
        });
        document.getElementById("logCount").textContent = `${data.count || 0} results for "${query}"`;
    }

    document.getElementById("logSearchInput").addEventListener("keydown", e => {
        if (e.key === "Enter") {
            const q = e.target.value.trim();
            if (q) searchLogs(q);
            else loadLogs(true);
        }
    });
    document.getElementById("logTypeFilter").addEventListener("change", () => loadLogs(true));
    document.getElementById("logLoadMore").addEventListener("click", () => loadLogs(false));

    // ── Entity Timeline ─────────────────────────────────────────
    async function loadEntity(type, value) {
        if (!value) return;
        document.getElementById("entityType").value = type;
        document.getElementById("entityValue").value = value;

        const data = await get(`/entity/${type}/${encodeURIComponent(value)}/timeline?limit=200`);
        document.getElementById("entityResults").classList.remove("hidden");
        document.getElementById("entityLabel").textContent = `${type}: ${value}`;
        document.getElementById("eLogs").textContent = (data.logs || []).length;
        document.getElementById("eAlerts").textContent = (data.alerts || []).length;
        document.getElementById("eIncidents").textContent = (data.incidents || []).length;

        // Build timeline (merge and sort logs + alerts)
        const items = [];
        (data.logs || []).forEach(l => items.push({ time: l.timestamp, type: "log", data: l }));
        (data.alerts || []).forEach(a => items.push({ time: a.timestamp, type: "alert", data: a }));
        items.sort((a, b) => (b.time || "").localeCompare(a.time || ""));

        const tl = document.getElementById("entityTimeline");
        tl.innerHTML = items.slice(0, 100).map(item => {
            if (item.type === "alert") {
                return `<div class="tl-item tl-alert">
                    <span class="tl-time">${fmtDateTime(item.time)}</span>
                    <div class="tl-content">
                        <div class="tl-type">${sevBadge(item.data.severity)} ${item.data.alert_type || "Alert"} ${mitreBadge(item.data.mitre_technique)}</div>
                        <div>${item.data.description || ""}</div>
                    </div>
                </div>`;
            }
            return `<div class="tl-item">
                <span class="tl-time">${fmtDateTime(item.time)}</span>
                <div class="tl-content">
                    <div class="tl-type">${item.data.event_type || "event"}</div>
                    <div>${truncate(item.data.message, 80)}</div>
                </div>
            </div>`;
        }).join("");
    }

    document.getElementById("entityLookup").addEventListener("click", () => {
        const type = document.getElementById("entityType").value;
        const val = document.getElementById("entityValue").value.trim();
        if (val) loadEntity(type, val);
    });

    document.getElementById("entityValue").addEventListener("keydown", e => {
        if (e.key === "Enter") {
            const type = document.getElementById("entityType").value;
            const val = e.target.value.trim();
            if (val) loadEntity(type, val);
        }
    });

    // Entity links throughout the app
    function bindEntityLinks() {
        document.querySelectorAll(".entity-link").forEach(el => {
            el.addEventListener("click", e => {
                e.preventDefault();
                const type = el.dataset.type;
                const val = el.dataset.value;
                if (val && val !== "-" && val !== "None" && val !== "unknown") {
                    navigate("entity");
                    loadEntity(type, val);
                }
            });
        });
    }

    // ── Polling Loop ────────────────────────────────────────────
    async function poll() {
        try {
            await loadOverview();
            await loadLoginChart();
            await loadProcChart();
            await loadMitreGrid();
        } catch (e) {
            console.error("Poll error:", e);
        }
    }

    // ── Init ────────────────────────────────────────────────────
    const startPage = location.hash.slice(1) || "overview";
    navigate(startPage);
    poll();
    setInterval(poll, POLL);

})();
