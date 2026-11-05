/* ==========================================================================
   SBOM Security Recovery Studio — Front-end Logic (White Theme & Graphs)
   ========================================================================== */

(function () {
  'use strict';

  // State
  let state = {
    mode: 'deterministic', // 'deterministic' or 'single_agent'
    projects: [],
    selectedProject: null,
    selectedScanner: null,
    activeJobId: null,
    pollInterval: null,
    currentRunDetails: null,
    currentFormat: 'cdx'
  };

  // DOM Elements
  const btnModeDeterministic = document.getElementById('btnModeDeterministic');
  const btnModeAI = document.getElementById('btnModeAI');
  const aiSettingsSection = document.getElementById('aiSettingsSection');
  const selectProject = document.getElementById('selectProject');
  const selectScanner = document.getElementById('selectScanner');
  const inputApiKey = document.getElementById('inputApiKey');
  const selectModel = document.getElementById('selectModel');
  const checkStreaming = document.getElementById('checkStreaming');
  const inputCustomSbom = document.getElementById('inputCustomSbom');
  const inputCustomContext = document.getElementById('inputCustomContext');
  const inputCustomTarget = document.getElementById('inputCustomTarget');
  const btnExecuteRecovery = document.getElementById('btnExecuteRecovery');
  const btnRunText = document.getElementById('btnRunText');
  const runsListContainer = document.getElementById('runsListContainer');
  const runCountBadge = document.getElementById('runCountBadge');
  const btnRefreshRuns = document.getElementById('btnRefreshRuns');

  // Status & Metrics
  const jobStatusBadge = document.getElementById('jobStatusBadge');
  const jobStatusTitle = document.getElementById('jobStatusTitle');
  const jobStatusMeta = document.getElementById('jobStatusMeta');
  const jobDurationText = document.getElementById('jobDurationText');
  const statAccepted = document.getElementById('statAccepted');
  const statSupported = document.getElementById('statSupported');
  const statRejected = document.getElementById('statRejected');
  const statValid = document.getElementById('statValid');

  // Delta Highlights
  const badgeAddedEdges = document.getElementById('badgeAddedEdges');
  const badgeRepairedFields = document.getElementById('badgeRepairedFields');
  const badgeAddedNodes = document.getElementById('badgeAddedNodes');
  const deltaChangesListContainer = document.getElementById('deltaChangesListContainer');

  // Graphs
  const initialGraphSub = document.getElementById('initialGraphSub');
  const recoveredGraphSub = document.getElementById('recoveredGraphSub');
  const svgInitialGraph = document.getElementById('svgInitialGraph');
  const svgRecoveredGraph = document.getElementById('svgRecoveredGraph');

  // Tabs & Views
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const terminalLogBox = document.getElementById('terminalLogBox');
  const btnClearLogs = document.getElementById('btnClearLogs');
  const overviewDetailsContainer = document.getElementById('overviewDetailsContainer');
  const recoveredSbomCode = document.getElementById('recoveredSbomCode');
  const btnFormatCdx = document.getElementById('btnFormatCdx');
  const btnFormatSpdx = document.getElementById('btnFormatSpdx');
  const btnCopyRecovered = document.getElementById('btnCopyRecovered');
  const candidatesTableBody = document.getElementById('candidatesTableBody');
  const toolTracesContainer = document.getElementById('toolTracesContainer');
  const conversionAuditCode = document.getElementById('conversionAuditCode');

  // Initialization
  async function init() {
    setupEventListeners();
    await loadProjects();
    await loadRuns();

    // Auto-select first project if available
    if (state.projects.length > 0) {
      const preferred = state.projects.find(p => p.name === 'requests') ||
                        state.projects.find(p => p.name === 'vulture') ||
                        state.projects[0];
      selectProject.value = preferred.name;
      onProjectSelected(preferred.name);
    }
  }

  function setupEventListeners() {
    // Mode Switcher
    btnModeDeterministic.addEventListener('click', () => setMode('deterministic'));
    btnModeAI.addEventListener('click', () => setMode('single_agent'));

    // Project & Scanner selection
    selectProject.addEventListener('change', (e) => onProjectSelected(e.target.value));
    selectScanner.addEventListener('change', (e) => onScannerSelected(e.target.value));

    // Execution
    btnExecuteRecovery.addEventListener('click', handleExecuteRecovery);
    btnRefreshRuns.addEventListener('click', loadRuns);

    // Tab switching
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        switchTab(targetTab);
      });
    });

    // Format toggle
    btnFormatCdx.addEventListener('click', () => setFormat('cdx'));
    btnFormatSpdx.addEventListener('click', () => setFormat('spdx'));

    // Copy Recovered JSON
    btnCopyRecovered.addEventListener('click', () => {
      const text = recoveredSbomCode.textContent;
      navigator.clipboard.writeText(text).then(() => {
        const orig = btnCopyRecovered.textContent;
        btnCopyRecovered.textContent = 'Đã sao chép';
        setTimeout(() => { btnCopyRecovered.textContent = orig; }, 2000);
      });
    });

    btnClearLogs.addEventListener('click', () => {
      terminalLogBox.textContent = '';
    });
  }

  function setMode(mode) {
    state.mode = mode;
    if (mode === 'deterministic') {
      btnModeDeterministic.className = 'mode-btn active-deterministic';
      btnModeDeterministic.setAttribute('aria-selected', 'true');
      btnModeAI.className = 'mode-btn';
      btnModeAI.setAttribute('aria-selected', 'false');

      aiSettingsSection.style.display = 'none';
    } else {
      btnModeDeterministic.className = 'mode-btn';
      btnModeDeterministic.setAttribute('aria-selected', 'false');
      btnModeAI.className = 'mode-btn active-ai';
      btnModeAI.setAttribute('aria-selected', 'true');

      aiSettingsSection.style.display = 'block';
    }
    btnRunText.textContent = 'Run';
  }

  async function loadProjects() {
    try {
      const res = await fetch('/api/projects');
      if (!res.ok) throw new Error('Failed to fetch projects');
      state.projects = await res.json();

      selectProject.innerHTML = '';
      state.projects.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.name;
        opt.textContent = `${p.name} (${p.scanners.length} SBOMs)`;
        selectProject.appendChild(opt);
      });
    } catch (err) {
      selectProject.innerHTML = `<option value="">Lỗi tải dự án: ${err.message}</option>`;
    }
  }

  function onProjectSelected(projectName) {
    const proj = state.projects.find(p => p.name === projectName);
    if (!proj) return;
    state.selectedProject = proj;

    selectScanner.innerHTML = '';
    proj.scanners.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s;
      if (s.includes('trivy.spdx.json') || s.includes('syft.spdx.json')) {
        opt.selected = true;
      }
      selectScanner.appendChild(opt);
    });

    if (proj.scanners.length > 0) {
      onScannerSelected(selectScanner.value);
    }

    inputCustomContext.value = proj.context_path;
    inputCustomTarget.value = proj.target_path;
  }

  function onScannerSelected(scannerName) {
    state.selectedScanner = scannerName;
    if (state.selectedProject) {
      inputCustomSbom.value = `research/.work/m25-cohort-captures-v2/${state.selectedProject.name}/runtime/${scannerName}`;
    }
  }

  async function loadRuns() {
    try {
      const res = await fetch('/api/runs');
      if (!res.ok) return;
      const runs = await res.json();
      runCountBadge.textContent = `${runs.length} lần`;

      if (runs.length === 0) {
        runsListContainer.innerHTML = '<div style="font-size: 0.8rem; color: var(--text-muted); text-align: center; padding: 12px;">Chưa có lịch sử chạy</div>';
        return;
      }

      runsListContainer.innerHTML = '';
      runs.forEach(run => {
        const item = document.createElement('div');
        item.className = 'run-item';
        item.innerHTML = `
          <div>
            <div class="run-item-title">${run.id}</div>
            <div class="run-item-sub">${run.created_at} • <span>${run.policy}</span></div>
          </div>
          <span style="font-size: 0.75rem; color: var(--text-muted);">❯</span>
        `;
        item.addEventListener('click', () => viewRunDetails(run.path));
        runsListContainer.appendChild(item);
      });

      // Auto-view the latest run if current is empty
      if (!state.currentRunDetails && runs.length > 0) {
        viewRunDetails(runs[0].path);
      }
    } catch (err) {
      console.error('Error loading runs:', err);
    }
  }

  async function viewRunDetails(runPath) {
    try {
      const res = await fetch(`/api/run-details?run=${encodeURIComponent(runPath)}`);
      if (!res.ok) throw new Error('Run details not found');
      const details = await res.json();
      state.currentRunDetails = details;
      renderRunDetails(details);
    } catch (err) {
      alert(`Không thể tải chi tiết bản chạy: ${err.message}`);
    }
  }

  function renderRunDetails(details) {
    const res = details.result || {};
    const val = details.cyclonedx_validation || {};
    const candidates = details.candidates || {};

    // Status Banner
    jobStatusBadge.className = 'status-badge status-success';
    jobStatusBadge.textContent = (res.status || 'COMPLETE').toUpperCase();
    jobStatusTitle.textContent = res.status === 'COMPLETE' ? 'Phục hồi SBOM hoàn tất' : (details.run_id || 'Hoàn tất');
    const policyName = (res.policy && res.policy.toLowerCase().includes('agent')) ? 'AI Agent' : 'Tất định';
    jobStatusMeta.textContent = `Chính sách: ${policyName}`;

    const debugOut = document.getElementById('debugOutputDir');
    if (debugOut) debugOut.textContent = details.run_path || '--';

    if (res.duration_seconds) {
      jobDurationText.textContent = `${res.duration_seconds.toFixed(2)}s`;
    } else {
      jobDurationText.textContent = '--';
    }

    // Stats
    const verified = res.verified || {};
    statAccepted.textContent = res.accepted_changes !== undefined ? res.accepted_changes : (verified.accepted ? verified.accepted.length : 0);
    statSupported.textContent = res.supported_changes !== undefined ? res.supported_changes : (candidates.supported ? candidates.supported.length : 0);
    statRejected.textContent = res.rejected_changes !== undefined ? res.rejected_changes : (candidates.rejected ? candidates.rejected.length : 0);
    statValid.textContent = val.valid ? 'HỢP LỆ' : (val.valid === false ? 'LỖI' : 'N/A');

    // Render Graphs & Delta
    renderGraphsAndDelta(details.graph_data);

    // Overview Tab
    renderOverviewTab(details);

    // Recovered Tab
    renderRecoveredTab(details);

    // Candidates Tab
    renderCandidatesTab(details);

    // Traces Tab
    renderTracesTab(details);

    // Audit Tab
    if (details.conversion_audit) {
      conversionAuditCode.textContent = JSON.stringify(details.conversion_audit, null, 2);
    } else {
      conversionAuditCode.textContent = 'Không có dữ liệu conversion audit.';
    }
  }

  function renderGraphsAndDelta(graphData) {
    if (!graphData || graphData.error) {
      deltaChangesListContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">Không thể trích xuất đồ thị cho bản chạy này.</div>';
      return;
    }

    const delta = graphData.delta || {};
    const changes = delta.changes_list || [];

    // Delta Badges
    badgeAddedEdges.textContent = `+${delta.added_edges_count || 0} Cạnh phụ thuộc mới`;
    badgeRepairedFields.textContent = `+${delta.repaired_fields_count || 0} Trường metadata đã sửa`;
    badgeAddedNodes.textContent = `+${delta.added_components_count || 0} Gói mới thêm`;

    // Delta Highlights Table
    if (changes.length === 0) {
      deltaChangesListContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">Không có thay đổi nào được khôi phục.</div>';
    } else {
      let tableHtml = `
        <table class="data-table" style="margin-top: 6px;">
          <thead>
            <tr>
              <th>Loại thay đổi</th>
              <th>Thành phần (Gói)</th>
              <th>Chi tiết khôi phục</th>
              <th>Quyền hạn xác thực</th>
            </tr>
          </thead>
          <tbody>
      `;

      changes.forEach(c => {
        let typeBadge = '';
        let detailText = '';

        if (c.type === 'DEPENDENCY_ADDED') {
          typeBadge = '<span style="color: var(--accent-green); font-weight: 600;">Cạnh phụ thuộc</span>';
          detailText = `Kết nối phụ thuộc: <strong>${c.source_name}</strong> ➔ <strong>${c.target_name}</strong>`;
        } else if (c.type === 'METADATA_REPAIRED') {
          typeBadge = '<span style="color: var(--accent-amber); font-weight: 600;">Sửa Metadata</span>';
          const beforeVal = c.before === null ? 'None' : JSON.stringify(c.before);
          detailText = `Trường <code>${c.field}</code>: <span style="text-decoration: line-through; color: var(--text-muted);">${beforeVal}</span> ➔ <strong style="color: var(--accent-green);">${JSON.stringify(c.after)}</strong>`;
        } else {
          typeBadge = '<span style="color: var(--accent-blue); font-weight: 600;">Gói mới</span>';
          detailText = `Bổ sung gói: <strong>${c.subject_name}</strong>`;
        }

        tableHtml += `
          <tr>
            <td>${typeBadge}</td>
            <td style="font-weight: 600;">${c.subject_name || c.source_name || ''}</td>
            <td>${detailText}</td>
            <td><code style="font-size: 0.75rem;">${c.authority || 'VERIFIED_TARGET'}</code></td>
          </tr>
        `;
      });

      tableHtml += '</tbody></table>';
      deltaChangesListContainer.innerHTML = tableHtml;
    }

    // Render Initial Graph
    const initData = graphData.initial || { nodes: [], edges: [] };
    initialGraphSub.textContent = `${initData.nodes.length} gói • ${initData.edges.length} quan hệ phụ thuộc`;
    renderSvgGraph(svgInitialGraph, initData.nodes, initData.edges, false);

    // Render Recovered Graph
    const recData = graphData.recovered || { nodes: [], edges: [] };
    recoveredGraphSub.textContent = `${recData.nodes.length} gói • ${recData.edges.length} quan hệ phụ thuộc`;
    renderSvgGraph(svgRecoveredGraph, recData.nodes, recData.edges, true);
  }

  function renderSvgGraph(svgElement, nodes, edges, isRecovered) {
    svgElement.innerHTML = '';
    if (!nodes || nodes.length === 0) {
      svgElement.innerHTML = '<text x="20" y="30" fill="#94a3b8" font-size="12">Không có nút trong đồ thị</text>';
      return;
    }

    const NODE_WIDTH = 150;
    const NODE_HEIGHT = 42;
    const HORIZONTAL_GAP = 30;
    const VERTICAL_GAP = 60;

    // Build adjacency and identify roots
    const inDegree = {};
    const outDegree = {};
    const adj = {};
    nodes.forEach(n => {
      inDegree[n.id] = 0;
      outDegree[n.id] = 0;
      adj[n.id] = [];
    });

    edges.forEach(e => {
      if (inDegree[e.target] !== undefined) inDegree[e.target]++;
      if (outDegree[e.source] !== undefined) outDegree[e.source]++;
      if (adj[e.source]) adj[e.source].push(e.target);
    });

    // Connected vs Standalone
    const connectedNodes = nodes.filter(n => inDegree[n.id] > 0 || outDegree[n.id] > 0);
    const standaloneNodes = nodes.filter(n => inDegree[n.id] === 0 && outDegree[n.id] === 0);

    const positions = {};
    let currentY = 24;

    // Layout connected nodes in hierarchical levels
    if (connectedNodes.length > 0) {
      const levels = [];
      const visited = new Set();

      // Find roots
      let roots = connectedNodes.filter(n => inDegree[n.id] === 0);
      if (roots.length === 0) roots = [connectedNodes[0]];

      levels.push(roots);
      roots.forEach(r => visited.add(r.id));

      let currentLevel = roots;
      while (currentLevel.length > 0) {
        const nextLevel = [];
        currentLevel.forEach(node => {
          (adj[node.id] || []).forEach(childId => {
            if (!visited.has(childId)) {
              visited.add(childId);
              const childNode = connectedNodes.find(n => n.id === childId);
              if (childNode) nextLevel.push(childNode);
            }
          });
        });
        if (nextLevel.length > 0) {
          levels.push(nextLevel);
        }
        currentLevel = nextLevel;
      }

      // Add remaining unvisited connected nodes
      const remainingConnected = connectedNodes.filter(n => !visited.has(n.id));
      if (remainingConnected.length > 0) {
        levels.push(remainingConnected);
      }

      // Position each level
      levels.forEach(lvl => {
        const totalW = lvl.length * NODE_WIDTH + (lvl.length - 1) * HORIZONTAL_GAP;
        const startX = 20;
        lvl.forEach((node, idx) => {
          positions[node.id] = {
            x: startX + idx * (NODE_WIDTH + HORIZONTAL_GAP),
            y: currentY
          };
        });
        currentY += NODE_HEIGHT + VERTICAL_GAP;
      });
    }

    // Layout standalone nodes in a compact grid
    if (standaloneNodes.length > 0) {
      const cols = 3;
      standaloneNodes.forEach((node, idx) => {
        const col = idx % cols;
        const row = Math.floor(idx / cols);
        positions[node.id] = {
          x: 20 + col * (NODE_WIDTH + HORIZONTAL_GAP),
          y: currentY + row * (NODE_HEIGHT + 16)
        };
      });
      currentY += Math.ceil(standaloneNodes.length / cols) * (NODE_HEIGHT + 16);
    }

    // Calculate bounding box for SVG
    let maxX = 500;
    Object.values(positions).forEach(p => {
      if (p.x + NODE_WIDTH + 40 > maxX) maxX = p.x + NODE_WIDTH + 40;
    });
    const maxY = Math.max(380, currentY + 30);

    svgElement.setAttribute('viewBox', `0 0 ${maxX} ${maxY}`);
    svgElement.setAttribute('width', maxX);
    svgElement.setAttribute('height', maxY);

    // SVG Defs for Arrowhead markers
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `
      <marker id="arrow-default" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#94a3b8" />
      </marker>
      <marker id="arrow-new" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#059669" />
      </marker>
    `;
    svgElement.appendChild(defs);

    // Draw Edges
    const edgesGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    edges.forEach(e => {
      const srcPos = positions[e.source];
      const dstPos = positions[e.target];
      if (!srcPos || !dstPos) return;

      const x1 = srcPos.x + NODE_WIDTH / 2;
      const y1 = srcPos.y + NODE_HEIGHT;
      const x2 = dstPos.x + NODE_WIDTH / 2;
      const y2 = dstPos.y;

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      const dx = (x2 - x1) * 0.15;
      const dy = (y2 - y1) * 0.5;
      const d = `M ${x1} ${y1} C ${x1 + dx} ${y1 + dy}, ${x2 - dx} ${y2 - dy}, ${x2} ${y2}`;

      path.setAttribute('d', d);
      path.setAttribute('fill', 'none');

      if (e.is_new) {
        path.setAttribute('stroke', '#059669');
        path.setAttribute('stroke-width', '2.5');
        path.setAttribute('marker-end', 'url(#arrow-new)');
      } else {
        path.setAttribute('stroke', '#94a3b8');
        path.setAttribute('stroke-width', '1.5');
        path.setAttribute('marker-end', 'url(#arrow-default)');
      }

      edgesGroup.appendChild(path);
    });
    svgElement.appendChild(edgesGroup);

    // Draw Nodes
    const nodesGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    nodes.forEach(node => {
      const pos = positions[node.id];
      if (!pos) return;

      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);

      const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('width', NODE_WIDTH);
      rect.setAttribute('height', NODE_HEIGHT);
      rect.setAttribute('rx', '6');

      if (node.is_repaired) {
        rect.setAttribute('fill', '#fffbeb');
        rect.setAttribute('stroke', '#d97706');
        rect.setAttribute('stroke-width', '2');
      } else if (node.is_new) {
        rect.setAttribute('fill', '#ecfdf5');
        rect.setAttribute('stroke', '#059669');
        rect.setAttribute('stroke-width', '2');
      } else {
        rect.setAttribute('fill', '#ffffff');
        rect.setAttribute('stroke', '#cbd5e1');
        rect.setAttribute('stroke-width', '1.5');
      }
      g.appendChild(rect);

      // Node Name
      const textName = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      textName.setAttribute('x', '10');
      textName.setAttribute('y', '18');
      textName.setAttribute('font-size', '11');
      textName.setAttribute('font-weight', '600');
      textName.setAttribute('fill', '#0f172a');
      textName.textContent = truncate(node.name, 18);
      g.appendChild(textName);

      // Node Version / Badge
      const textSub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      textSub.setAttribute('x', '10');
      textSub.setAttribute('y', '32');
      textSub.setAttribute('font-size', '9.5');
      textSub.setAttribute('font-family', 'monospace');

      if (node.is_repaired) {
        textSub.setAttribute('fill', '#d97706');
        textSub.textContent = `v${node.version || '?'} [Sửa]`;
      } else if (node.is_new) {
        textSub.setAttribute('fill', '#059669');
        textSub.textContent = `v${node.version || '?'} [Mới]`;
      } else {
        textSub.setAttribute('fill', '#64748b');
        textSub.textContent = node.version ? `v${node.version}` : 'version: ?';
      }
      g.appendChild(textSub);

      nodesGroup.appendChild(g);
    });
    svgElement.appendChild(nodesGroup);
  }

  function truncate(str, maxLen) {
    if (!str) return '';
    return str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : str;
  }

  function renderOverviewTab(details) {
    const res = details.result || {};
    const verified = res.verified || {};
    const val = details.cyclonedx_validation || {};

    let html = `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; margin-bottom: 20px;">
        <div style="background: var(--bg-muted); padding: 14px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Mô hình / Chính sách</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: var(--text-primary); margin-top: 4px;">${res.model || res.policy || 'deterministic'}</div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 4px;">Giao thức: ${res.transport || (res.streaming ? 'SSE Streaming' : 'Standard')}</div>
        </div>
        <div style="background: var(--bg-muted); padding: 14px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">CycloneDX Schema Validation</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${val.valid ? 'var(--accent-green)' : 'var(--accent-red)'}; margin-top: 4px;">
            ${val.valid ? 'Hợp lệ (Schema 1.6)' : 'Không hợp lệ'}
          </div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 4px;">Lỗi cú pháp: ${val.errors ? val.errors.length : 0}</div>
        </div>
        <div style="background: var(--bg-muted); padding: 14px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Số lượt gọi API</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: var(--text-primary); margin-top: 4px;">${res.llm_api_calls || 0} lượt</div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 4px;">Tool invocations: ${res.tool_trace ? res.tool_trace.length : 0}</div>
        </div>
      </div>
    `;

    overviewDetailsContainer.innerHTML = html;
  }

  function renderRecoveredTab(details) {
    if (state.currentFormat === 'cdx' && details.recovered_cdx) {
      recoveredSbomCode.textContent = JSON.stringify(details.recovered_cdx, null, 2);
    } else if (state.currentFormat === 'spdx' && details.recovered_spdx) {
      recoveredSbomCode.textContent = JSON.stringify(details.recovered_spdx, null, 2);
    } else if (details.recovered_cdx) {
      recoveredSbomCode.textContent = JSON.stringify(details.recovered_cdx, null, 2);
    } else {
      recoveredSbomCode.textContent = 'Không có tệp SBOM phục hồi trong bản ghi này.';
    }
  }

  function setFormat(fmt) {
    state.currentFormat = fmt;
    if (fmt === 'cdx') {
      btnFormatCdx.style.background = 'var(--accent-blue-bg)';
      btnFormatCdx.style.color = 'var(--accent-blue)';
      btnFormatSpdx.style.background = '';
      btnFormatSpdx.style.color = '';
    } else {
      btnFormatSpdx.style.background = 'var(--accent-blue-bg)';
      btnFormatSpdx.style.color = 'var(--accent-blue)';
      btnFormatCdx.style.background = '';
      btnFormatCdx.style.color = '';
    }
    if (state.currentRunDetails) {
      renderRecoveredTab(state.currentRunDetails);
    }
  }

  function renderCandidatesTab(details) {
    const cand = details.candidates || {};
    const supported = cand.supported || [];
    const rejected = cand.rejected || [];
    const all = [...supported, ...rejected];

    if (all.length === 0) {
      candidatesTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 14px;">Không có ứng viên nào bị tách ra sidecar.</td></tr>';
      return;
    }

    candidatesTableBody.innerHTML = all.map(item => {
      const p = item.proposal || {};
      const isRejected = item.reason && item.reason.includes('INVALID');
      const statusBadge = isRejected
        ? `<span style="color: var(--accent-red); font-weight: 600;">REJECTED</span>`
        : `<span style="color: var(--accent-amber); font-weight: 600;">${item.status || 'SUPPORTED'}</span>`;

      return `
        <tr>
          <td><code>${p.operation || 'set_field'}</code></td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem;">${p.subject || ''}</td>
          <td>${p.field || '--'}</td>
          <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${JSON.stringify(p.value)}</td>
          <td>${statusBadge}</td>
          <td style="color: var(--text-muted); font-size: 0.78rem;">${item.reason || '--'}</td>
        </tr>
      `;
    }).join('');
  }

  function renderTracesTab(details) {
    const res = details.result || {};
    const trace = res.tool_trace || [];
    const turns = details.turns || [];

    if (trace.length === 0 && turns.length === 0) {
      toolTracesContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 0.85rem;">Không có thông tin lượt gọi công cụ.</p>';
      return;
    }

    let html = '';
    if (trace.length > 0) {
      html += `
        <div style="display: flex; flex-direction: column; gap: 8px;">
          ${trace.map((t, idx) => `
            <div style="background: var(--bg-muted); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <span style="font-weight: 700; font-family: var(--font-mono); color: var(--accent-primary);">
                  Turn #${idx + 1}: ${t.tool || 'action'}
                </span>
                <span style="font-size: 0.75rem; color: var(--text-muted);">
                  ${t.duration_seconds ? t.duration_seconds.toFixed(3) + 's' : ''} • Status: <strong style="color: var(--accent-green);">${t.status || 'OK'}</strong>
                </span>
              </div>
              <div style="font-size: 0.78rem; color: var(--text-secondary);">
                <strong>Tham số:</strong> <code>${JSON.stringify(t.arguments)}</code>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }

    toolTracesContainer.innerHTML = html;
  }

  function switchTab(tabId) {
    tabButtons.forEach(btn => {
      if (btn.getAttribute('data-tab') === tabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    tabPanes.forEach(pane => {
      if (pane.id === tabId) {
        pane.classList.add('active');
      } else {
        pane.classList.remove('active');
      }
    });
  }

  async function handleExecuteRecovery() {
    const inputSbom = inputCustomSbom.value.trim();
    const contextFile = inputCustomContext.value.trim();
    const targetPath = inputCustomTarget.value.trim();

    if (!inputSbom || !contextFile || !targetPath) {
      alert('Vui lòng chọn hoặc điền đầy đủ: Input SBOM, Context Path và Target Venv!');
      return;
    }

    const payload = {
      policy: state.mode,
      input_file: inputSbom,
      context_file: contextFile,
      target_path: targetPath,
      project_name: state.selectedProject ? state.selectedProject.name : 'custom',
      model: selectModel.value,
      streaming: checkStreaming.checked,
      api_key: inputApiKey.value.trim()
    };

    setRunningState(true);
    switchTab('tabConsole');
    terminalLogBox.textContent = `[*] Bắt đầu thực thi (${state.mode})...\n`;

    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) throw new Error('Không thể khởi chạy tác vụ');
      const data = await res.json();
      state.activeJobId = data.job_id;

      startJobPolling(data.job_id);
    } catch (err) {
      setRunningState(false);
      terminalLogBox.textContent += `[-] Lỗi: ${err.message}\n`;
      alert(`Khởi chạy thất bại: ${err.message}`);
    }
  }

  function setRunningState(isRunning) {
    if (isRunning) {
      btnExecuteRecovery.disabled = true;
      btnRunText.innerHTML = '<span class="spinner"></span> Running...';

      jobStatusBadge.className = 'status-badge status-running';
      jobStatusBadge.textContent = 'ĐANG CHẠY';
      jobStatusTitle.textContent = `Đang xử lý ${state.mode}...`;
      jobStatusMeta.textContent = 'Tiến trình đang phân tích và khôi phục SBOM...';
    } else {
      btnExecuteRecovery.disabled = false;
      btnRunText.textContent = 'Run';
    }
  }

  function startJobPolling(jobId) {
    if (state.pollInterval) clearInterval(state.pollInterval);

    state.pollInterval = setInterval(async () => {
      try {
        const res = await fetch(`/api/job-status?job_id=${jobId}`);
        if (!res.ok) return;
        const job = await res.json();

        terminalLogBox.textContent = job.logs;
        terminalLogBox.scrollTop = terminalLogBox.scrollHeight;

        if (job.status === 'SUCCESS' || job.status === 'FAILED' || job.status === 'ERROR') {
          clearInterval(state.pollInterval);
          state.pollInterval = null;
          setRunningState(false);

          if (job.status === 'SUCCESS') {
            jobStatusBadge.className = 'status-badge status-success';
            jobStatusBadge.textContent = 'HOÀN TẤT';
            jobStatusTitle.textContent = 'Phục hồi SBOM thành công';
            const policyLabel = state.mode === 'single_agent' ? 'AI Agent' : 'Tất định';
            jobStatusMeta.textContent = `Chính sách: ${policyLabel}`;
            const debugOut = document.getElementById('debugOutputDir');
            if (debugOut) debugOut.textContent = job.out_dir;
            if (job.duration) {
              jobDurationText.textContent = `${job.duration.toFixed(2)}s`;
            }

            await loadRuns();
            await viewRunDetails(job.out_dir);
            switchTab('tabGraphs');
          } else {
            jobStatusBadge.className = 'status-badge status-error';
            jobStatusBadge.textContent = 'THẤT BẠI';
            jobStatusTitle.textContent = 'Quá trình thực thi gặp lỗi';
            jobStatusMeta.textContent = 'Kiểm tra terminal log để biết thêm chi tiết';
          }
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 800);
  }

  // Start app
  window.addEventListener('DOMContentLoaded', init);
})();
