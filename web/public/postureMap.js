'use strict';

/* ── Posture map: interactive entity graph + attack paths ──────────────── */

// Shared globals from app.js (do not redeclare):
//   currentAssessment, escHtml, $, SEVERITY_ORDER, navigateTo
//   TOPBAR_TITLES  (topbar entry handled in app.js)
//   showToast      (toast helper)

const PM = (() => {
  // ── Constants ────────────────────────────────────────────────────────────
  const COL_W = 240;        // horizontal distance between depth columns
  const ROW_H = 96;         // vertical distance between leaf slots
  const PAD_X = 40;         // left/top padding around the graph
  const NODE_W = 220;
  const NODE_H = 64;
  const SEV = ['critical', 'high', 'medium', 'low', 'informational'];

  // category → {label, iconKey, role}
  const CATEGORY_MAP = {
    // transport
    dns:             { label: 'DNS',              icon: 'dns',         role: 'transport' },
    ssl:             { label: 'SSL / TLS',        icon: 'ssl',         role: 'transport' },
    mtls:            { label: 'mTLS',             icon: 'ssl',         role: 'transport' },
    securitytxt:     { label: 'security.txt',     icon: 'shield',      role: 'transport' },
    'security-txt':  { label: 'security.txt',     icon: 'shield',      role: 'transport' },
    ch:              { label: 'Custom hostnames', icon: 'globe',       role: 'transport' },
    insight:         { label: 'Security insights',icon: 'eye',         role: 'transport' },
    securityInsights:{ label: 'Security insights',icon: 'eye',         role: 'transport' },
    // controls
    waf:             { label: 'WAF',              icon: 'shield',      role: 'control' },
    bot:             { label: 'Bot management',   icon: 'bot',         role: 'control' },
    api:             { label: 'API Shield',       icon: 'api',         role: 'control' },
    'page-shield':   { label: 'Page Shield',      icon: 'shield',      role: 'control' },
    cache:           { label: 'Cache',            icon: 'cache',       role: 'control' },
    rules:           { label: 'Rules',            icon: 'rules',       role: 'control' },
    cfrule:          { label: 'Rules',            icon: 'rules',       role: 'control' },
    txrule:          { label: 'Transform rules',  icon: 'rules',       role: 'control' },
    turnstile:       { label: 'Turnstile',        icon: 'turnstile',   role: 'control' },
    performance:     { label: 'Performance',      icon: 'speed',       role: 'control' },
    // assets
    workers:         { label: 'Workers',          icon: 'code',        role: 'asset' },
    pages:           { label: 'Pages',            icon: 'pages',       role: 'asset' },
    r2:              { label: 'R2',               icon: 'database',    role: 'asset' },
    tunnels:         { label: 'Tunnels',          icon: 'plug',        role: 'asset' },
    gateway:         { label: 'Gateway',          icon: 'filter',      role: 'asset' },
    dlp:             { label: 'DLP',              icon: 'eye-off',     role: 'asset' },
    zerotrust:       { label: 'Zero Trust',       icon: 'fingerprint', role: 'asset' },
    spectrum:        { label: 'Spectrum',         icon: 'spectrum',    role: 'asset' },
    'ai-gateway':    { label: 'AI Gateway',       icon: 'sparkles',    role: 'asset' },
    snippets:        { label: 'Snippets',         icon: 'code',        role: 'asset' },
    lb:              { label: 'Load balancer',    icon: 'lb',          role: 'asset' },
    email:           { label: 'Email routing',    icon: 'mail',        role: 'asset' },
    // identity
    token:           { label: 'Tokens',           icon: 'key',         role: 'identity' },
    'attack-surface':{ label: 'Attack surface',   icon: 'radar',       role: 'identity' },
    device:          { label: 'Devices',          icon: 'device',      role: 'identity' },
    account:         { label: 'Account',          icon: 'building',    role: 'identity' },
  };

  // 24x24 path data (stroke="currentColor" style applied at use site)
  const ICONS = {
    globe:        '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    building:     '<rect x="4" y="3" width="16" height="18" rx="1"/><line x1="9" y1="7" x2="9" y2="7"/><line x1="15" y1="7" x2="15" y2="7"/><line x1="9" y1="11" x2="9" y2="11"/><line x1="15" y1="11" x2="15" y2="11"/><line x1="9" y1="15" x2="9" y2="15"/><line x1="15" y1="15" x2="15" y2="15"/><line x1="10" y1="21" x2="10" y2="18"/><line x1="14" y1="21" x2="14" y2="18"/>',
    shield:       '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    lock:         '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    server:       '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><line x1="7" y1="7" x2="7" y2="7"/><line x1="7" y1="17" x2="7" y2="17"/>',
    bot:          '<rect x="3" y="8" width="18" height="12" rx="2"/><line x1="12" y1="3" x2="12" y2="8"/><circle cx="9" cy="14" r="1"/><circle cx="15" cy="14" r="1"/><line x1="8" y1="6" x2="16" y2="6"/>',
    code:         '<polyline points="8 6 2 12 8 18"/><polyline points="16 6 22 12 16 18"/><line x1="14" y1="4" x2="10" y2="20"/>',
    database:     '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
    mail:         '<rect x="3" y="5" width="18" height="14" rx="2"/><polyline points="3 7 12 13 21 7"/>',
    fingerprint:  '<path d="M5 12a7 7 0 0 1 14 0v2a3 3 0 0 1-3 3 2 2 0 0 1-2-2v-3"/><path d="M9 19a3 3 0 0 1-3-3v-2"/><path d="M12 5v2"/><path d="M16 9v2"/>',
    plug:         '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-6 6 6 6 0 0 1-6-6V8z"/><path d="M12 17v5"/>',
    'eye-off':    '<path d="M3 3l18 18M10.6 6.1A10 10 0 0 1 12 6c5 0 9 4 10 6-0.4 0.8-1.6 2.6-3.6 4.2M6.6 6.6C4 8.2 2.4 10.6 2 12c1 2 5 6 10 6 1.5 0 2.9-.4 4.1-1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    filter:       '<polygon points="3 4 21 4 14 12 14 19 10 21 10 12 3 4"/>',
    generic:      '<circle cx="12" cy="12" r="2"/>',
    eye:          '<path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>',
    api:          '<path d="M4 12a8 8 0 0 1 8-8M4 12a8 8 0 0 0 8 8M20 12a8 8 0 0 0-8-8M20 12a8 8 0 0 1-8 8"/>',
    cache:        '<path d="M3 3h18l-2 8H5L3 3z"/><path d="M5 11l-1 10h16l-1-10"/><line x1="9" y1="14" x2="9" y2="18"/><line x1="15" y1="14" x2="15" y2="18"/>',
    rules:        '<line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="14" y2="18"/><polyline points="16 16 20 18 16 20"/>',
    turnstile:    '<path d="M4 4v6a4 4 0 0 0 4 4h8a4 4 0 0 1 4 4v2"/><circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/>',
    speed:        '<path d="M12 2a10 10 0 1 0 10 10"/><polyline points="12 6 12 12 16 14"/>',
    pages:        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
    spectrum:     '<path d="M2 12a10 10 0 0 1 20 0"/><path d="M6 12a6 6 0 0 1 12 0"/><path d="M10 12a2 2 0 0 1 4 0"/>',
    sparkles:     '<path d="M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6L12 3z"/><path d="M19 14l.8 2.2L22 17l-2.2.8L19 20l-.8-2.2L16 17l2.2-.8L19 14z"/>',
    lb:           '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><line x1="8" y1="7" x2="8" y2="7"/><line x1="8" y1="17" x2="8" y2="17"/><path d="M12 10v4"/>',
    key:          '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9"/><path d="M16 7l3 3"/>',
    radar:        '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/><line x1="12" y1="12" x2="20" y2="6"/>',
    device:       '<rect x="6" y="3" width="12" height="18" rx="2"/><line x1="12" y1="18" x2="12" y2="18"/>',
    'shield-check':'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
  };

  const iconSvg = (key, size = 18) => {
    const path = ICONS[key] || ICONS.generic;
    return `<svg class="pm-node-icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
  };

  // ── Module state ────────────────────────────────────────────────────────
  let svg, viewport, edgesG, nodesG, drawer, drawerBody, drawerTitle, drawerIcon,
      drawerSub, drawerClose, drawerBackdrop, emptyEl, stats, pathsToggle, stage;
  let currentView = null;     // { nodes, edges, bounds, attackNodes, attackEdges, dangerLeaves }
  let camera = { scale: 1, tx: 0, ty: 0 };
  let bound = false;

  // ── Build the graph from currentAssessment ──────────────────────────────
  function buildGraph(assessment) {
    const zones = Array.isArray(assessment.zones) ? assessment.zones : [];
    const findings = Array.isArray(assessment.findings) ? assessment.findings : [];
    const account = assessment.account || { id: 'account', name: 'Account' };

    // Index zones by id and by name (lowercased)
    const zonesById = new Map(zones.map(z => [z.id, z]));
    const zonesByName = new Map(zones.map(z => [(z.name || '').toLowerCase(), z]));

    // Group findings by (resourceType, resourceId, category)
    // For zone findings, we may only have resourceName in some payloads — resolve to id.
    const buckets = new Map();   // key -> { parentKey, category, findings[] }
    const getBucket = (parentKey, category) => {
      const key = `${parentKey}::${category}`;
      if (!buckets.has(key)) buckets.set(key, { parentKey, category, findings: [] });
      return buckets.get(key);
    };

    // Always include internet + account nodes even with no findings
    for (const f of findings) {
      let parentKey;
      if (f.resourceType === 'account' || !f.resourceId) {
        parentKey = `account::${account.id}`;
      } else if (f.resourceType === 'zone' || zonesById.has(f.resourceId) || zonesByName.has(String(f.resourceId || '').toLowerCase())) {
        // Try to resolve a zone id
        let zoneId = f.resourceId;
        if (!zonesById.has(zoneId) && f.resourceName) {
          const z = zonesByName.get(String(f.resourceName).toLowerCase());
          if (z) zoneId = z.id;
        }
        if (zonesById.has(zoneId)) {
          parentKey = `zone::${zoneId}`;
        } else {
          // orphan zone reference — still create a synthetic node
          parentKey = `zone::${f.resourceId}`;
        }
      } else {
        parentKey = `account::${account.id}`;
      }
      const cat = (f.service || f.category || 'general').toString().toLowerCase();
      getBucket(parentKey, cat).findings.push(f);
    }

    // Construct nodes
    const nodes = new Map();

    // Internet (root)
    nodes.set('internet::0', {
      id: 'internet::0', type: 'internet', label: 'Internet', sub: 'External requests',
      depth: 0, parentId: null, children: [], findings: [],
    });

    // Account
    const accountId = `account::${account.id}`;
    nodes.set(accountId, {
      id: accountId, type: 'account', label: account.name || 'Account',
      sub: account.id ? `id · ${account.id.slice(0, 8)}` : '',
      depth: 1, parentId: 'internet::0', children: [], findings: [],
    });

    // Zones
    const zoneNodeIds = [];
    for (const z of zones) {
      const id = `zone::${z.id}`;
      nodes.set(id, {
        id, type: 'zone', label: z.name, sub: z.plan ? `plan · ${z.plan}` : '',
        depth: 2, parentId: accountId, children: [], findings: [],
      });
      zoneNodeIds.push(id);
    }
    // Account-level service buckets
    const accountBuckets = [];
    // Service buckets keyed per zone
    const zoneBuckets = new Map();

    for (const [key, bucket] of buckets.entries()) {
      const meta = CATEGORY_MAP[bucket.category] || {
        label: bucket.category.replace(/(^|[-_])(\w)/g, (_, __, c) => ' ' + c.toUpperCase()).trim(),
        icon: 'generic', role: 'asset',
      };
      const node = {
        id: key,
        type: 'service',
        category: bucket.category,
        label: meta.label,
        sub: `${bucket.findings.length} finding${bucket.findings.length === 1 ? '' : 's'}`,
        icon: meta.icon,
        role: meta.role,
        depth: bucket.parentKey.startsWith('zone::') ? 3 : 2,
        parentId: bucket.parentKey,
        children: [],
        findings: bucket.findings,
      };
      // Compute severity (worst FAIL; otherwise pass if any findings; else skip node)
      node.severity = computeNodeSeverity(bucket.findings);
      if (!node.severity) continue; // skip empty buckets (no findings at all)
      nodes.set(key, node);
      if (bucket.parentKey.startsWith('zone::')) {
        if (!zoneBuckets.has(bucket.parentKey)) zoneBuckets.set(bucket.parentKey, []);
        zoneBuckets.get(bucket.parentKey).push(node);
      } else {
        accountBuckets.push(node);
      }
    }

    // Wire parent→child links
    for (const node of nodes.values()) {
      if (node.parentId) {
        const parent = nodes.get(node.parentId);
        if (parent) parent.children.push(node);
      }
    }

    // Deterministic sort: by severity asc (worst first) → label
    const sortChildren = (n) => {
      n.children.sort((a, b) => {
        const sa = SEVERITY_ORDER[a.severity] ?? 9;
        const sb = SEVERITY_ORDER[b.severity] ?? 9;
        if (sa !== sb) return sa - sb;
        return (a.label || '').localeCompare(b.label || '');
      });
      n.children.forEach(sortChildren);
    };
    sortChildren(nodes.get('internet::0'));

    // Build edges
    const edges = [];
    for (const node of nodes.values()) {
      if (node.parentId) edges.push({ from: node.parentId, to: node.id, node });
    }

    // Attack paths: nodes with severity critical/high (and any ancestors + edges)
    const dangerLeaves = [...nodes.values()].filter(n => n.severity === 'critical' || n.severity === 'high');
    const attackNodes = new Set();
    const attackEdges = new Set();
    for (const leaf of dangerLeaves) {
      let cur = leaf;
      while (cur) {
        attackNodes.add(cur.id);
        if (cur.parentId) {
          attackEdges.add(`${cur.parentId}->${cur.id}`);
          cur = nodes.get(cur.parentId);
        } else break;
      }
    }

    return { nodes, edges, attackNodes, attackEdges, dangerLeaves };
  }

  function computeNodeSeverity(findings) {
    if (!findings || findings.length === 0) return null;
    let worst = null;
    for (const f of findings) {
      if (f.status === 'PASS') continue;
      const sev = f.severity || 'low';
      if (worst == null || (SEVERITY_ORDER[sev] ?? 9) < (SEVERITY_ORDER[worst] ?? 9)) worst = sev;
    }
    return worst || 'pass';
  }

  // ── Layout: tidy left→right tree ────────────────────────────────────────
  function layout(graph) {
    const nodeW = NODE_W, nodeH = NODE_H;
    const leafIndex = { value: 0 };
    const positions = new Map();   // id -> {x, y, w, h}

    function assign(node) {
      if (!node.children || node.children.length === 0) {
        const y = leafIndex.value * ROW_H;
        leafIndex.value++;
        positions.set(node.id, { x: 0, y, w: nodeW, h: nodeH });
        return y + nodeH / 2;
      }
      const childCenters = node.children.map(assign);
      const cy = (childCenters[0] + childCenters[childCenters.length - 1]) / 2;
      positions.set(node.id, { x: 0, y: cy - nodeH / 2, w: nodeW, h: nodeH });
      return cy;
    }

    const root = [...graph.nodes.values()].find(n => n.type === 'internet');
    if (!root) return null;
    assign(root);

    // Assign x by depth, shift y by minimum so it starts at 0, and pad
    let minY = Infinity, maxY = -Infinity, maxX = -Infinity;
    for (const n of graph.nodes.values()) {
      const p = positions.get(n.id);
      p.x = PAD_X + n.depth * COL_W;
      p.y = p.y; // will be shifted below
      if (p.y < minY) minY = p.y;
      if (p.y + p.h > maxY) maxY = p.y + p.h;
      if (p.x + p.w > maxX) maxX = p.x + p.w;
    }
    const yShift = PAD_X - minY;
    for (const p of positions.values()) p.y += yShift;
    maxY += yShift;

    // Compute bounds
    const bounds = { x: 0, y: 0, w: maxX + PAD_X, h: maxY + PAD_X };

    return { positions, bounds };
  }

  // ── Render ──────────────────────────────────────────────────────────────
  function render() {
    const page = document.getElementById('page-posture');
    if (!page) return;

    // Build / fetch DOM on first call (idempotent on subsequent calls)
    if (!svg) {
      page.classList.add('pm-page-body');
      // Toolbar
      const toolbar = page.querySelector('.pm-toolbar') || createToolbar();
      // Stage
      stage = page.querySelector('.pm-stage') || createStage();
      // Drawer + backdrop
      createDrawer();
    }

    const assessment = (typeof currentAssessment !== 'undefined') ? currentAssessment : null;
    const findings = assessment?.findings || [];
    if (!assessment || findings.length === 0) {
      showEmpty(true);
      updateStats(null);
      return;
    }
    showEmpty(false);

    const graph = buildGraph(assessment);
    const lay = layout(graph);
    if (!lay) { showEmpty(true); return; }
    currentView = { graph, layout: lay, camera: { ...camera } };
    paintGraph(currentView);
    updateStats(graph);
    fit();
  }

  function createToolbar() {
    const page = document.getElementById('page-posture');
    const head = page.querySelector('.v1-page-head');
    const toolbar = document.createElement('div');
    toolbar.className = 'pm-toolbar';
    toolbar.innerHTML = `
      <div class="pm-toolbar-section pm-stats" id="pm-stats"></div>
      <div class="pm-toolbar-section pm-legend">
        <span class="pm-legend-item"><span class="pm-legend-swatch" style="background:var(--crit)"></span>Critical</span>
        <span class="pm-legend-item"><span class="pm-legend-swatch" style="background:var(--high)"></span>High</span>
        <span class="pm-legend-item"><span class="pm-legend-swatch" style="background:var(--med)"></span>Medium</span>
        <span class="pm-legend-item"><span class="pm-legend-swatch" style="background:var(--low)"></span>Low</span>
        <span class="pm-legend-item"><span class="pm-legend-line"></span>Attack path</span>
      </div>
      <div class="pm-toolbar-section">
        <label class="pm-toggle" title="Highlight chains to high/critical nodes">
          <input type="checkbox" id="pm-paths-toggle" checked /> Attack paths
        </label>
        <button class="v1-btn v1-btn-ghost v1-btn-sm" type="button" id="pm-zoom-out" aria-label="Zoom out">−</button>
        <button class="v1-btn v1-btn-ghost v1-btn-sm" type="button" id="pm-zoom-in" aria-label="Zoom in">+</button>
        <button class="v1-btn v1-btn-ghost v1-btn-sm" type="button" id="pm-fit" type="button">Fit</button>
      </div>
    `;
    head.insertAdjacentElement('afterend', toolbar);
    stats = toolbar.querySelector('#pm-stats');
    pathsToggle = toolbar.querySelector('#pm-paths-toggle');
    toolbar.querySelector('#pm-zoom-in').addEventListener('click', () => zoom(1.25));
    toolbar.querySelector('#pm-zoom-out').addEventListener('click', () => zoom(0.8));
    toolbar.querySelector('#pm-fit').addEventListener('click', fit);
    pathsToggle.addEventListener('change', () => {
      svg.classList.toggle('show-paths', pathsToggle.checked);
    });
    return toolbar;
  }

  function createStage() {
    const page = document.getElementById('page-posture');
    const stage = document.createElement('div');
    stage.className = 'pm-stage';
    stage.innerHTML = `
      <svg id="pm-svg" class="show-paths" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
        <defs>
          <filter id="pm-shadow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="2" stdDeviation="2" flood-color="#000" flood-opacity="0.35"/>
          </filter>
        </defs>
        <g id="pm-viewport">
          <g id="pm-edges"></g>
          <g id="pm-nodes"></g>
        </g>
      </svg>
      <div class="pm-empty" id="pm-empty" style="display:none">
        <div class="pm-empty-icon">${iconSvg('globe', 36)}</div>
        <h3>No assessment loaded</h3>
        <p>Run an assessment to populate the posture map. The graph will show your zones, services, and any open findings, with chains to high-severity exposures.</p>
      </div>
    `;
    page.appendChild(stage);
    svg = stage.querySelector('#pm-svg');
    viewport = stage.querySelector('#pm-viewport');
    edgesG = stage.querySelector('#pm-edges');
    nodesG = stage.querySelector('#pm-nodes');
    emptyEl = stage.querySelector('#pm-empty');
    bindStage();
    return stage;
  }

  function createDrawer() {
    if (document.querySelector('.pm-drawer')) {
      drawer = document.querySelector('.pm-drawer');
      drawerBackdrop = document.querySelector('.pm-backdrop');
      drawerBody = drawer.querySelector('#pm-drawer-body');
      drawerTitle = drawer.querySelector('#pm-drawer-title');
      drawerSub = drawer.querySelector('#pm-drawer-type');
      drawerIcon = drawer.querySelector('#pm-drawer-icon');
      drawerClose = drawer.querySelector('.pm-drawer-close');
      return;
    }
    const backdrop = document.createElement('div');
    backdrop.className = 'pm-backdrop';
    const dr = document.createElement('aside');
    dr.className = 'pm-drawer';
    dr.setAttribute('role', 'dialog');
    dr.setAttribute('aria-label', 'Entity details');
    dr.innerHTML = `
      <div class="pm-drawer-head">
        <div class="pm-drawer-title">
          <span class="pm-drawer-title-icon" id="pm-drawer-icon">${iconSvg('globe', 20)}</span>
          <div class="pm-drawer-title-text">
            <small id="pm-drawer-type">Entity</small>
            <h2 id="pm-drawer-title">—</h2>
          </div>
        </div>
        <button class="pm-drawer-close" type="button" aria-label="Close">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg>
        </button>
      </div>
      <div class="pm-drawer-body" id="pm-drawer-body"></div>
    `;
    document.body.appendChild(backdrop);
    document.body.appendChild(dr);
    drawer = dr;
    drawerBackdrop = backdrop;
    drawerBody = dr.querySelector('#pm-drawer-body');
    drawerTitle = dr.querySelector('#pm-drawer-title');
    drawerSub = dr.querySelector('#pm-drawer-type');
    drawerIcon = dr.querySelector('#pm-drawer-icon');
    drawerClose = dr.querySelector('.pm-drawer-close');
    drawerClose.addEventListener('click', closeDrawer);
    drawerBackdrop.addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && drawer.classList.contains('open')) closeDrawer();
    });
  }

  function bindStage() {
    if (bound) return; bound = true;

    // Wheel zoom — toward cursor. Trackpad pinch = wheel + ctrlKey.
    svg.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const factor = (e.ctrlKey || e.metaKey) ? (e.deltaY > 0 ? 0.92 : 1.08) : (e.deltaY > 0 ? 0.9 : 1.1);
      zoomToward(cx, cy, factor);
    }, { passive: false });

    // Pan via background drag
    let panning = null;
    svg.addEventListener('mousedown', (e) => {
      if (e.target.closest('.pm-node')) return; // don't pan when starting on a node
      panning = { x: e.clientX, y: e.clientY, tx: camera.tx, ty: camera.ty };
      svg.classList.add('is-panning');
      e.preventDefault();
    });
    window.addEventListener('mousemove', (e) => {
      if (!panning) return;
      camera.tx = panning.tx + (e.clientX - panning.x);
      camera.ty = panning.ty + (e.clientY - panning.y);
      applyCamera();
    });
    window.addEventListener('mouseup', () => {
      if (panning) svg.classList.remove('is-panning');
      panning = null;
    });

    // Click node (delegated)
    nodesG.addEventListener('click', (e) => {
      const node = e.target.closest('.pm-node');
      if (!node) return;
      openDrawer(node.dataset.nodeId);
    });
    nodesG.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const node = e.target.closest('.pm-node');
      if (!node) return;
      e.preventDefault();
      openDrawer(node.dataset.nodeId);
    });
    // Hover dim
    nodesG.addEventListener('mouseover', (e) => {
      const node = e.target.closest('.pm-node');
      if (!node) return;
      focusNeighbors(node.dataset.nodeId, true);
    });
    nodesG.addEventListener('mouseout', (e) => {
      const node = e.target.closest('.pm-node');
      if (!node) return;
      focusNeighbors(node.dataset.nodeId, false);
    });

    window.addEventListener('resize', () => { if (currentView) fit(); });
  }

  function focusNeighbors(nodeId, on) {
    if (!currentView) return;
    const { graph } = currentView;
    const node = graph.nodes.get(nodeId);
    if (!node) return;
    svg.classList.toggle('is-focusing', on);
    if (!on) {
      nodesG.querySelectorAll('.pm-focus').forEach(n => n.classList.remove('pm-focus'));
      edgesG.querySelectorAll('.pm-focus').forEach(n => n.classList.remove('pm-focus'));
      return;
    }
    const ids = new Set([nodeId]);
    for (const e of graph.edges) {
      if (e.from === nodeId) ids.add(e.to);
      if (e.to === nodeId) ids.add(e.from);
    }
    nodesG.querySelectorAll('.pm-node').forEach(n => n.classList.toggle('pm-focus', ids.has(n.dataset.nodeId)));
    edgesG.querySelectorAll('.pm-edge').forEach(e => e.classList.toggle('pm-focus', ids.has(e.dataset.from) && ids.has(e.dataset.to)));
  }

  function paintGraph(view) {
    edgesG.innerHTML = '';
    nodesG.innerHTML = '';
    const { graph, layout: lay } = view;
    const positions = lay.positions;

    // Edges first (so nodes sit on top)
    for (const edge of graph.edges) {
      const fromP = positions.get(edge.from);
      const toP = positions.get(edge.to);
      if (!fromP || !toP) continue;
      const x1 = fromP.x + fromP.w;
      const y1 = fromP.y + fromP.h / 2;
      const x2 = toP.x;
      const y2 = toP.y + toP.h / 2;
      const dx = (x2 - x1) / 2;
      const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', d);
      path.setAttribute('class', `pm-edge sev-${edge.node.severity || 'pass'}`);
      path.dataset.from = edge.from;
      path.dataset.to = edge.to;
      if (graph.attackEdges.has(`${edge.from}->${edge.to}`)) path.classList.add('on-path');
      edgesG.appendChild(path);
    }

    // Nodes
    for (const n of graph.nodes.values()) {
      const p = positions.get(n.id);
      if (!p) continue;
      const sev = n.severity || (n.type === 'internet' ? 'info' : 'pass');
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', `pm-node is-${sev} ${graph.attackNodes.has(n.id) ? 'on-path' : ''}`);
      g.setAttribute('transform', `translate(${p.x}, ${p.y})`);
      g.setAttribute('tabindex', '0');
      g.setAttribute('role', 'button');
      g.dataset.nodeId = n.id;
      const ariaLabel = `${n.label || ''} — ${n.type}${n.findings && n.findings.length ? ' — ' + n.findings.length + ' findings' : ''}`;
      g.setAttribute('aria-label', ariaLabel);

      // Background card
      const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      bg.setAttribute('class', 'pm-node-bg');
      bg.setAttribute('width', p.w);
      bg.setAttribute('height', p.h);
      bg.setAttribute('rx', 10);
      g.appendChild(bg);

      // Left accent bar
      const accent = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      accent.setAttribute('class', 'pm-node-accent');
      accent.setAttribute('width', 3);
      accent.setAttribute('height', p.h);
      accent.setAttribute('rx', 1.5);
      accent.setAttribute('fill', severityColor(sev));
      g.appendChild(accent);

      // Icon
      const icon = iconFor(n);
      g.insertAdjacentHTML('beforeend',
        `<g transform="translate(14, 14)">${iconSvg(icon, 18)}</g>`);

      // Type label
      const typeLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      typeLabel.setAttribute('class', 'pm-node-type');
      typeLabel.setAttribute('x', 42);
      typeLabel.setAttribute('y', 16);
      typeLabel.textContent = n.type === 'service' ? n.label : n.type;
      g.appendChild(typeLabel);

      // Main label
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('class', 'pm-node-text');
      label.setAttribute('x', 42);
      label.setAttribute('y', 35);
      const labelText = n.type === 'service' ? (n.findings[0]?.resourceName || capitalize(n.category)) : (n.label || '');
      label.textContent = truncate(labelText || n.label || '', 22);
      g.appendChild(label);

      // Sub (plan / id / finding count)
      const sub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      sub.setAttribute('class', 'pm-node-sub');
      sub.setAttribute('x', 42);
      sub.setAttribute('y', 52);
      const failCount = n.findings ? n.findings.filter(f => f.status === 'FAIL').length : 0;
      const baseSub = n.sub || '';
      const subText = failCount > 0 ? `${baseSub} · ${failCount} fail` : baseSub;
      sub.textContent = truncate(subText, 28);
      g.appendChild(sub);

      // Failure count badge
      if (failCount > 0) {
        const badgeX = p.w - 28, badgeY = 10;
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', badgeX + 9);
        circle.setAttribute('cy', badgeY + 9);
        circle.setAttribute('r', 10);
        circle.setAttribute('fill', severityColor(sev));
        g.appendChild(circle);
        const num = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        num.setAttribute('class', 'pm-badge');
        num.setAttribute('x', badgeX + 9);
        num.setAttribute('y', badgeY + 13);
        num.setAttribute('text-anchor', 'middle');
        num.textContent = String(failCount);
        g.appendChild(num);
      }

      nodesG.appendChild(g);
    }

    // Compute viewBox
    svg.setAttribute('viewBox', `0 0 ${lay.bounds.w} ${lay.bounds.h}`);
  }

  function iconFor(node) {
    if (node.type === 'service') return node.icon || 'generic';
    if (node.type === 'internet') return 'globe';
    if (node.type === 'account') return 'building';
    if (node.type === 'zone') return 'globe';
    return 'generic';
  }

  function severityColor(sev) {
    switch (sev) {
      case 'critical': return 'var(--crit)';
      case 'high':     return 'var(--high)';
      case 'medium':   return 'var(--med)';
      case 'low':      return 'var(--low)';
      case 'info':     return 'var(--info)';
      case 'informational': return 'var(--info)';
      case 'pass':     return 'var(--low)';
      default:         return 'var(--line-2)';
    }
  }

  function capitalize(s) { return (s || '').charAt(0).toUpperCase() + (s || '').slice(1); }
  function truncate(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  // ── Camera (pan/zoom) ───────────────────────────────────────────────────
  function applyCamera() {
    if (!viewport) return;
    viewport.setAttribute('transform', `translate(${camera.tx}, ${camera.ty}) scale(${camera.scale})`);
  }

  function zoomToward(cx, cy, factor) {
    const newScale = Math.max(0.3, Math.min(2.5, camera.scale * factor));
    // Adjust tx/ty so (cx, cy) stays at the same graph point
    const k = newScale / camera.scale;
    camera.tx = cx - (cx - camera.tx) * k;
    camera.ty = cy - (cy - camera.ty) * k;
    camera.scale = newScale;
    applyCamera();
  }
  function zoom(factor) {
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    zoomToward(rect.width / 2, rect.height / 2, factor);
  }
  function fit() {
    if (!svg || !currentView) return;
    const b = currentView.layout.bounds;
    const rect = svg.getBoundingClientRect();
    if (b.w === 0 || b.h === 0 || rect.width === 0 || rect.height === 0) return;
    const scale = Math.min(rect.width / b.w, rect.height / b.h) * 0.92;
    camera.scale = Math.max(0.3, Math.min(2.5, scale));
    camera.tx = (rect.width - b.w * camera.scale) / 2 - 0;   // viewBox starts at 0
    camera.ty = (rect.height - b.h * camera.scale) / 2;
    applyCamera();
  }

  // ── Stats / empty ───────────────────────────────────────────────────────
  function updateStats(graph) {
    if (!stats) return;
    if (!graph) { stats.innerHTML = ''; return; }
    const total = graph.nodes.size;
    const attackPaths = graph.dangerLeaves.length;
    const exposed = graph.dangerLeaves.length;
    const findingsCount = [...graph.nodes.values()].reduce((a, n) => a + (n.findings?.length || 0), 0);
    stats.innerHTML = `
      <span class="pm-stat"><b>${total}</b> entities</span>
      <span class="pm-stat is-danger"><b>${findingsCount}</b> findings</span>
      <span class="pm-stat is-path"><b>${attackPaths}</b> attack path${attackPaths === 1 ? '' : 's'}</span>
      <span class="pm-stat"><b>${exposed}</b> exposed asset${exposed === 1 ? '' : 's'}</span>
    `;
  }

  function showEmpty(on) {
    if (!emptyEl) return;
    emptyEl.style.display = on ? 'flex' : 'none';
    if (svg) svg.style.visibility = on ? 'hidden' : 'visible';
  }

  // ── Drawer ──────────────────────────────────────────────────────────────
  function openDrawer(nodeId) {
    if (!currentView) return;
    const node = currentView.graph.nodes.get(nodeId);
    if (!node) return;
    drawerSub.textContent = node.type === 'service' ? node.label : capitalize(node.type);
    drawerTitle.textContent = node.label || '—';
    drawerIcon.innerHTML = iconSvg(iconFor(node), 20);
    drawerBody.innerHTML = renderDrawerBody(node);
    drawer.classList.add('open');
    drawerBackdrop.classList.add('open');
  }
  function closeDrawer() {
    drawer.classList.remove('open');
    drawerBackdrop.classList.remove('open');
  }

  function renderDrawerBody(node) {
    const findings = node.findings || [];
    const failCount = findings.filter(f => f.status === 'FAIL').length;
    const passCount = findings.length - failCount;
    const sev = node.severity || 'pass';
    const remediableIds = (window.__REMEDIABLE_CHECK_IDS__ instanceof Set) ? window.__REMEDIABLE_CHECK_IDS__ : null;

    let html = `
      <div class="pm-drawer-meta">
        <span class="pm-drawer-meta-sev ${sev}">${sev === 'pass' ? 'pass' : sev}</span>
        <span>${failCount} failing · ${passCount} passing</span>
        ${node.sub ? `<span style="color:var(--fg-4)">·</span><span>${escHtml(node.sub)}</span>` : ''}
      </div>
    `;

    if (findings.length === 0) {
      html += `<div class="pm-drawer-section-label">Findings</div>
        <div style="color:var(--fg-3);font-size:13px">No findings on this node.</div>`;
      return html;
    }

    // Sort findings: FAIL first, then severity
    const sorted = [...findings].sort((a, b) => {
      const af = a.status === 'FAIL' ? 0 : 1;
      const bf = b.status === 'FAIL' ? 0 : 1;
      if (af !== bf) return af - bf;
      return (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    });

    html += `<div class="pm-drawer-section-label">Findings (${findings.length})</div>`;
    for (const f of sorted) {
      const title = f.checkTitle || f.title || f.checkId || 'Finding';
      const evidence = f.metadata?.evidence || f.description || '';
      const isRemediable = remediableIds && remediableIds.has(f.checkId) && f.status === 'FAIL';
      const meta = [
        f.checkId,
        f.service || f.category,
        f.resourceType === 'account' ? 'account' : (f.resourceName || f.resourceId || ''),
        f.severity,
      ].filter(Boolean).join(' · ');
      html += `
        <div class="pm-drawer-finding">
          <div class="pm-drawer-finding-title">${escHtml(title)}</div>
          <div class="pm-drawer-finding-meta">
            <span>${escHtml(meta)}</span>
            <span class="v1-finding-status ${escHtml(f.metadata?.status || 'existing')}">${escHtml(f.metadata?.status || (f.status === 'PASS' ? 'pass' : 'fail'))}</span>
          </div>
          ${evidence ? `<div class="pm-drawer-finding-ev">${escHtml(evidence.length > 240 ? evidence.slice(0, 240) + '…' : evidence)}</div>` : ''}
          ${isRemediable ? `
            <div class="pm-drawer-remedy-row">
              <button type="button" class="v1-btn v1-btn-sm v1-btn-primary" data-remediate="${escHtml(f.checkId)}">
                Remediate
              </button>
            </div>` : ''}
        </div>
      `;
    }

    // Bind Remediate buttons after render
    setTimeout(() => {
      drawerBody.querySelectorAll('[data-remediate]').forEach(btn => {
        btn.addEventListener('click', () => {
          closeDrawer();
          if (typeof navigateTo === 'function') navigateTo('remediate');
        });
      });
    }, 0);

    return html;
  }

  // ── Public entry point ──────────────────────────────────────────────────
  function initPostureMap() {
    render();
  }

  return { initPostureMap, render };
})();

function initPostureMap() { PM.initPostureMap(); }
