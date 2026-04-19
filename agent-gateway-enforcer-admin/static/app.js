// Vanilla JS — no bundler. Small enough to audit in one sitting.
//
// Auto-refreshes every 30s. Changing tab, namespace, or `since`
// triggers an immediate reload.

const $ = (sel) => document.querySelector(sel);

const state = {
  tab: 'overview',
  ns: '',
  since: '1h',
};

function setTab(name) {
  state.tab = name;
  document.querySelectorAll('header nav button').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('main .tab').forEach((t) => {
    t.classList.toggle('active', t.id === `tab-${name}`);
  });
  load();
}

function nsQuery() {
  return state.ns ? `?namespace=${encodeURIComponent(state.ns)}` : '';
}

async function j(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

function escape(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function setStatus(text, isErr) {
  const el = $('#status');
  el.textContent = text;
  el.style.color = isErr ? '#b91c1c' : '#6b7280';
}

function fmtSelector(ml) {
  const keys = Object.keys(ml || {}).sort();
  if (keys.length === 0) return '<empty>';
  return keys.map((k) => `${k}=${ml[k]}`).join(',');
}

function fmtList(items) {
  if (!items || items.length === 0) return '<none>';
  if (items.length <= 3) return items.join(',');
  return `${items.slice(0, 3).join(',')} (+${items.length - 3} more)`;
}

function util(budget, spent) {
  if (!budget || budget <= 0) return '<span style="color:#6b7280">N/A</span>';
  const pct = (100 * spent) / budget;
  const cls = pct >= 90 ? 'util-high' : pct >= 70 ? 'util-warn' : '';
  return `<span class="${cls}">${pct.toFixed(1)}</span>`;
}

function kindClass(kind) {
  switch (kind) {
    case 'EgressBlocked': return 'kind-egress';
    case 'FileBlocked': return 'kind-file';
    case 'ExecBlocked': return 'kind-exec';
    case 'MutationBlocked': return 'kind-mutation';
    default: return '';
  }
}

async function loadOverview() {
  const o = await j('/api/v1/overview');
  $('#ov-nodes').textContent = o.nodes_up;
  $('#ov-policies').textContent = o.policy_count;
  $('#ov-caps').textContent = o.capability_count;
  $('#ov-viol').textContent = o.violation_count_last_hour;
  $('#ov-spend').textContent = `$${o.total_spend_today_usd.toFixed(2)}`;
}

async function loadPolicies() {
  const rows = await j(`/api/v1/policies${nsQuery()}`);
  const tbody = $('#policies-table tbody');
  tbody.innerHTML = rows.map((p) => `
    <tr>
      <td>${escape(p.namespace)}</td>
      <td>${escape(p.name)}</td>
      <td>${escape(fmtSelector(p.selector))}</td>
      <td>${escape(p.default_egress_action || '—')}</td>
      <td>${escape(p.schedule_summary || '—')}</td>
      <td>${p.enforced_pods}</td>
      <td>${escape((p.bundle_hash || '<pending>').slice(0, 12))}</td>
      <td>${escape(p.message || '')}</td>
    </tr>
  `).join('');
}

async function loadCapabilities() {
  const rows = await j(`/api/v1/capabilities${nsQuery()}`);
  const tbody = $('#caps-table tbody');
  tbody.innerHTML = rows.map((c) => {
    const spent = c.spent_today_usd === null ? null : c.spent_today_usd;
    const spentStr = spent === null ? '—' : `$${spent.toFixed(2)}`;
    return `
      <tr>
        <td>${escape(c.namespace)}</td>
        <td>${escape(c.name)}</td>
        <td>${escape(fmtList(c.allowed_models))}</td>
        <td>${escape(fmtList(c.allowed_tools))}</td>
        <td>$${c.max_daily_spend_usd.toFixed(2)}</td>
        <td>${spentStr}</td>
        <td>${spent === null ? '—' : util(c.max_daily_spend_usd, spent)}</td>
      </tr>
    `;
  }).join('');
}

async function loadViolations() {
  const q = new URLSearchParams();
  if (state.ns) q.set('namespace', state.ns);
  if (state.since) q.set('since', state.since);
  const rows = await j(`/api/v1/violations?${q.toString()}`);
  const tbody = $('#viol-table tbody');
  tbody.innerHTML = rows.map((v) => `
    <tr>
      <td>${escape(v.namespace)}</td>
      <td>${escape(v.pod)}</td>
      <td>${escape(v.policy)}</td>
      <td class="${kindClass(v.kind)}">${escape(v.kind)}</td>
      <td>${escape(v.detail)}</td>
      <td>${v.count}</td>
      <td>${escape(v.last_seen)}</td>
    </tr>
  `).join('');
}

async function load() {
  try {
    setStatus('loading…');
    switch (state.tab) {
      case 'overview': await loadOverview(); break;
      case 'policies': await loadPolicies(); break;
      case 'capabilities': await loadCapabilities(); break;
      case 'violations': await loadViolations(); break;
    }
    setStatus(`updated ${new Date().toLocaleTimeString()}`);
  } catch (e) {
    setStatus(`error: ${e.message}`, true);
  }
}

// --- Wire up controls ---
document.querySelectorAll('header nav button').forEach((b) => {
  b.addEventListener('click', () => setTab(b.dataset.tab));
});
$('#refreshBtn').addEventListener('click', load);
$('#nsInput').addEventListener('change', (e) => {
  state.ns = e.target.value.trim();
  load();
});
$('#sinceInput').addEventListener('change', (e) => {
  state.since = e.target.value;
  if (state.tab === 'violations') load();
});
setInterval(load, 30_000);
load();
