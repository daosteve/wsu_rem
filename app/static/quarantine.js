'use strict';

const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

const ACTION_LABELS = {
  ad_disable:            'Disable AD account',
  ad_reset_password:     'Reset AD password',
  gw_suspend:            'Suspend Google Workspace',
  gw_reset_cookies:      'Reset GW sign-in cookies',
  entra_revoke_sessions: 'Revoke Entra ID sessions',
};
const ACTIONS = Object.keys(ACTION_LABELS);

/* ── Utilities ─────────────────────────────────────────────────────────── */
function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function setSpinner(btn, spinner, on) {
  btn.disabled = on;
  spinner.classList.toggle('d-none', !on);
}

function gatherActions() {
  return Array.from(document.querySelectorAll('input[type=checkbox]:checked'))
    .map(cb => ({ username: cb.dataset.user, action: cb.dataset.action }));
}

function selectAllAction(action) {
  document.querySelectorAll(`input[type=checkbox][data-action="${action}"]`)
    .forEach(cb => { if (!cb.disabled) cb.checked = true; });
}

function clearAllActions() {
  document.querySelectorAll('input[type=checkbox]').forEach(cb => cb.checked = false);
}

/* ── Select-all / clear buttons ────────────────────────────────────────── */
document.querySelectorAll('[data-select-action]').forEach(btn => {
  btn.addEventListener('click', () => selectAllAction(btn.dataset.selectAction));
});
document.getElementById('clearAllBtn').addEventListener('click', clearAllActions);

/* ── Lookup ─────────────────────────────────────────────────────────────── */
document.getElementById('lookupBtn').addEventListener('click', async () => {
  const btn     = document.getElementById('lookupBtn');
  const spinner = document.getElementById('lookupSpinner');

  setSpinner(btn, spinner, true);
  try {
    const text = document.getElementById('usernameInput').value.trim();
    if (!text) { alert('Enter at least one username.'); return; }
    const resp = await fetch('/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
      body: JSON.stringify({ usernames: text }),
    });
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }
    renderUserTable(data.users || []);
  } catch (err) {
    alert('Lookup failed: ' + err);
  } finally {
    setSpinner(btn, spinner, false);
  }
});

const DOMAIN_COLOURS = {};      // lazily assigned per domain name
const DOMAIN_PALETTE = ['primary', 'info', 'warning', 'secondary', 'dark'];

function domainBadge(domain) {
  if (!domain) return '—';
  if (!DOMAIN_COLOURS[domain]) {
    const idx = Object.keys(DOMAIN_COLOURS).length % DOMAIN_PALETTE.length;
    DOMAIN_COLOURS[domain] = DOMAIN_PALETTE[idx];
  }
  return `<span class="badge bg-${DOMAIN_COLOURS[domain]}">${esc(domain)}</span>`;
}

function renderUserTable(users) {
  const tbody = document.getElementById('userTableBody');
  tbody.innerHTML = '';
  users.forEach(u => {
    const found = u.found;
    const tr = document.createElement('tr');
    if (!found) tr.classList.add('table-warning');

    const adBadge = found
      ? (u.ad_disabled
          ? '<span class="badge bg-danger">Disabled</span>'
          : '<span class="badge bg-success">Enabled</span>')
      : '—';

    const notFoundLabel = u.reason
      ? `<em class="text-muted">${esc(u.reason)}</em>`
      : '<em class="text-muted">Not found</em>';

    const checkboxes = ACTIONS.map(a =>
      `<td class="text-center">${found
        ? `<input type="checkbox" class="form-check-input" data-user="${esc(u.username)}" data-action="${a}">`
        : '—'
      }</td>`
    ).join('');

    let displayCell = found ? `<strong>${esc(u.display_name || '')}</strong>` : notFoundLabel;
    if (found) {
      if (u.ou)      displayCell += `<br><span class="text-muted small"><strong>OU:</strong> ${esc(u.ou)}</span>`;
      if (u.created) displayCell += `<br><span class="text-muted small"><strong>Created:</strong> ${esc(u.created)}</span>`;
      if (u.modified) displayCell += `<br><span class="text-muted small"><strong>Modified:</strong> ${esc(u.modified)}</span>`;
      if (u.groups && u.groups.length) {
        displayCell += `<br><span class="text-muted small"><strong>Groups:</strong> ${u.groups.map(esc).join(', ')}</span>`;
      }
    }

    tr.innerHTML = `
      <td class="font-monospace">${esc(u.username)}</td>
      <td>${displayCell}</td>
      <td>${found ? domainBadge(u.domain) : '—'}</td>
      <td>${adBadge}</td>
      ${checkboxes}
    `;
    tbody.appendChild(tr);
  });
  document.getElementById('userTableSection').classList.remove('d-none');
  document.getElementById('resultsSection').classList.add('d-none');
}

/* ── Execute (confirmation modal) ───────────────────────────────────────── */
const confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));

document.getElementById('executeBtn').addEventListener('click', () => {
  const actions = gatherActions();
  if (!actions.length) { alert('Select at least one action.'); return; }

  const lines = actions
    .map(a => `• ${a.username}  →  ${ACTION_LABELS[a.action] || a.action}`)
    .join('\n');

  document.getElementById('confirmModalBody').innerHTML =
    `<p>You are about to execute <strong>${actions.length}</strong> action(s):</p>` +
    `<pre class="small border rounded p-2 bg-light">${esc(lines)}</pre>` +
    `<p class="text-danger fw-bold mb-0">These actions cannot be undone.</p>`;

  confirmModal.show();
});

document.getElementById('confirmExecuteBtn').addEventListener('click', async () => {
  const actions = gatherActions();
  confirmModal.hide();

  const btn     = document.getElementById('executeBtn');
  const spinner = document.getElementById('executeSpinner');
  setSpinner(btn, spinner, true);
  try {
    const resp = await fetch('/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
      body: JSON.stringify({ actions }),
    });
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }
    renderResults(data.results || []);
  } catch (err) {
    alert('Execute failed: ' + err);
  } finally {
    setSpinner(btn, spinner, false);
  }
});

function renderResults(results) {
  const tbody = document.getElementById('resultsTableBody');
  tbody.innerHTML = '';
  results.forEach(r => {
    const tr = document.createElement('tr');
    tr.classList.add(r.result === 'success' ? 'table-success' : 'table-danger');
    tr.innerHTML = `
      <td class="font-monospace">${esc(r.username)}</td>
      <td>${esc(ACTION_LABELS[r.action] || r.action)}</td>
      <td><span class="badge bg-${r.result === 'success' ? 'success' : 'danger'}">${esc(r.result)}</span></td>
      <td class="small">${esc(r.detail || '')}</td>
    `;
    tbody.appendChild(tr);
  });
  const section = document.getElementById('resultsSection');
  section.classList.remove('d-none');
  section.scrollIntoView({ behavior: 'smooth' });
}
