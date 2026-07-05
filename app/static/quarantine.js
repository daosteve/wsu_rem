'use strict';

const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

const ACTION_LABELS = {
  ad_disable:            'Disable Active Directory account',
  ad_enable:             'Enable Active Directory account',
  ad_reset_password:     'Reset Active Directory password',
  gw_suspend:            'Suspend Google Workspace',
  gw_unsuspend:          'Unsuspend Google Workspace',
  gw_reset_cookies:      'Reset Google Workspace sign-in cookies',
  entra_revoke_sessions:          'Revoke Entra ID sessions',
  entra_require_mfa_reregister:    'Require re-register MFA',
};
const ACTIONS = Object.keys(ACTION_LABELS);

// Actions that do NOT require a quarantine reason
const ACTIONS_NO_REASON = new Set(['ad_enable', 'gw_unsuspend']);

const QUARANTINE_REASONS = [
  'Breached',
  'Compromised',
  'Risky Geolocation',
  'Phishing',
  'Malware',
  'Policy Violation',
  'Other',
];
const REASON_OPTIONS_HTML = QUARANTINE_REASONS.map(r =>
  `<option value="${esc(r)}">${esc(r)}</option>`
).join('');

/* ── Utilities ─────────────────────────────────────────────────────────── */
function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/**
 * Convert a UTC date string from the server to a local-time display string.
 * Accepts "YYYY-MM-DD HH:MM UTC" → "May 22, 2026 @ 5:55PM"
 * Accepts "YYYY-MM-DD"           → "May 22, 2026"
 */
function fmtLocalTime(utcStr) {
  if (!utcStr) return '';
  let m = utcStr.match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})/);
  if (m) {
    const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]));
    const date = d.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
    const time = d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })
                  .replace(/\s+(AM|PM)$/i, '$1');
    return `${date} @ ${time}`;
  }
  m = utcStr.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (m) {
    const d = new Date(+m[1], +m[2] - 1, +m[3]);
    return d.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
  }
  return utcStr;
}

function setSpinner(btn, spinner, on) {
  btn.disabled = on;
  spinner.classList.toggle('d-none', !on);
}

function gatherActions() {
  return Array.from(document.querySelectorAll('#userTableBody input[type=checkbox]:checked'))
    .map(cb => {
      const row = cb.closest('tr');
      const reason  = row ? row.querySelector('.qr-reason')?.value  : '';
      const comment = row ? row.querySelector('.qr-comment')?.value : '';
      return { username: cb.dataset.user, action: cb.dataset.action, reason, comment };
    });
}

/* ── Lookup ─────────────────────────────────────────────────────────────── */
const MAX_USERNAMES = 20;

function normalizeUsernameToken(token) {
  // Strip mailto: prefix
  if (token.toLowerCase().startsWith('mailto:')) token = token.slice(7);
  // Extract username from user@worcester.edu
  const atIdx = token.indexOf('@');
  if (atIdx !== -1) token = token.slice(0, atIdx);
  return token;
}

function normalizeUsernamesText(text) {
  return text.trim()
    ? text.trim().split(/[\s,;]+/).filter(u => u.length > 0).map(normalizeUsernameToken).join('\n')
    : text;
}

function countUsernames(text) {
  return text.trim() ? text.trim().split(/[\s,;]+/).filter(u => u.length > 0).length : 0;
}

const usernameInput = document.getElementById('usernameInput');
const usernameCount = document.getElementById('usernameCount');

usernameInput.addEventListener('paste', (e) => {
  e.preventDefault();
  const pasted = (e.clipboardData || window.clipboardData).getData('text');
  const normalized = normalizeUsernamesText(pasted);
  const start = usernameInput.selectionStart;
  const end = usernameInput.selectionEnd;
  const current = usernameInput.value;
  usernameInput.value = current.slice(0, start) + normalized + current.slice(end);
  usernameInput.dispatchEvent(new Event('input'));
});

usernameInput.addEventListener('input', () => {
  const n = countUsernames(usernameInput.value);
  usernameCount.textContent = `${n} / ${MAX_USERNAMES}`;
  usernameCount.classList.toggle('text-danger', n > MAX_USERNAMES);
  usernameCount.classList.toggle('text-muted', n <= MAX_USERNAMES);
});

document.getElementById('lookupBtn').addEventListener('click', async () => {
  const btn     = document.getElementById('lookupBtn');
  const spinner = document.getElementById('lookupSpinner');

  setSpinner(btn, spinner, true);
  try {
    const text = normalizeUsernamesText(document.getElementById('usernameInput').value.trim());
    if (!text) { alert('Enter at least one username.'); return; }
    if (countUsernames(text) > MAX_USERNAMES) { alert(`Maximum ${MAX_USERNAMES} usernames allowed.`); return; }
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

    const checkboxes = ACTIONS.map(a => {
      if (!found) return `<td class="text-center action-cell"><span class="text-muted">—</span></td>`;
      // ad_disable only makes sense for enabled accounts; ad_enable only for disabled ones.
      if (a === 'ad_disable' && u.ad_disabled) {
        return `<td class="text-center action-cell"><span class="text-muted" title="Account already disabled">—</span></td>`;
      }
      if (a === 'ad_enable' && !u.ad_disabled) {
        return `<td class="text-center action-cell"><span class="text-muted" title="Account is not disabled">—</span></td>`;
      }
      if (a === 'ad_enable' && !u.quarantined_by_us) {
        return `<td class="text-center action-cell"><span class="text-muted" title="Not disabled by this system">—</span></td>`;
      }
      return `<td class="text-center action-cell"><input type="checkbox" class="form-check-input" data-user="${esc(u.username)}" data-action="${a}"></td>`;
    }).join('');

    let displayCell;
    if (!found) {
      displayCell = notFoundLabel;
    } else {
      // Line 1: username · domain badge · AD status badge · OU
      const domainPart = u.domain ? ` ${domainBadge(u.domain)}` : '';
      const ouPart = u.ou ? ` <span class="badge bg-secondary">${esc(u.ou)}</span>` : '';
      const displayNamePart = u.display_name ? ` (${esc(u.display_name)})` : '';
      displayCell = `<span class="badge bg-dark font-monospace">${esc(u.username)}${displayNamePart}</span>${ouPart}${domainPart} ${adBadge}`;
      // Line 2: created · modified
      const createdPart = u.created ? `<strong>Created:</strong> ${fmtLocalTime(u.created)}` : '';
      const modifiedPart = u.modified ? `<strong>Modified:</strong> ${fmtLocalTime(u.modified)}` : '';
      const dateParts = [createdPart, modifiedPart].filter(Boolean).join(' &nbsp;·&nbsp; ');
      if (dateParts) displayCell += `<br><span class="text-muted small">${dateParts}</span>`;
      // Groups
      if (u.groups && u.groups.length) {
        displayCell += `<br><span class="text-muted small"><strong>Groups:</strong> ${u.groups.map(esc).join(', ')}</span>`;
      }
      // GW last login
      if (u.gw_last_login) {
        displayCell += `<br><span class="text-muted small"><strong>Google Workspace Last Login:</strong> ${fmtLocalTime(u.gw_last_login)}</span>`;
      }
      // Entra MFA info
      if (u.mfa_methods && u.mfa_methods.length) {
        let mfaLine = '<strong>Entra MFA:</strong> Registered: ' + u.mfa_methods.map(m => {
          let s = esc(m.name || m);
          if (m.registered) {
            s += ` <span class="text-muted fst-italic">(registered: ${fmtLocalTime(m.registered)})</span>`;
          }
          return s;
        }).join(', ');
        displayCell += `<br><span class="text-muted small">${mfaLine}</span>`;
      }
      // Entra recent audit activity
      if (u.entra_audit && u.entra_audit.length) {
        displayCell += `<br><span class="text-muted small"><strong>Last MFA Registration:</strong> ${fmtLocalTime(u.entra_audit[0].date)}</span>`;
      }
      // Shared reason/comment (shown when any non-exempt action is checked)
      displayCell += `<div class="qr-inline mt-2 d-none">
        <select class="form-select form-select-sm qr-reason" onchange="this.classList.remove('is-invalid')">
          <option value="">— reason —</option>
          ${REASON_OPTIONS_HTML}
        </select>
        <input type="text" class="form-control form-control-sm qr-comment mt-1" placeholder="Comment (optional)">
      </div>`;
    }

    tr.innerHTML = `
      <td>${displayCell}</td>
      ${checkboxes}
    `;
    tbody.appendChild(tr);
  });
  document.getElementById('userTableSection').classList.remove('d-none');
  document.getElementById('resultsSection').classList.add('d-none');
}

/* ── Inline reason form toggle ─────────────────────────────────────────── */
document.getElementById('userTableBody').addEventListener('change', e => {
  if (!e.target.matches('input[type=checkbox]')) return;
  const row = e.target.closest('tr');

  // gw_suspend and gw_unsuspend are mutually exclusive
  if (e.target.checked && e.target.dataset.action === 'gw_suspend') {
    row.querySelectorAll('input[data-action="gw_unsuspend"]').forEach(cb => { cb.checked = false; });
  } else if (e.target.checked && e.target.dataset.action === 'gw_unsuspend') {
    row.querySelectorAll('input[data-action="gw_suspend"]').forEach(cb => { cb.checked = false; });
  }

  const anyNonExemptChecked = Array.from(row.querySelectorAll('input[type=checkbox]:checked'))
    .some(cb => !ACTIONS_NO_REASON.has(cb.dataset.action));
  row.querySelector('.qr-inline')?.classList.toggle('d-none', !anyNonExemptChecked);
});

/* ── Execute (confirmation modal) ───────────────────────────────────────── */
const confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));
let _pendingExecute = null;   // set by whichever tab opened the modal

document.getElementById('confirmExecuteBtn').addEventListener('click', async () => {
  confirmModal.hide();
  if (_pendingExecute) { await _pendingExecute(); _pendingExecute = null; }
});

document.getElementById('executeBtn').addEventListener('click', () => {
  const actions = gatherActions();
  if (!actions.length) { alert('Select at least one action.'); return; }

  // Require a quarantine reason for rows with at least one non-exempt action checked
  let missingReason = false;
  const rowsNeedingReason = new Set();
  document.querySelectorAll('#userTableBody input[type=checkbox]:checked').forEach(cb => {
    if (!ACTIONS_NO_REASON.has(cb.dataset.action)) rowsNeedingReason.add(cb.closest('tr'));
  });
  rowsNeedingReason.forEach(row => {
    const sel = row.querySelector('.qr-reason');
    if (sel && !sel.value) { sel.classList.add('is-invalid'); missingReason = true; }
  });
  if (missingReason) { alert('Please select a Quarantine Reason for every action.'); return; }

  const lines = actions
    .map(a => {
      const meta = [a.reason, a.comment].filter(Boolean).join(' — ');
      return `• ${a.username}  →  ${ACTION_LABELS[a.action] || a.action}${meta ? ` (${meta})` : ''}`;
    })
    .join('\n');

  document.getElementById('confirmModalBody').innerHTML =
    `<p>You are about to execute <strong>${actions.length}</strong> action(s):</p>` +
    `<pre class="small border rounded p-2 bg-light">${esc(lines)}</pre>` +
    `<p class="text-danger fw-bold mb-0">These actions cannot be undone.</p>`;

  _pendingExecute = async () => {
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
  };

  confirmModal.show();
});

function renderResults(results) {
  const tbody = document.getElementById('resultsTableBody');
  tbody.innerHTML = '';
  results.forEach(r => {
    const tr = document.createElement('tr');
    const rowClass = r.result === 'success' ? 'table-success' : r.result === 'warning' ? 'table-warning' : 'table-danger';
    const badgeClass = r.result === 'success' ? 'success' : r.result === 'warning' ? 'warning text-dark' : 'danger';
    tr.classList.add(rowClass);
    tr.innerHTML = `
      <td class="font-monospace">${esc(r.username)}</td>
      <td>${esc(ACTION_LABELS[r.action] || r.action)}</td>
      <td><span class="badge bg-${badgeClass}">${esc(r.result)}</span></td>
      <td class="small">${esc(r.detail || '')}</td>
    `;
    tbody.appendChild(tr);
  });
  const section = document.getElementById('resultsSection');
  section.classList.remove('d-none');
  section.scrollIntoView({ behavior: 'smooth' });
}

/* ── CSV Import tab ────────────────────────────────────────────────────── */
const csvDropZone  = document.getElementById('csvDropZone');
const csvFileInput = document.getElementById('csvFileInput');
const csvFileLabel = document.getElementById('csvFileLabel');
let   _csvDroppedFile    = null;   // file from drag-and-drop
let   _csvLastUsers      = null;   // last verified user list (for re-render after lock)
const _csvProcessed      = new Set(); // usernames executed this session

const CSV_ACTIONS = ['ad_reset_password', 'gw_reset_cookies', 'entra_revoke_sessions'];

/* drag-and-drop ----------------------------------------------------------- */
csvDropZone.addEventListener('dragover', e => {
  e.preventDefault();
  csvDropZone.classList.add('border-primary', 'bg-light');
});
csvDropZone.addEventListener('dragleave', () => {
  csvDropZone.classList.remove('border-primary', 'bg-light');
});
csvDropZone.addEventListener('drop', e => {
  e.preventDefault();
  csvDropZone.classList.remove('border-primary', 'bg-light');
  const file = e.dataTransfer.files[0];
  if (file) { _csvDroppedFile = file; updateCsvFileLabel(file.name); }
});
csvFileInput.addEventListener('change', () => {
  _csvDroppedFile = null;
  if (csvFileInput.files[0]) updateCsvFileLabel(csvFileInput.files[0].name);
});
function updateCsvFileLabel(name) {
  csvFileLabel.textContent = name;
  csvFileLabel.classList.remove('text-muted');
  csvFileLabel.classList.add('fw-semibold');
}

/* select-all header checkboxes ------------------------------------------- */
CSV_ACTIONS.forEach(action => {
  const hdr = document.getElementById(`csvSelAll-${action}`);
  if (!hdr) return;
  hdr.addEventListener('change', () => {
    document.querySelectorAll(
      `#csvUserTableBody .csv-action-cb[data-action="${action}"]:not(:disabled)`
    ).forEach(cb => { cb.checked = hdr.checked; });
  });
});

/* Verify Users ------------------------------------------------------------ */
document.getElementById('csvVerifyBtn').addEventListener('click', async () => {
  const file = _csvDroppedFile || csvFileInput.files[0];
  if (!file) { alert('Select a CSV file first.'); return; }

  const btn     = document.getElementById('csvVerifyBtn');
  const spinner = document.getElementById('csvVerifySpinner');
  setSpinner(btn, spinner, true);
  try {
    const fd = new FormData();
    fd.append('csv_file', file);
    const resp = await fetch('/csv_lookup', {
      method: 'POST',
      headers: { 'X-CSRFToken': CSRF_TOKEN },
      body: fd,
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
      alert(err.error || 'Verification failed.');
      return;
    }
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }

    _csvLastUsers = data.users || [];
    populateCsvDomainFilter(_csvLastUsers);
    renderCsvUserTable(_csvLastUsers);
    applyCsvFilters();

    const alreadyCount = _csvLastUsers.filter(u => _csvProcessed.has(u.username)).length;
    document.getElementById('csvStatBadges').innerHTML = `
      <span class="badge bg-secondary me-1">${data.total_in_csv} unique users in CSV</span>
      <span class="badge bg-success me-1">${data.found} found in AD</span>
      ${data.not_found ? `<span class="badge bg-warning text-dark me-1">${data.not_found} not found in AD</span>` : ''}
      ${alreadyCount ? `<span class="badge bg-dark me-1">${alreadyCount} already processed this session</span>` : ''}
    `;

    document.getElementById('csvExecResultsSection').classList.add('d-none');
    document.getElementById('csvVerifySection').classList.remove('d-none');
    document.getElementById('csvVerifySection').scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    alert('Verification failed: ' + err);
  } finally {
    setSpinner(btn, spinner, false);
  }
});

/* render CSV user table --------------------------------------------------- */
function renderCsvUserTable(users) {
  const tbody = document.getElementById('csvUserTableBody');
  tbody.innerHTML = '';

  users.forEach(u => {
    const tr = document.createElement('tr');
    tr.dataset.username = u.username;
    const processed = _csvProcessed.has(u.username);

    if (!u.found) {
      tr.classList.add('table-warning');
      tr.innerHTML = `
        <td class="font-monospace">${esc(u.username)}
          <span class="badge bg-warning text-dark ms-1 small">Not in AD</span>
        </td>
        <td colspan="3" class="text-center text-muted fst-italic small">Not found in Active Directory</td>
      `;
    } else {
      if (processed) tr.classList.add('table-secondary');
      const adBadge = u.ad_disabled
        ? '<span class="badge bg-danger ms-1">Disabled</span>'
        : '<span class="badge bg-success ms-1">Enabled</span>';
      const domainPart = u.domain ? ` ${domainBadge(u.domain)}` : '';
      const ouPart     = u.ou
        ? `<br><span class="text-muted small">${esc(u.ou)}</span>` : '';
      const displayPart = (u.display_name && u.display_name !== u.username)
        ? ` <span class="text-muted">(${esc(u.display_name)})</span>` : '';
      const procBadge  = processed
        ? ' <span class="badge bg-secondary ms-1">Processed</span>' : '';

      const mkCb = action => {
        if (processed)
          return `<td class="text-center action-cell"><span class="text-muted">—</span></td>`;
        return `<td class="text-center action-cell">
          <input type="checkbox" class="form-check-input csv-action-cb"
                 data-user="${esc(u.username)}" data-action="${action}">
        </td>`;
      };

      tr.innerHTML = `
        <td>
          <span class="badge bg-dark font-monospace">${esc(u.username)}</span>${displayPart}${domainPart}${adBadge}${procBadge}${ouPart}
        </td>
        ${CSV_ACTIONS.map(mkCb).join('')}
      `;
    }
    tbody.appendChild(tr);
  });
}

/* Execute CSV Actions ----------------------------------------------------- */
function showCsvExecError(msg) {
  const el = document.getElementById('csvExecError');
  el.textContent = msg;
  el.classList.remove('d-none');
}
function clearCsvExecError() {
  document.getElementById('csvExecError').classList.add('d-none');
}

document.getElementById('csvExecuteBtn').addEventListener('click', () => {
  clearCsvExecError();
  const reason = document.getElementById('csvReason').value;
  if (!reason) {
    document.getElementById('csvReason').classList.add('is-invalid');
    showCsvExecError('Please select a Quarantine Reason before executing.');
    document.getElementById('csvReason').focus();
    return;
  }
  document.getElementById('csvReason').classList.remove('is-invalid');

  const comment = document.getElementById('csvComment').value.trim();
  const actions = Array.from(
    document.querySelectorAll('#csvUserTableBody .csv-action-cb:checked:not(:disabled)')
  ).map(cb => ({ username: cb.dataset.user, action: cb.dataset.action, reason, comment }));

  if (!actions.length) {
    showCsvExecError('No actions selected. Check at least one action checkbox in the table (use the column header checkboxes to select all).');
    return;
  }

  const uniqueUsers = new Set(actions.map(a => a.username)).size;
  const lines = actions
    .map(a => `• ${a.username}  →  ${ACTION_LABELS[a.action] || a.action}`)
    .join('\n');

  document.getElementById('confirmModalBody').innerHTML =
    `<p>You are about to execute <strong>${actions.length}</strong> action(s) across ` +
    `<strong>${uniqueUsers}</strong> user(s).</p>` +
    `<pre class="small border rounded p-2 bg-light">${esc(lines)}</pre>` +
    `<p><strong>Reason:</strong> ${esc(reason)}${comment ? ` &mdash; ${esc(comment)}` : ''}</p>` +
    `<p class="text-danger fw-bold mb-0">These actions cannot be undone. ` +
    `Processed users will be locked from re-selection.</p>`;

  _pendingExecute = async () => {
    const btn     = document.getElementById('csvExecuteBtn');
    const spinner = document.getElementById('csvExecuteSpinner');
    setSpinner(btn, spinner, true);
    try {
      const resp = await fetch('/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
        body: JSON.stringify({ actions }),
      });
      const data = await resp.json();
      if (data.error) { alert(data.error); return; }
      renderCsvExecResults(data.results || []);
      // Lock all executed users so they cannot be re-selected
      const executed = [...new Set(actions.map(a => a.username))];
      executed.forEach(u => _csvProcessed.add(u));
      if (_csvLastUsers) { renderCsvUserTable(_csvLastUsers); applyCsvFilters(); }
    } catch (err) {
      alert('Execute failed: ' + err);
    } finally {
      setSpinner(btn, spinner, false);
    }
  };

  confirmModal.show();
});

function renderCsvExecResults(results) {
  const tbody = document.getElementById('csvExecResultsTableBody');
  tbody.innerHTML = '';
  results.forEach(r => {
    const tr = document.createElement('tr');
    const rowClass   = r.result === 'success' ? 'table-success'
                     : r.result === 'warning' ? 'table-warning' : 'table-danger';
    const badgeClass = r.result === 'success' ? 'success'
                     : r.result === 'warning' ? 'warning text-dark' : 'danger';
    tr.classList.add(rowClass);
    tr.innerHTML = `
      <td class="font-monospace">${esc(r.username)}</td>
      <td>${esc(ACTION_LABELS[r.action] || r.action)}</td>
      <td><span class="badge bg-${badgeClass}">${esc(r.result)}</span></td>
      <td class="small">${esc(r.detail || '')}</td>
    `;
    tbody.appendChild(tr);
  });
  const sec = document.getElementById('csvExecResultsSection');
  sec.classList.remove('d-none');
  sec.scrollIntoView({ behavior: 'smooth' });
}

/* CSV filters ------------------------------------------------------------- */
function populateCsvDomainFilter(users) {
  const sel = document.getElementById('csvFilterDomain');
  const domains = [...new Set(
    users.filter(u => u.found && u.domain).map(u => u.domain)
  )].sort();
  sel.innerHTML = '<option value="">All Domains</option>' +
    domains.map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('');
}

function applyCsvFilters() {
  const domainVal    = document.getElementById('csvFilterDomain').value;
  const statusVal    = document.getElementById('csvFilterStatus').value;
  const processedVal = document.getElementById('csvFilterProcessed').value;
  let visible = 0, total = 0;

  document.querySelectorAll('#csvUserTableBody tr[data-username]').forEach(row => {
    total++;
    const username = row.dataset.username;
    const u = _csvLastUsers && _csvLastUsers.find(x => x.username === username);
    const isProcessed = _csvProcessed.has(username);
    let show = true;

    if (domainVal) {
      if (!u || !u.found || u.domain !== domainVal) show = false;
    }
    if (statusVal === 'notfound')  { if (u && u.found)                  show = false; }
    else if (statusVal === 'enabled')  { if (!u || !u.found || u.ad_disabled)  show = false; }
    else if (statusVal === 'disabled') { if (!u || !u.found || !u.ad_disabled) show = false; }

    if (processedVal === 'pending' && isProcessed)  show = false;
    if (processedVal === 'done'    && !isProcessed) show = false;

    row.classList.toggle('d-none', !show);
    if (show) visible++;
  });

  const countEl = document.getElementById('csvFilterCount');
  if (countEl) countEl.textContent = visible < total ? `Showing ${visible} of ${total}` : '';
}

['csvFilterDomain', 'csvFilterStatus', 'csvFilterProcessed'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('change', applyCsvFilters);
});
document.getElementById('csvFilterReset').addEventListener('click', () => {
  document.getElementById('csvFilterDomain').value    = '';
  document.getElementById('csvFilterStatus').value    = '';
  document.getElementById('csvFilterProcessed').value = '';
  applyCsvFilters();
});
