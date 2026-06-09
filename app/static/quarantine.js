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
  return Array.from(document.querySelectorAll('input[type=checkbox]:checked'))
    .map(cb => {
      const row = cb.closest('tr');
      const reason  = row ? row.querySelector('.qr-reason')?.value  : '';
      const comment = row ? row.querySelector('.qr-comment')?.value : '';
      return { username: cb.dataset.user, action: cb.dataset.action, reason, comment };
    });
}

/* ── Lookup ─────────────────────────────────────────────────────────────── */
const MAX_USERNAMES = 20;

function countUsernames(text) {
  return text.trim() ? text.trim().split(/[\s,;]+/).filter(u => u.length > 0).length : 0;
}

const usernameInput = document.getElementById('usernameInput');
const usernameCount = document.getElementById('usernameCount');
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
    const text = document.getElementById('usernameInput').value.trim();
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

document.getElementById('executeBtn').addEventListener('click', () => {
  const actions = gatherActions();
  if (!actions.length) { alert('Select at least one action.'); return; }

  // Require a quarantine reason for rows with at least one non-exempt action checked
  let missingReason = false;
  const rowsNeedingReason = new Set();
  document.querySelectorAll('input[type=checkbox]:checked').forEach(cb => {
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
