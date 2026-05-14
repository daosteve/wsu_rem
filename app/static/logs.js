'use strict';

let currentPage = 1;

document.getElementById('filterForm').addEventListener('submit', e => {
  e.preventDefault();
  currentPage = 1;
  loadLogs();
});

// Show the 25 most recent actions on page load
loadLogs();

// ── Remediate modal ───────────────────────────────────────────────────────────
document.getElementById('logTableBody').addEventListener('click', e => {
  const cell = e.target.closest('td.js-target-username');
  if (!cell) return;
  const username = cell.dataset.username;
  document.getElementById('remediateUsername').textContent = username;
  document.getElementById('remediateResult').innerHTML = '';
  document.getElementById('pwdSection').classList.add('d-none');
  document.getElementById('newPassword').value = '';
  document.getElementById('confirmPassword').value = '';
  document.getElementById('btnEnable').disabled      = false;
  document.getElementById('btnResetPwd').disabled    = false;
  document.getElementById('btnGwUnsuspend').disabled = false;
  bootstrap.Modal.getOrCreateInstance(document.getElementById('remediateModal')).show();
});

function postRemediate(username, action, password) {
  const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  const body = { username, action };
  if (password !== undefined) body.password = password;
  return fetch('/logs/remediate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken,
    },
    body: JSON.stringify(body),
  }).then(r => r.json());
}

function showRemediateResult(data) {
  const ok = data.result === 'success';
  document.getElementById('remediateResult').innerHTML =
    `<div class="alert alert-${ok ? 'success' : 'danger'} py-2 mb-0">
      <strong>${ok ? 'Success' : 'Error'}:</strong> ${esc(data.detail || data.error || '')}
    </div>`;
}

document.getElementById('btnEnable').addEventListener('click', () => {
  const username = document.getElementById('remediateUsername').textContent;
  document.getElementById('btnEnable').disabled   = true;
  document.getElementById('btnResetPwd').disabled = true;
  postRemediate(username, 'ad_enable')
    .then(showRemediateResult)
    .catch(err => { document.getElementById('remediateResult').innerHTML = `<div class="alert alert-danger py-2 mb-0">${esc(String(err))}</div>`; });
});

document.getElementById('btnGwUnsuspend').addEventListener('click', () => {
  const username = document.getElementById('remediateUsername').textContent;
  document.getElementById('btnEnable').disabled      = true;
  document.getElementById('btnResetPwd').disabled    = true;
  document.getElementById('btnGwUnsuspend').disabled = true;
  postRemediate(username, 'gw_unsuspend')
    .then(showRemediateResult)
    .catch(err => { document.getElementById('remediateResult').innerHTML = `<div class="alert alert-danger py-2 mb-0">${esc(String(err))}</div>`; });
});

document.getElementById('btnResetPwd').addEventListener('click', () => {
  // Reveal password fields instead of submitting immediately
  document.getElementById('pwdSection').classList.remove('d-none');
  document.getElementById('newPassword').focus();
});

document.getElementById('btnConfirmReset').addEventListener('click', () => {
  const username  = document.getElementById('remediateUsername').textContent;
  const pwd       = document.getElementById('newPassword').value;
  const pwdConfirm = document.getElementById('confirmPassword').value;
  if (!pwd) {
    document.getElementById('remediateResult').innerHTML =
      '<div class="alert alert-warning py-2 mb-0">Please enter a password.</div>';
    return;
  }
  if (pwd !== pwdConfirm) {
    document.getElementById('remediateResult').innerHTML =
      '<div class="alert alert-warning py-2 mb-0">Passwords do not match.</div>';
    return;
  }
  document.getElementById('btnEnable').disabled      = true;
  document.getElementById('btnResetPwd').disabled    = true;
  document.getElementById('btnConfirmReset').disabled = true;
  postRemediate(username, 'ad_reset_password', pwd)
    .then(data => {
      document.getElementById('pwdSection').classList.add('d-none');
      document.getElementById('newPassword').value = '';
      document.getElementById('confirmPassword').value = '';
      showRemediateResult(data);
    })
    .catch(err => { document.getElementById('remediateResult').innerHTML = `<div class="alert alert-danger py-2 mb-0">${esc(String(err))}</div>`; });
});
// ─────────────────────────────────────────────────────────────────────────────

function loadLogs(page) {
  if (page) currentPage = page;
  const params = new URLSearchParams(new FormData(document.getElementById('filterForm')));
  params.set('page', currentPage);
  fetch('/logs/search?' + params.toString())
    .then(r => r.json())
    .then(renderLogs)
    .catch(err => alert('Error loading logs: ' + err));
}

function renderLogs(data) {
  const tbody = document.getElementById('logTableBody');
  tbody.innerHTML = '';

  if (!data.rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No matching records.</td></tr>';
  } else {
    data.rows.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="text-nowrap small">${esc(r.timestamp)}</td>
        <td class="font-monospace small">${esc(r.operator)}</td>
        <td class="font-monospace small js-target-username" data-username="${esc(r.target_username)}" title="Click to remediate">${esc(r.target_username)}</td>
        <td><span class="badge bg-secondary">${esc(r.system)}</span></td>
        <td class="small">${esc(r.action.replace(/_/g, ' '))}</td>
        <td><span class="badge bg-${r.result === 'success' ? 'success' : 'danger'}">${esc(r.result)}</span></td>
        <td class="small text-truncate td-detail" title="${esc(r.detail)}">${esc(r.detail)}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  document.getElementById('totalCount').textContent =
    data.total ? `${data.total.toLocaleString()} record(s)` : '';

  const nav  = document.getElementById('paginationNav');
  const list = document.getElementById('paginationList');
  list.innerHTML = '';

  if (data.pages > 1) {
    nav.classList.remove('d-none');
    for (let p = 1; p <= data.pages; p++) {
      const li = document.createElement('li');
      li.className = 'page-item' + (p === data.page ? ' active' : '');
      li.innerHTML = `<a class="page-link" href="#" data-page="${p}">${p}</a>`;
      list.appendChild(li);
    }
    list.addEventListener('click', e => {
      e.preventDefault();
      const a = e.target.closest('a[data-page]');
      if (a) loadLogs(parseInt(a.dataset.page, 10));
    });
  } else {
    nav.classList.add('d-none');
  }
}

function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
