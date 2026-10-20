package main

import (
	"fmt"
)

func renderGetCodeHTML(rec *DeviceRecord, code string, rem int, src string) string {
	dispCode := code
	if dispCode == "" {
		dispCode = "------"
	}
	pct := (rem * 100) / 30
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Al Mino 2FA Code — %s</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0d1117; color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px;
  }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 16px;
    max-width: 440px; width: 100%%; padding: 28px; text-align: center;
    box-shadow: 0 12px 32px rgba(0,0,0,0.45);
  }
  .badge {
    display: inline-block; background: rgba(56,139,253,0.15); color: #58a6ff;
    border: 1px solid rgba(56,139,253,0.4); border-radius: 999px;
    padding: 4px 12px; font-size: 12px; font-weight: 600; margin-bottom: 12px;
  }
  .email { font-size: 15px; color: #8b949e; margin-bottom: 20px; word-break: break-all; }
  .code-box {
    background: #0d1117; border: 1px solid #30363d; border-radius: 12px;
    padding: 20px; font-size: 42px; font-weight: 800; letter-spacing: 8px;
    color: #3fb950; font-family: "Consolas", monospace; cursor: pointer;
    user-select: all; transition: transform 0.1s;
  }
  .code-box:active { transform: scale(0.98); }
  .progress-wrap {
    background: #21262d; height: 6px; border-radius: 4px; overflow: hidden; margin: 18px 0 10px;
  }
  .progress-bar {
    background: linear-gradient(90deg, #2ea043, #58a6ff); height: 100%%;
    width: %d%%; transition: width 0.4s linear;
  }
  .meta { font-size: 13px; color: #8b949e; margin-bottom: 18px; }
  .btn {
    background: #238636; color: #fff; border: none; border-radius: 8px;
    padding: 11px 20px; font-size: 14px; font-weight: 600; cursor: pointer; width: 100%%;
  }
  .btn:hover { background: #2ea043; }
</style>
</head>
<body>
<div class="card">
  <div class="badge">🍏 Al Mino (al-mino.site) &bull; MacBook Pro 2FA</div>
  <div class="email">%s</div>
  <div class="code-box" id="codeBox" onclick="copyCode()">%s</div>
  <div class="progress-wrap"><div class="progress-bar" id="bar"></div></div>
  <div class="meta">Refreshes in <b id="rem">%d</b>s &bull; Source: <span>%s</span></div>
  <button class="btn" id="copyBtn" onclick="copyCode()">📋 Copy 6-Digit Code</button>
</div>
<script>
const tokenKey = %q;
function copyCode() {
  const c = document.getElementById('codeBox').innerText.trim();
  if (!c || c.includes('-')) return;
  navigator.clipboard.writeText(c);
  const btn = document.getElementById('copyBtn');
  btn.innerText = '✅ Copied: ' + c;
  setTimeout(() => { btn.innerText = '📋 Copy 6-Digit Code'; }, 1500);
}
async function tick() {
  try {
    const r = await fetch('/api/getcode/' + encodeURIComponent(tokenKey));
    const d = await r.json();
    if (d && d.code) {
      document.getElementById('codeBox').innerText = d.code;
      document.getElementById('rem').innerText = d.remaining_seconds;
      document.getElementById('bar').style.width = ((d.remaining_seconds / 30) * 100) + '%%';
    }
  } catch(e) {}
}
setInterval(tick, 1000);
</script>
</body>
</html>`, rec.Email, pct, rec.Email, dispCode, rem, src, rec.TokenKey)
}

const webStudioHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🍏 Al Mino (al-mino.site) — Apple Mac Linker & 2FA Cloud</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0d1117; color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 16px;
  }
  .header {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 14px 20px; margin-bottom: 14px; gap: 12px;
  }
  .title { font-size: 18px; font-weight: 800; color: #58a6ff; }
  .stats { display: flex; gap: 10px; font-size: 12.5px; font-weight: 600; flex-wrap: wrap; align-items: center; }
  .stat-pill {
    background: #0d1117; border: 1px solid #30363d; border-radius: 999px; padding: 5px 12px;
  }
  .grid-top {
    display: grid; grid-template-columns: 1fr 340px; gap: 14px; margin-bottom: 14px;
  }
  @media (max-width: 900px) { .grid-top { grid-template-columns: 1fr; } }
  .panel {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 14px;
  }
  .panel h3 { font-size: 13px; color: #8b949e; text-transform: uppercase; margin-bottom: 10px; }
  textarea {
    width: 100%; height: 115px; background: #0d1117; color: #e6edf3;
    border: 1px solid #30363d; border-radius: 8px; padding: 10px;
    font-family: "Consolas", monospace; font-size: 12.5px; resize: vertical;
  }
  .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  button, .file-label {
    background: #21262d; color: #e6edf3; border: 1px solid #30363d; border-radius: 7px;
    padding: 8px 13px; font-size: 12.5px; font-weight: 600; cursor: pointer;
    display: inline-flex; align-items: center; gap: 5px;
  }
  button:hover, .file-label:hover { background: #30363d; border-color: #58a6ff; }
  .btn-green { background: #238636; border-color: #2ea043; color: #fff; }
  .btn-green:hover { background: #2ea043; }
  .btn-red { background: #da3633; border-color: #f85149; color: #fff; }
  .btn-red:hover { background: #f85149; }
  .btn-blue { background: #1f6feb; border-color: #388bfd; color: #fff; }
  .btn-blue:hover { background: #388bfd; }
  .ctrl-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; font-size: 13px; }
  input[type="number"], input[type="text"], input[type="password"], select {
    background: #0d1117; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 6px; padding: 7px 10px; font-weight: 600;
  }
  .table-wrap {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    overflow-x: auto; max-height: 460px; overflow-y: auto; margin-bottom: 14px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th {
    position: sticky; top: 0; background: #21262d; color: #58a6ff;
    text-align: left; padding: 10px; border-bottom: 1px solid #30363d; z-index: 1;
  }
  td { padding: 8px 10px; border-bottom: 1px solid #21262d; font-family: "Consolas", monospace; }
  tr:hover { background: rgba(56,139,253,0.06); }
  .code-pill {
    background: rgba(63,185,80,0.12); color: #3fb950; border: 1px solid rgba(63,185,80,0.35);
    padding: 3px 8px; border-radius: 6px; font-weight: 700; cursor: pointer;
  }
  .link-a { color: #58a6ff; text-decoration: none; cursor: pointer; }
  .link-a:hover { text-decoration: underline; }
  .log-box {
    background: #090d11; border: 1px solid #30363d; border-radius: 10px;
    padding: 10px; height: 150px; overflow-y: auto;
    font-family: "Consolas", monospace; font-size: 12px; color: #8b949e;
  }
  /* Login & Admin Modals */
  .overlay {
    position: fixed; inset: 0; background: rgba(1,4,9,0.88);
    display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 16px;
  }
  .modal-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 16px;
    max-width: 420px; width: 100%; padding: 26px; box-shadow: 0 16px 40px rgba(0,0,0,0.6);
  }
  .modal-wide { max-width: 680px; }
  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; font-size: 12.5px; color: #8b949e; margin-bottom: 6px; }
  .form-group input, .form-group select { width: 100%; }
</style>
</head>
<body>

<!-- LOGIN OVERLAY -->
<div class="overlay" id="loginOverlay" style="display:none">
  <div class="modal-card">
    <div style="text-align:center;margin-bottom:18px">
      <div style="font-size:32px;margin-bottom:6px">🍏</div>
      <h2 style="color:#58a6ff;font-size:20px">Al Mino Cloud Login</h2>
      <p style="color:#8b949e;font-size:13px;margin-top:4px">al-mino.site &bull; Virtual Mac Linker Studio</p>
    </div>
    <div class="form-group">
      <label>Username</label>
      <input type="text" id="loginUser" placeholder="Enter username..." onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="loginPass" placeholder="Enter password..." onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <div id="loginErr" style="color:#f85149;font-size:12.5px;margin-bottom:10px;display:none"></div>
    <button class="btn-green" style="width:100%;justify-content:center;padding:11px" onclick="doLogin()">🔐 Sign In</button>
  </div>
</div>

<!-- ADMIN USERS MANAGER MODAL -->
<div class="overlay" id="usersModal" style="display:none">
  <div class="modal-card modal-wide">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <h3 style="color:#58a6ff">👥 Users & Credits Manager (Admin)</h3>
      <button onclick="document.getElementById('usersModal').style.display='none'">✖ Close</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 110px 100px auto;gap:8px;margin-bottom:14px;align-items:end">
      <div>
        <label style="font-size:11px;color:#8b949e">Username</label>
        <input type="text" id="uName" placeholder="user1" style="width:100%">
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e">Password</label>
        <input type="text" id="uPass" placeholder="pass123" style="width:100%">
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e">Credits</label>
        <input type="number" id="uCredits" value="100" style="width:100%">
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e">Role</label>
        <select id="uRole" style="width:100%">
          <option value="USER">USER</option>
          <option value="ADMIN">ADMIN</option>
        </select>
      </div>
      <button class="btn-green" onclick="saveUser()">➕ Save User</button>
    </div>
    <div class="table-wrap" style="max-height:260px;margin-bottom:0">
      <table>
        <thead>
          <tr><th>Username</th><th>Password</th><th>Role</th><th>Credits</th><th>Action</th></tr>
        </thead>
        <tbody id="usersTbody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="header">
  <div class="title">⚡ Al Mino (al-mino.site) — Apple Mac Linker & 2FA Cloud</div>
  <div class="stats">
    <div class="stat-pill">👤 <span id="stUser" style="color:#58a6ff">-</span> (<span id="stCredits" style="color:#3fb950">0</span>)</div>
    <div class="stat-pill">🚀 Goroutines: <span id="stGoroutines" style="color:#58a6ff">0</span></div>
    <div class="stat-pill">🍏 Ready Macs: <span id="stPrewarm" style="color:#3fb950">0</span></div>
    <div class="stat-pill">Total: <span id="stTotal">0</span></div>
    <div class="stat-pill" style="color:#3fb950">✅ Linked: <span id="stLinked">0</span></div>
    <div class="stat-pill" style="color:#f85149">❌ Failed: <span id="stFailed">0</span></div>
    <button id="btnAdminUsers" class="btn-blue" style="display:none;padding:5px 11px" onclick="openUsersModal()">👥 Users</button>
    <button style="padding:5px 11px" onclick="doLogout()">🚪 Logout</button>
  </div>
</div>

<div class="grid-top">
  <div class="panel">
    <h3>1. Paste Accounts (Single-Line or Multi-Line Format)</h3>
    <textarea id="rawInput" placeholder="email@hotmail.com&#9;Password123#&#9;19482064708&#9;https://xsd20vip.com/sms-record?token=...&#10;OR multi-line:&#10;email@hotmail.com&#10;Password123#&#10;19482064708 https://xsd20vip.com/sms-record?token=..."></textarea>
    <div class="btn-row">
      <button class="btn-blue" onclick="addAccounts()">➕ Add to Queue</button>
      <button onclick="pasteClipboard()">📋 Paste & Add</button>
      <label class="file-label">📂 Load File (.txt/.csv)<input type="file" accept=".txt,.csv" style="display:none" onchange="loadFile(event)"></label>
      <button onclick="clearTable()">🗑 Clear Table</button>
    </div>
  </div>

  <div class="panel">
    <h3>2. Golang Goroutine Engine Controls</h3>
    <div class="ctrl-row">
      <span>Concurrent Goroutines (Threads):</span>
      <input type="number" id="numThreads" value="100" min="1" max="5000" style="width:110px">
    </div>
    <div class="ctrl-row">
      <span>SMS Polling Timeout (sec):</span>
      <input type="number" id="smsTimeout" value="45" min="15" max="180" style="width:110px">
    </div>
    <div class="btn-row" style="margin-top:14px">
      <button class="btn-green" style="flex:1;justify-content:center" onclick="startLinking()">🚀 Start Linking All</button>
      <button class="btn-red" onclick="stopLinking()">⏹ Stop</button>
    </div>
    <div class="btn-row">
      <button onclick="retryFailed()">🔄 Retry Failed</button>
      <button onclick="copyAllLinked()">📋 Copy All Linked</button>
      <button onclick="exportLinked()">💾 Export .TXT</button>
    </div>
  </div>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Apple ID (Email)</th>
        <th>Password</th>
        <th>Phone</th>
        <th>SMS OTP Link</th>
        <th>Status</th>
        <th>SMS Code</th>
        <th>Live Mac Code (30s)</th>
        <th>Permanent GetCode Link (Click to Copy)</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<div class="log-box" id="logBox"></div>

<script>
let currentJobs = [];
let authToken = localStorage.getItem('almino_token') || '';

function authHeaders() {
  return {
    'Content-Type': 'application/json',
    'X-Auth-Token': authToken
  };
}

async function doLogin() {
  const u = document.getElementById('loginUser').value.trim();
  const p = document.getElementById('loginPass').value.trim();
  const errEl = document.getElementById('loginErr');
  errEl.style.display = 'none';
  try {
    const r = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    const d = await r.json();
    if (!r.ok || !d.ok) {
      errEl.innerText = d.error || 'Invalid credentials';
      errEl.style.display = 'block';
      return;
    }
    authToken = d.token;
    localStorage.setItem('almino_token', authToken);
    document.getElementById('loginOverlay').style.display = 'none';
    refreshState();
  } catch(e) {
    errEl.innerText = 'Connection error';
    errEl.style.display = 'block';
  }
}

function doLogout() {
  authToken = '';
  localStorage.removeItem('almino_token');
  document.cookie = 'almino_token=; Max-Age=0; path=/';
  document.getElementById('loginOverlay').style.display = 'flex';
}

async function openUsersModal() {
  document.getElementById('usersModal').style.display = 'flex';
  loadUsersList();
}

async function loadUsersList() {
  const r = await fetch('/api/v1/admin/users', {headers: authHeaders()});
  if (!r.ok) return;
  const d = await r.json();
  const users = d.users || [];
  let html = '';
  for (const u of users) {
    html += '<tr>' +
      '<td><b>' + u.username + '</b></td>' +
      '<td>' + u.password + '</td>' +
      '<td>' + u.role + '</td>' +
      '<td>' + (u.role === 'ADMIN' ? '∞ Unlimited' : u.credits) + '</td>' +
      '<td>' + (u.username !== 'mina' ? '<button class="btn-red" style="padding:3px 8px" onclick="deleteUser(\'' + u.username + '\')">Delete</button>' : '-') + '</td>' +
    '</tr>';
  }
  document.getElementById('usersTbody').innerHTML = html;
}

async function saveUser() {
  const username = document.getElementById('uName').value.trim();
  const password = document.getElementById('uPass').value.trim();
  const credits = parseInt(document.getElementById('uCredits').value || '0', 10);
  const role = document.getElementById('uRole').value;
  if (!username || !password) return alert('Enter username and password');
  await fetch('/api/v1/admin/users/upsert', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({username, password, credits, role})
  });
  document.getElementById('uName').value = '';
  document.getElementById('uPass').value = '';
  loadUsersList();
}

async function deleteUser(username) {
  await fetch('/api/v1/admin/users/delete', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({username})
  });
  loadUsersList();
}

async function addAccounts() {
  const raw = document.getElementById('rawInput').value.trim();
  if (!raw) return;
  await fetch('/api/v1/linker/add', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({raw_text: raw})
  });
  document.getElementById('rawInput').value = '';
  refreshState();
}

async function pasteClipboard() {
  try {
    const t = await navigator.clipboard.readText();
    if (t && t.trim()) {
      document.getElementById('rawInput').value = t.trim();
      await addAccounts();
    }
  } catch(e) {}
}

function loadFile(ev) {
  const f = ev.target.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = async (e) => {
    document.getElementById('rawInput').value = e.target.result;
    await addAccounts();
  };
  reader.readAsText(f);
}

async function startLinking() {
  const raw = document.getElementById('rawInput').value.trim();
  const threads = parseInt(document.getElementById('numThreads').value || '100', 10);
  const timeout = parseInt(document.getElementById('smsTimeout').value || '45', 10);
  const r = await fetch('/api/v1/linker/start', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({threads: threads, sms_timeout: timeout, raw_text: raw})
  });
  if (r.status === 403) {
    alert('No credits remaining on your account!');
  }
  document.getElementById('rawInput').value = '';
  refreshState();
}

async function stopLinking() {
  await fetch('/api/v1/linker/stop', {method: 'POST', headers: authHeaders()});
  refreshState();
}

async function retryFailed() {
  const threads = parseInt(document.getElementById('numThreads').value || '100', 10);
  const timeout = parseInt(document.getElementById('smsTimeout').value || '45', 10);
  await fetch('/api/v1/linker/retry', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({threads: threads, sms_timeout: timeout})
  });
  refreshState();
}

async function clearTable() {
  await fetch('/api/v1/linker/clear', {method: 'POST', headers: authHeaders()});
  refreshState();
}

function copyText(txt) {
  if (!txt) return;
  navigator.clipboard.writeText(txt);
}

function copyAllLinked() {
  const lines = currentJobs
    .filter(j => (j.status || '').includes('LINKED'))
    .map(j => j.phone ? (j.email + ',' + j.password + ',' + j.phone + ',' + j.getcode_url) : (j.email + ',' + j.password + ',' + j.getcode_url));
  if (!lines.length) return alert('No linked accounts yet.');
  navigator.clipboard.writeText(lines.join('\n'));
  alert('Copied ' + lines.length + ' linked account(s)!');
}

function exportLinked() {
  const lines = currentJobs
    .filter(j => (j.status || '').includes('LINKED'))
    .map(j => j.email + ',' + j.password + ',' + (j.phone || '') + ',' + j.getcode_url);
  if (!lines.length) return alert('No linked accounts yet.');
  const blob = new Blob([lines.join('\n') + '\n'], {type: 'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'linked_mac_accounts.txt';
  a.click();
}

async function refreshState() {
  if (!authToken) {
    document.getElementById('loginOverlay').style.display = 'flex';
    return;
  }
  try {
    const r = await fetch('/api/v1/linker/state', {headers: authHeaders()});
    if (r.status === 401) {
      document.getElementById('loginOverlay').style.display = 'flex';
      return;
    }
    document.getElementById('loginOverlay').style.display = 'none';
    const d = await r.json();
    currentJobs = d.jobs || [];
    document.getElementById('stUser').innerText = d.user || '-';
    document.getElementById('stCredits').innerText = d.role === 'ADMIN' ? '∞ ADMIN' : (d.credits + ' Credits');
    document.getElementById('btnAdminUsers').style.display = d.role === 'ADMIN' ? 'inline-flex' : 'none';
    document.getElementById('stGoroutines').innerText = d.active_goroutines || 0;
    document.getElementById('stPrewarm').innerText = d.prewarmed_macs || 0;
    document.getElementById('stTotal').innerText = d.total || 0;
    document.getElementById('stLinked').innerText = d.linked || 0;
    document.getElementById('stFailed').innerText = d.failed || 0;

    const tbody = document.getElementById('tbody');
    let html = '';
    for (let i = 0; i < currentJobs.length; i++) {
      const j = currentJobs[i];
      const shortOtp = j.otp_url ? (j.otp_url.length > 34 ? j.otp_url.substring(0, 34) + '...' : j.otp_url) : '-';
      const pureCode = (j.live_code || '').split(' ')[0];
      html += '<tr>' +
        '<td>' + (i + 1) + '</td>' +
        '<td>' + (j.email || '') + '</td>' +
        '<td>' + (j.password || '') + '</td>' +
        '<td>' + (j.phone || '-') + '</td>' +
        '<td title="' + (j.otp_url || '') + '">' + shortOtp + '</td>' +
        '<td style="color:' + (j.status_hex || '#e6edf3') + ';font-weight:700">' + (j.status || '') + '</td>' +
        '<td style="color:#3fb950;font-weight:700">' + (j.sms_code || '-') + '</td>' +
        '<td>' + (j.live_code && j.live_code !== '-' ? '<span class="code-pill" onclick="copyText(\'' + pureCode + '\')">' + j.live_code + '</span>' : '-') + '</td>' +
        '<td>' + (j.getcode_url ? '<span class="link-a" onclick="copyText(\'' + j.getcode_url + '\')">' + j.getcode_url + '</span> &nbsp;<a class="link-a" href="' + j.getcode_url + '" target="_blank">↗</a>' : '') + '</td>' +
      '</tr>';
    }
    tbody.innerHTML = html;

    const lb = document.getElementById('logBox');
    lb.innerText = (d.logs || []).join('\n');
    lb.scrollTop = lb.scrollHeight;
  } catch(e) {}
}

setInterval(refreshState, 1000);
refreshState();
</script>
</body>
</html>`
