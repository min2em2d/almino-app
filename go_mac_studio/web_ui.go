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
<title>Apple 2FA Code — %s</title>
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
<title>🍏 Apple Virtual Mac Linker Studio & 2FA Cloud (Golang Edition)</title>
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
  .stats { display: flex; gap: 14px; font-size: 13px; font-weight: 600; flex-wrap: wrap; }
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
  input[type="number"] {
    background: #0d1117; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 6px; padding: 6px 10px; width: 110px; font-weight: 700;
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
</style>
</head>
<body>

<div class="header">
  <div class="title">⚡ Al Mino (al-mino.site) — Apple Mac Linker & 2FA Cloud (Golang Edition)</div>
  <div class="stats">
    <div class="stat-pill">🚀 Goroutines: <span id="stGoroutines" style="color:#58a6ff">0</span></div>
    <div class="stat-pill">🍏 Pre-Warmed Macs: <span id="stPrewarm" style="color:#3fb950">0</span></div>
    <div class="stat-pill">Total: <span id="stTotal">0</span></div>
    <div class="stat-pill" style="color:#3fb950">✅ Linked: <span id="stLinked">0</span></div>
    <div class="stat-pill" style="color:#f85149">❌ Failed: <span id="stFailed">0</span></div>
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
      <input type="number" id="numThreads" value="100" min="1" max="5000">
    </div>
    <div class="ctrl-row">
      <span>SMS Polling Timeout (sec):</span>
      <input type="number" id="smsTimeout" value="45" min="15" max="180">
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

async function addAccounts() {
  const raw = document.getElementById('rawInput').value.trim();
  if (!raw) return;
  await fetch('/api/v1/linker/add', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
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
  await fetch('/api/v1/linker/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({threads: threads, sms_timeout: timeout, raw_text: raw})
  });
  document.getElementById('rawInput').value = '';
  refreshState();
}

async function stopLinking() {
  await fetch('/api/v1/linker/stop', {method: 'POST'});
  refreshState();
}

async function retryFailed() {
  const threads = parseInt(document.getElementById('numThreads').value || '100', 10);
  const timeout = parseInt(document.getElementById('smsTimeout').value || '45', 10);
  await fetch('/api/v1/linker/retry', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({threads: threads, sms_timeout: timeout})
  });
  refreshState();
}

async function clearTable() {
  await fetch('/api/v1/linker/clear', {method: 'POST'});
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
  try {
    const r = await fetch('/api/v1/linker/state');
    const d = await r.json();
    currentJobs = d.jobs || [];
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
