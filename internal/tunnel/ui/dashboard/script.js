'use strict';

// ── CSRF helper ────────────────────────────────
// Reads the gotunnel_csrf cookie set by the server on every authenticated
// response and includes it in all state-changing POST requests.
function getCsrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)gotunnel_csrf=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : '';
}

// ── State ──────────────────────────────────────
let activeTunnel = null;
let currentTab = 'overview';
let allReqs    = [];
let tunnelsMap = {};
let totalEver  = 0;

// ── DOM refs ───────────────────────────────────
const $list     = document.getElementById('req-list');
const $empty    = document.getElementById('empty-state');
const $tCount   = document.getElementById('t-count');
const $tunConns = document.getElementById('tun-conns');
const $tunType  = document.getElementById('tun-type');
const $tunProxy = document.getElementById('tun-proxyurl');
const $uptime   = document.getElementById('uptime');
const $tunList  = document.getElementById('tunnel-list');
const $apiVal   = document.getElementById('api-val');
const $chipLbl  = document.getElementById('filter-label');
const $sidebar  = document.getElementById('sidebar');
const $backdrop = document.getElementById('sidebar-backdrop');
const $hamburger = document.getElementById('hamburger-btn');

// ── Navigation ─────────────────────────────────
function switchTab(tab) {
  if (!activeTunnel) return;
  currentTab = tab;
  document.getElementById('tab-overview').classList.toggle('active', tab === 'overview');
  document.getElementById('tab-inspector').classList.toggle('active', tab === 'inspector');
  
  document.getElementById('view-overview').style.display = tab === 'overview' ? 'flex' : 'none';
  document.getElementById('view-inspector').style.display = tab === 'inspector' ? 'flex' : 'none';
}

// ── Mobile sidebar drawer ───────────────────────
function openSidebar() {
  $sidebar.classList.add('open');
  $backdrop.classList.add('show');
  $hamburger.setAttribute('aria-expanded', 'true');
}
function closeSidebar() {
  $sidebar.classList.remove('open');
  $backdrop.classList.remove('show');
  $hamburger.setAttribute('aria-expanded', 'false');
}
function toggleSidebar() {
  $sidebar.classList.contains('open') ? closeSidebar() : openSidebar();
}
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeSidebar();
});

function selectTunnel(ep) {
  _maskApiKey();
  _baCreds         = { user: '', pass: '' };
  _baEditOpen      = false;
  _baPendingEnable = false;
  _baMaskCreds();
  activeTunnel = ep;
  document.querySelectorAll('.tunnel-entry').forEach(el => {
    el.classList.toggle('active', el.dataset.ep === ep);
  });
  closeSidebar(); // no-op on desktop; collapses the drawer on mobile after a pick

  if (!ep) {
    document.getElementById('nav-tabs').style.display = 'none';
    document.getElementById('view-empty').style.display = 'flex';
    document.getElementById('view-overview').style.display = 'none';
    document.getElementById('view-inspector').style.display = 'none';
    document.getElementById('tunnel-auth-section').style.display = 'none';
    return;
  }

  document.getElementById('nav-tabs').style.display = 'flex';
  document.getElementById('view-empty').style.display = 'none';
  switchTab(currentTab);
  renderTunnelOverview();

  $chipLbl.textContent = ep;
  renderAll();
}

function renderTunnelOverview() {
  const t = tunnelsMap[activeTunnel];
  if (!t) return;
  $tunProxy.textContent = t.proxy_url || '—';
  $tunType.textContent = t.type || '—';
  $tunConns.textContent = t.connections;
  document.getElementById('tun-clientip').textContent = (t.client_ip || '—').replace(/(:\d+)$/, '').replace(/^\[|\]$/g, '');

  document.getElementById('tunnel-auth-section').style.display = 'contents';

  _syncAIModeUI(t);

  // Sync API key state
  const apikeyEnabled = !!t.apikey_enabled;
  document.getElementById('apikey-toggle').checked = apikeyEnabled;
  _setApikeyStatus(apikeyEnabled);
  if (!apikeyEnabled) _maskApiKey();

  // Basic Auth — skip all DOM writes while the user is in the edit flow.
  if (!_baEditOpen && !_baPendingEnable) {
    const baEnabled = !!t.basicauth_enabled;
    document.getElementById('basicauth-toggle').checked = baEnabled;
    _setBasicAuthStatus(baEnabled);
    if (baEnabled) {
      _baShowEditForm(false);
      _baShowCredView(true);
      // Refresh curl snippet if creds are cached
      if (_baCreds.user) _updateBaCurlSnippet(_baCreds.user, _baCreds.pass);
    } else {
      _baShowCredView(false);
      _baShowEditForm(false);
    }
  }
}

// ── Helpers ────────────────────────────────────
function fmtTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtDur(ms) {
  if (ms < 1000) return ms + 'ms';
  return (ms / 1000).toFixed(2) + 's';
}
function fmtUptime(s) {
  if (s < 60)   return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s%60) + 's';
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60);
  return h + 'h ' + m + 'm';
}
function statusCls(code) {
  if (code < 300) return 's2';
  if (code < 400) return 's3';
  if (code < 500) return 's4';
  return 's5';
}
function esc(s) {
  const d = document.createElement('div');
  d.textContent = String(s ?? '');
  return d.innerHTML;
}
function hdrsHtml(h) {
  if (!h || !Object.keys(h).length) return '<span style="opacity:.4">none</span>';
  return Object.entries(h).map(([k, vs]) =>
    vs.map(v => `<span class="hdr-k">${esc(k)}</span>: ${esc(v)}`).join('<br>')
  ).join('<br>');
}

// ── Token ──────────────────────────────────────
// The token is NEVER stored in a JS variable at module scope.
// • tokenReveal() fetches /api/token, shows it for 30 s then re-masks.
// • tokenCopy()   fetches /api/token, writes to clipboard, token then goes
//   out of scope — nothing persists in memory between clicks.
// CSP connect-src 'self' means even if injected JS calls /api/token, it
// cannot send the result anywhere external.

let _tokenHideTimer = null;

function tokenReveal() {
  const val = document.getElementById('nav-token-val');
  const btn = document.getElementById('token-reveal-btn');

  // If already revealed, re-mask immediately
  if (!val.classList.contains('masked')) {
    _maskToken();
    return;
  }

  fetch('/api/token')
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(data => {
      if (!data.token) return;
      val.textContent = data.token;
      val.classList.remove('masked');
      btn.title = 'Hide';

      // Auto-hide after 30 s
      clearTimeout(_tokenHideTimer);
      _tokenHideTimer = setTimeout(_maskToken, 30000);
    })
    .catch(() => {});
}

function _maskToken() {
  const val = document.getElementById('nav-token-val');
  const btn = document.getElementById('token-reveal-btn');
  if (!val) return;
  val.textContent = '••••••••';
  val.classList.add('masked');
  if (btn) btn.title = 'Reveal';
  clearTimeout(_tokenHideTimer);
}

function tokenCopy() {
  const chip = document.getElementById('nav-token-chip');

  fetch('/api/token')
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(data => {
      const tok = data.token;
      if (!tok) return;
      const done = () => {
        chip.classList.add('ok');
        setTimeout(() => chip.classList.remove('ok'), 1800);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(tok).then(done).catch(() => _fallbackCopy(tok, done));
      } else {
        _fallbackCopy(tok, done);
      }
      // tok goes out of scope here — never stored globally
    })
    .catch(() => {});
}

function _fallbackCopy(tok, cb) {
  const ta = document.createElement('textarea');
  ta.value = tok;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:absolute;left:-9999px';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); cb(); } catch(e) {}
  document.body.removeChild(ta);
  // tok goes out of scope
}

// ── API Key ─────────────────────────────────────
// Same security model as the server token:
// - Never stored in a JS global variable
// - Fetched from /api/tunnels/apikey?endpoint=X only on explicit user action
// - Auto-hides after 30 s when revealed
// - CSP connect-src 'self' blocks exfiltration even if injected JS calls the endpoint

let _apikeyHideTimer = null;

function _apikeyEndpoint() {
  return encodeURIComponent(activeTunnel || '(default)');
}

// ── Toast notifications ─────────────────────────────────
function showToast(msg, type = 'info', duration = 3000) {
  const icons = { success: '✓', error: '✗', info: 'ℹ' };
  const c = document.getElementById('toast-container');
  if (!c) return;
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span><span class="toast-msg">${esc(msg)}</span>`;
  c.appendChild(t);
  setTimeout(() => {
    t.style.animation = 'toastOut .2s ease forwards';
    setTimeout(() => t.remove(), 220);
  }, duration);
}

// ── AI Optimization ─────────────────────────────────────
function aiModeToggleChanged() {
  const enabled = document.getElementById('aimode-toggle').checked;
  const ep = activeTunnel || '(default)';
  _setAIModeStatus(enabled);
  if (tunnelsMap[ep]) tunnelsMap[ep].aimode_enabled = enabled;

  fetch('/api/tunnels/aimode', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()},
    body: JSON.stringify({ endpoint: ep, enabled })
  })
  .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
  .then(data => {
    if (tunnelsMap[ep]) tunnelsMap[ep].aimode_enabled = data.enabled;
    _setAIModeStatus(data.enabled);
    showToast(data.enabled ? 'AI Optimization enabled' : 'AI Optimization disabled', data.enabled ? 'success' : 'info');
  })
  .catch(() => {
    const reverted = !enabled;
    document.getElementById('aimode-toggle').checked = reverted;
    if (tunnelsMap[ep]) tunnelsMap[ep].aimode_enabled = reverted;
    _setAIModeStatus(reverted);
    showToast('Failed to update AI Optimization', 'error');
  });
}

function _setAIModeStatus(enabled) {
  const badge = document.getElementById('aimode-badge');
  if (badge) {
    badge.textContent = enabled ? 'Active' : 'Off';
    badge.className = 'card-section-badge ' + (enabled ? 'active' : 'disabled');
  }
  // Update feature pills
  function setFeat(id, onText, offText, isOn) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = isOn ? onText : offText;
    el.className = 'feat-pill ' + (isOn ? 'on' : 'off');
  }
  setFeat('ai-feat-body',  '100 MB',   '10 MB',   enabled);
  setFeat('ai-feat-flush', '512 B',    '32 KB',   enabled);
  setFeat('ai-feat-cors',  'Enabled',  'Disabled', enabled);
  setFeat('ai-feat-buf',   'Disabled', 'Enabled',  enabled);
}

function _syncAIModeUI(t) {
  const enabled = !!t.aimode_enabled;
  document.getElementById('aimode-toggle').checked = enabled;
  _setAIModeStatus(enabled);
}

function _setApikeyStatus(enabled) {
  const badge = document.getElementById('apikey-badge');
  if (badge) {
    badge.textContent = enabled ? 'Active' : 'Off';
    badge.className = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled');
  }
  const ctrl = document.getElementById('apikey-controls');
  const dis  = document.getElementById('apikey-disabled-msg');
  if (ctrl) ctrl.style.display = enabled ? 'block' : 'none';
  if (dis)  dis.style.display  = enabled ? 'none'  : 'block';
}

// Custom key input strength checker
function apikeyCustomInputChanged() {
  const val = document.getElementById('apikey-custom-input').value.trim();
  const bar = document.getElementById('apikey-strength-bar');
  const lbl = document.getElementById('apikey-strength-label');
  const btn = document.getElementById('apikey-custom-save');
  if (!val) {
    if (bar) bar.style.display = 'none';
    if (lbl) lbl.textContent = '';
    if (btn) btn.disabled = true;
    return;
  }
  if (bar) bar.style.display = 'flex';
  const score = _keyStrength(val);
  const levels = ['','weak','fair','good','strong'];
  const labels = ['','Weak — too short or simple','Fair — consider adding symbols','Good — solid key','Strong — excellent'];
  for (let i = 1; i <= 4; i++) {
    const seg = document.getElementById('aks-' + i);
    if (seg) seg.className = 'strength-seg ' + (i <= score ? levels[score] : '');
  }
  if (lbl) { lbl.textContent = labels[score]; lbl.className = 'strength-label ' + levels[score]; }
  if (btn) btn.disabled = score < 2;
}

function _keyStrength(k) {
  if (k.length < 8) return 1;
  let score = 1;
  if (k.length >= 16) score++;
  if (/[A-Z]/.test(k) && /[a-z]/.test(k)) score++;
  if (/[0-9]/.test(k) && /[^A-Za-z0-9]/.test(k)) score++;
  return Math.min(score, 4);
}

function apikeyCustomSave() {
  const inp = document.getElementById('apikey-custom-input');
  const key = (inp ? inp.value.trim() : '');
  if (!key) return;
  const ep = activeTunnel || '(default)';
  fetch('/api/tunnels/auth', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()},
    body: JSON.stringify({ endpoint: ep, enabled: true, apikey: key })
  })
  .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
  .then(data => {
    if (tunnelsMap[ep]) { tunnelsMap[ep].apikey_enabled = true; tunnelsMap[ep].has_apikey = true; }
    _setApikeyStatus(true);
    // Show the newly set key
    const val = document.getElementById('api-val');
    if (val) { val.textContent = data.apikey; val.classList.remove('masked'); }
    const revBtn = document.getElementById('api-reveal');
    if (revBtn) revBtn.title = 'Hide';
    clearTimeout(_apikeyHideTimer);
    _apikeyHideTimer = setTimeout(_maskApiKey, 30000);
    if (inp) inp.value = '';
    apikeyCustomInputChanged();
    showToast('Custom API key applied', 'success');
  })
  .catch(() => showToast('Failed to set custom key', 'error'));
}

// ── API Key ─────────────────────────────────────────────
function apikeyToggleChanged() {
  const enabled = document.getElementById('apikey-toggle').checked;
  const ep = activeTunnel || '(default)';
  if (tunnelsMap[ep]) {
    tunnelsMap[ep].apikey_enabled = enabled;
  }
  _setApikeyStatus(enabled);
  if (!enabled) _maskApiKey();

  fetch('/api/tunnels/auth', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()},
    body: JSON.stringify({ endpoint: ep, enabled })
  })
  .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
  .then(data => {
    if (tunnelsMap[ep]) {
      tunnelsMap[ep].apikey_enabled = data.enabled;
      tunnelsMap[ep].has_apikey = !!data.apikey;
    }
    _setApikeyStatus(data.enabled);
    if (!data.enabled) _maskApiKey();
    showToast(data.enabled ? 'API key authentication enabled' : 'API key authentication disabled', data.enabled ? 'success' : 'info');
  })
  .catch(() => {
    const reverted = !enabled;
    document.getElementById('apikey-toggle').checked = reverted;
    if (tunnelsMap[ep]) tunnelsMap[ep].apikey_enabled = reverted;
    _setApikeyStatus(reverted);
    showToast('Failed to update API key', 'error');
  });
}

function apiReveal() {
  const val = document.getElementById('api-val');
  const btn = document.getElementById('api-reveal');
  if (!val.classList.contains('masked')) { _maskApiKey(); return; }
  fetch('/api/tunnels/apikey?endpoint=' + _apikeyEndpoint())
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(data => {
      if (!data.apikey) return;
      val.textContent = data.apikey;
      val.classList.remove('masked');
      if (btn) btn.title = 'Hide';
      clearTimeout(_apikeyHideTimer);
      _apikeyHideTimer = setTimeout(_maskApiKey, 30000);
    })
    .catch(() => showToast('Could not fetch API key', 'error'));
}

function _maskApiKey() {
  const val = document.getElementById('api-val');
  const btn = document.getElementById('api-reveal');
  if (!val) return;
  val.textContent = '••••••••••••••••••••••••••••••••';
  val.classList.add('masked');
  if (btn) btn.title = 'Reveal';
  clearTimeout(_apikeyHideTimer);
}

function apiCopy() {
  fetch('/api/tunnels/apikey?endpoint=' + _apikeyEndpoint())
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(data => {
      const key = data.apikey;
      if (!key) return;
      const done = () => {
        const btn = document.getElementById('api-copy');
        if (btn) { btn.classList.add('ok'); setTimeout(() => btn.classList.remove('ok'), 1800); }
        showToast('API key copied to clipboard', 'success');
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(key).then(done).catch(() => _apikeyFallbackCopy(key, done));
      } else {
        _apikeyFallbackCopy(key, done);
      }
    })
    .catch(() => showToast('Could not copy API key', 'error'));
}

function apiRegenerate() {
  const btn = document.getElementById('api-regen');
  if (!confirm('Regenerate API key for this tunnel? Existing clients will need the new key.')) return;
  btn.disabled = true;
  fetch('/api/tunnels/auth', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()},
    body: JSON.stringify({ endpoint: activeTunnel || '(default)', enabled: true, regenerate: true })
  })
  .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
  .then(data => {
    const val = document.getElementById('api-val');
    val.textContent = data.apikey;
    val.classList.remove('masked');
    document.getElementById('api-reveal').title = 'Hide';
    clearTimeout(_apikeyHideTimer);
    _apikeyHideTimer = setTimeout(_maskApiKey, 30000);
    const ep = activeTunnel || '(default)';
    if (tunnelsMap[ep]) { tunnelsMap[ep].has_apikey = true; tunnelsMap[ep].apikey_enabled = true; }
    _setApikeyStatus(true);
    showToast('API key regenerated', 'success');
  })
  .catch(() => showToast('Failed to regenerate key', 'error'))
  .finally(() => { btn.disabled = false; });
}

function _apikeyFallbackCopy(key, cb) {
  const ta = document.createElement('textarea');
  ta.value = key;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:absolute;left:-9999px';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); cb(); } catch(e) {}
  document.body.removeChild(ta);
}

function _setBasicAuthStatus(enabled) {
  const badge = document.getElementById('basicauth-badge');
  if (badge) {
    badge.textContent = enabled ? 'Active' : 'Off';
    badge.className = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled');
  }
  const dis = document.getElementById('basicauth-disabled-msg');
  if (dis) dis.style.display = enabled ? 'none' : 'block';
}

// ── Basic Auth state ────────────────────────────────────
// _baCreds: plaintext creds cached after first fetch/save — cleared on switch
// _baEditOpen: true while the edit form is open — blocks SSE ticks from
//              closing it while the user is typing
let _baCreds        = { user: '', pass: '' };
let _baEditOpen     = false;   // edit form is visible — blocks SSE from resetting panels
let _baPendingEnable = false;  // toggle just flipped ON — blocks SSE from resetting checkbox
let _baUserRevealed = false;
let _baPassRevealed = false;

function _baMaskCreds() {
  _baUserRevealed = false; _baPassRevealed = false;
  const u = document.getElementById('ba-user-val');
  const p = document.getElementById('ba-pass-val');
  if (u) u.textContent = '••••••';
  if (p) p.textContent = '••••••••';
  const br1 = document.getElementById('ba-user-reveal');
  const br2 = document.getElementById('ba-pass-reveal');
  if (br1) br1.title = 'Reveal';
  if (br2) br2.title = 'Reveal';
}

function _baShowCredView(show) {
  document.getElementById('basicauth-cred-view').style.display = show ? 'block' : 'none';
  document.getElementById('basicauth-controls').style.display  = 'none';
  if (show) _baEditOpen = false;
}

function _baShowEditForm(show) {
  document.getElementById('basicauth-controls').style.display  = show ? 'block' : 'none';
  document.getElementById('basicauth-cred-view').style.display = 'none';
  _baEditOpen = show;
}

// ── Credential reveal ───────────────────────────────────
function baReveal(field) {
  const ep     = activeTunnel || '(default)';
  const isUser = field === 'user';
  const valEl  = document.getElementById(isUser ? 'ba-user-val' : 'ba-pass-val');
  const btnEl  = document.getElementById(isUser ? 'ba-user-reveal' : 'ba-pass-reveal');
  const revealed = isUser ? _baUserRevealed : _baPassRevealed;

  if (revealed) {
    valEl.textContent = isUser ? '••••••' : '••••••••';
    btnEl.title = 'Reveal';
    if (isUser) _baUserRevealed = false; else _baPassRevealed = false;
    return;
  }

  const showVal = (u, p) => {
    if (isUser) { valEl.textContent = u; _baUserRevealed = true; btnEl.title = 'Hide'; }
    else        { valEl.textContent = p; _baPassRevealed = true; btnEl.title = 'Hide'; }
  };

  if (_baCreds.user || _baCreds.pass) { showVal(_baCreds.user, _baCreds.pass); return; }

  fetch('/api/tunnels/basicauth/creds?endpoint=' + encodeURIComponent(ep))
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      _baCreds = { user: d.username || '', pass: d.password || '' };
      showVal(_baCreds.user, _baCreds.pass);
    })
    .catch(() => { valEl.textContent = '(error)'; });
}

// ── Edit form ───────────────────────────────────────────
function baOpenEdit() {
  // Always fetch fresh creds so form is pre-filled even without a prior reveal
  if (_baCreds.user) {
    document.getElementById('basicauth-user').value = _baCreds.user;
    document.getElementById('basicauth-pass').value = '';
    _baShowEditForm(true);
    return;
  }
  const ep = activeTunnel || '(default)';
  fetch('/api/tunnels/basicauth/creds?endpoint=' + encodeURIComponent(ep))
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      _baCreds = { user: d.username || '', pass: d.password || '' };
      document.getElementById('basicauth-user').value = _baCreds.user;
      document.getElementById('basicauth-pass').value = '';
      _baShowEditForm(true);
    })
    .catch(() => {
      document.getElementById('basicauth-user').value = '';
      document.getElementById('basicauth-pass').value = '';
      _baShowEditForm(true);
    });
}

function baCancelEdit() {
  const ep       = activeTunnel || '(default)';
  const hasCreds = !!(tunnelsMap[ep] && tunnelsMap[ep].basicauth_enabled);
  _baPendingEnable = false;   // allow SSE to resume control of checkbox
  _baShowEditForm(false);
  if (hasCreds) {
    _baShowCredView(true);
  } else {
    // User cancelled without saving — revert toggle to disabled
    document.getElementById('basicauth-toggle').checked = false;
    _setBasicAuthStatus(false);
  }
}

function baTogglePassVis() {
  const inp = document.getElementById('basicauth-pass');
  inp.type  = inp.type === 'password' ? 'text' : 'password';
}

// ── Password strength ────────────────────────────────────
function baPassStrength() {
  const pass = document.getElementById('basicauth-pass').value;
  const lbl  = document.getElementById('ba-strength-label');
  const segs = [1,2,3,4].map(i => document.getElementById('bas-' + i));
  const levels = ['','weak','fair','good','strong'];
  const labels = ['','Weak','Fair','Good','Strong'];
  const score = _passStrengthScore(pass);
  segs.forEach((s, i) => { if (s) s.className = 'strength-seg ' + (i < score ? levels[score] : ''); });
  if (lbl) { lbl.textContent = pass ? labels[score] : ''; lbl.className = 'strength-label ' + (pass ? levels[score] : ''); }
}

function _passStrengthScore(p) {
  if (!p || p.length < 6) return 1;
  let s = 1;
  if (p.length >= 10) s++;
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
  if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++;
  return Math.min(s, 4);
}

// ── curl snippet ─────────────────────────────────────────
function _updateBaCurlSnippet(user, pass) {
  const proxyUrl = (tunnelsMap[activeTunnel || '(default)'] || {}).proxy_url || 'http://your-tunnel';
  const snippet = `curl -u "${user}:${pass}" ${proxyUrl}/`;
  const code = document.getElementById('ba-curl-code');
  const block = document.getElementById('ba-curl-block');
  if (code) code.textContent = snippet;
  if (block) block.style.display = user ? 'block' : 'none';
}

function baCopyCurl() {
  const code = document.getElementById('ba-curl-code');
  if (!code) return;
  const btn = document.getElementById('ba-curl-copy');
  const text = code.textContent;
  const done = () => { if (btn) { btn.textContent = 'copied!'; btn.classList.add('ok'); setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('ok'); }, 1600); } };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => _fallbackCopy(text, done));
  } else {
    _fallbackCopy(text, done);
  }
}

function _baAutoUser() {
  const adj   = ['swift','bright','calm','bold','cool','keen','wise','sharp','quick','clear'];
  const nouns = ['tunnel','proxy','gate','relay','bridge','node','link','path','route','mesh'];
  const pick  = arr => arr[Math.floor(Math.random() * arr.length)];
  return pick(adj) + '_' + pick(nouns) + Math.floor(100 + Math.random() * 900);
}

function _baAutoPass() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*';
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  let p = '';
  bytes.forEach(b => { p += chars[b % chars.length]; });
  return p;
}

function baGenUser() {
  document.getElementById('basicauth-user').value = _baAutoUser();
}

function baGenPass() {
  const inp = document.getElementById('basicauth-pass');
  inp.value = _baAutoPass();
  inp.type  = 'text';
  baPassStrength();
}

// ── Toggle ──────────────────────────────────────────────
function basicAuthToggleChanged() {
  const enabled = document.getElementById('basicauth-toggle').checked;
  const ep      = activeTunnel || '(default)';

  if (!enabled) {
    // ── Disable ─────────────────────────────────────────
    _baPendingEnable = false;
    _setBasicAuthStatus(false);
    if (tunnelsMap[ep]) tunnelsMap[ep].basicauth_enabled = false;
    _baShowCredView(false);
    _baShowEditForm(false);  // also clears _baEditOpen
    // NOTE: _baCreds is intentionally NOT cleared here so that re-enabling
    // the toggle reuses the same credentials without the user having to
    // re-enter them.
    _baMaskCreds();

    fetch('/api/tunnels/basicauth', {
      method: 'POST',
      headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify({ endpoint: ep, enabled: false })
    })
    .then(r => { if (!r.ok) throw new Error(r.status); })
    .catch(() => {
      // Revert
      document.getElementById('basicauth-toggle').checked = true;
      _setBasicAuthStatus(true);
      if (tunnelsMap[ep]) tunnelsMap[ep].basicauth_enabled = true;
      _baShowCredView(true);
    });
    return;
  }

  // ── Enable ───────────────────────────────────────────
  _baPendingEnable = true;
  _setBasicAuthStatus(true);

  if (_baCreds.user && _baCreds.pass) {
    // In-memory cache hit — re-enable with the same credentials immediately
    _doSaveBasicAuth(ep, _baCreds.user, _baCreds.pass, true);
    return;
  }

  // Cache miss (e.g. page was refreshed) — ask the server whether credentials
  // already exist before deciding to generate new ones.
  fetch('/api/tunnels/basicauth/creds?endpoint=' + encodeURIComponent(ep))
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      const user = d.username || '';
      const pass = d.password || '';
      if (user && pass) {
        // Server already has credentials — reuse them
        _baCreds = { user, pass };
        _doSaveBasicAuth(ep, user, pass, true);
      } else {
        // Genuinely first time — auto-generate and save
        const autoUser = _baAutoUser();
        const autoPass = _baAutoPass();
        _doSaveBasicAuth(ep, autoUser, autoPass, true);
      }
    })
    .catch(() => {
      // Fetch failed — fall back to auto-generate so the toggle still works
      const autoUser = _baAutoUser();
      const autoPass = _baAutoPass();
      _doSaveBasicAuth(ep, autoUser, autoPass, true);
    });
}

// ── Save / apply ────────────────────────────────────────
function _doSaveBasicAuth(ep, user, pass, showCredView) {
  const msg = document.getElementById('basicauth-msg');
  fetch('/api/tunnels/basicauth', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()},
    body: JSON.stringify({ endpoint: ep, enabled: true, username: user, password: pass })
  })
  .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
  .then(() => {
    _baPendingEnable = false;
    _baCreds = { user, pass };
    if (tunnelsMap[ep]) tunnelsMap[ep].basicauth_enabled = true;
    document.getElementById('basicauth-toggle').checked = true;
    _setBasicAuthStatus(true);
    _baMaskCreds();
    _updateBaCurlSnippet(user, pass);
    if (showCredView) {
      _baShowEditForm(false);
      _baShowCredView(true);
    }
    showToast('Basic Auth credentials saved', 'success');
    if (msg) msg.style.display = 'none';
  })
  .catch(() => {
    _baPendingEnable = false;
    if (msg) {
      msg.style.color   = 'var(--red,#ef4444)';
      msg.textContent   = 'Failed to save — check server logs';
      msg.style.display = 'block';
    }
    showToast('Failed to save Basic Auth', 'error');
    if (!tunnelsMap[ep] || !tunnelsMap[ep].basicauth_enabled) {
      document.getElementById('basicauth-toggle').checked = false;
      _setBasicAuthStatus(false);
    }
  });
}

function basicAuthSave() {
  const user = document.getElementById('basicauth-user').value.trim();
  const pass = document.getElementById('basicauth-pass').value;
  const ep   = activeTunnel || '(default)';
  const msg  = document.getElementById('basicauth-msg');
  if (!user || !pass) {
    if (msg) { msg.style.color = 'var(--red,#ef4444)'; msg.textContent = 'Username and password required'; msg.style.display = 'block'; }
    showToast('Username and password required', 'error');
    return;
  }
  const score = _passStrengthScore(pass);
  if (score < 2) {
    if (msg) { msg.style.color = 'var(--amber)'; msg.textContent = 'Password is too weak — use at least 10 characters'; msg.style.display = 'block'; }
    return;
  }
  _doSaveBasicAuth(ep, user, pass, true);
}

// ── Request rendering ────────────────────────── ──────────────────────────
function renderAll() {
  const list = activeTunnel ? allReqs.filter(r => r.endpoint === activeTunnel) : [];
  $tCount.textContent = list.length;
  $list.innerHTML = '';

  if (list.length === 0) {
    $empty.style.display = 'flex';
    return;
  }
  $empty.style.display = 'none';

  // newest first
  for (let i = list.length - 1; i >= 0; i--) {
    appendRow(list[i], false);
  }
}

// FIX: appendRow() and addReq() used to duplicate ~50 lines of identical
// row/detail-building markup. Both now call this single builder.
function buildReqRow(r, isNew) {
  const row = document.createElement('div');
  row.className = 'req-row' + (isNew ? ' is-new' : '');
  row.innerHTML = `
    <span class="r-time">${fmtTime(r.ts)}</span>
    <span class="r-clientip" style="font-family:'Geist Mono', monospace; font-size:12px; color:var(--text-3);">${esc(r.client_ip || '—')}</span>
    <span class="r-method ${r.method}">${r.method}</span>
    <span class="r-path" title="${esc(r.path)}">${esc(r.path)}</span>
    <span class="r-status ${statusCls(r.status)}">${r.status}</span>
    <span class="r-dur">${fmtDur(r.duration_ms)}</span>
    <div class="r-actions">
      <button class="replay-btn" onclick="replayReq(${r.id});event.stopPropagation()">Replay</button>
      <svg class="expand-icon" id="exp-${r.id}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
    </div>
  `;

  // body decode attempt
  let bodyHtml = '';
  if (r.req_body && r.req_body.length) {
    try {
      const txt = atob(r.req_body);
      bodyHtml = `<div class="detail-section-title" style="margin-top:12px">Request Body</div><div class="detail-body">${esc(txt)}</div>`;
    } catch(e) {}
  }

  const detail = document.createElement('div');
  detail.className = 'req-detail';
  detail.innerHTML = `
    <div class="detail-grid">
      <div>
        <div class="detail-section-title">Request Headers</div>
        <div class="detail-headers">${hdrsHtml(r.req_headers)}</div>
        ${bodyHtml}
      </div>
      <div>
        <div class="detail-section-title">Response Headers</div>
        <div class="detail-headers">${hdrsHtml(r.resp_headers)}</div>
      </div>
    </div>
  `;

  row.addEventListener('click', () => {
    detail.classList.toggle('open');
    document.getElementById('exp-' + r.id)?.classList.toggle('open');
  });

  return { row, detail };
}

function appendRow(r, isNew) {
  const { row, detail } = buildReqRow(r, isNew);
  $list.appendChild(row);
  $list.appendChild(detail);
}

// FIX: allReqs.find(x => x.id === r.id) was an O(n) linear scan on every
// incoming SSE event. With reqIdSet this is now an O(1) lookup.
const reqIdSet = new Set();

function addReq(r, isNew) {
  if (reqIdSet.has(r.id)) return;
  reqIdSet.add(r.id);
  allReqs.push(r);
  if (allReqs.length > 500) reqIdSet.delete(allReqs.shift().id);

  totalEver = Math.max(totalEver, r.id);

  if (activeTunnel && r.endpoint !== activeTunnel) {
    $tCount.textContent = allReqs.filter(x => x.endpoint === activeTunnel).length;
    return;
  }

  $empty.style.display = 'none';

  if (isNew) {
    const { row, detail } = buildReqRow(r, true);
    // Insert at top (newest first).
    $list.prepend(detail);
    $list.prepend(row);
  }

  $tCount.textContent = (activeTunnel ? allReqs.filter(x => x.endpoint === activeTunnel) : []).length;
}

function clearReqs() {
  allReqs = allReqs.filter(r => {
    const keep = r.endpoint !== activeTunnel;
    if (!keep) reqIdSet.delete(r.id);
    return keep;
  });
  renderAll();
}

// ── Replay ─────────────────────────────────────
function replayReq(id) {
  fetch('/api/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ id })
  });
}

// ── Tunnels ────────────────────────────────────
function renderTunnels(tunnels) {
  // Merge server data into tunnelsMap instead of replacing it wholesale.
  // This preserves optimistic auth-toggle state set by the user while
  // still updating connection counts, proxy_url, client_ip, etc.
  const incoming = {};
  tunnels.forEach(t => { incoming[t.endpoint] = t; });

  // Remove endpoints that are no longer present.
  Object.keys(tunnelsMap).forEach(ep => {
    if (!incoming[ep]) delete tunnelsMap[ep];
  });

  // Merge each incoming entry: keep client-side auth fields if already patched.
  tunnels.forEach(t => {
    const existing = tunnelsMap[t.endpoint];
    if (existing) {
      // Preserve fields the user may have toggled (optimistic patches).
      // Only accept server values when they differ from the default (false),
      // meaning the server actually has the feature enabled — in that case
      // the server is the source of truth.
      tunnelsMap[t.endpoint] = Object.assign({}, t, {
        apikey_enabled:    t.apikey_enabled    || existing.apikey_enabled,
        basicauth_enabled: t.basicauth_enabled || existing.basicauth_enabled,
        aimode_enabled:    t.aimode_enabled    || existing.aimode_enabled,
        has_apikey:        t.has_apikey        || existing.has_apikey,
      });
    } else {
      tunnelsMap[t.endpoint] = t;
    }
  });

  if (!tunnels || !tunnels.length) {
    $tunList.innerHTML = '<div class="tunnel-empty-msg">No active tunnels</div>';
    if (activeTunnel) selectTunnel(null);
    return;
  }

  let found = false;
  // FIX: dropped the inline onclick="selectTunnel('...')" handler. It only
  // escaped single quotes, so an endpoint name containing a double quote or
  // "><script> could break out of the attribute and execute arbitrary JS.
  // Endpoint selection is now handled by a single delegated click listener
  // (see bindTunnelListClick below) that reads the safely-escaped data-ep
  // attribute instead of interpolating into an HTML event handler string.
  $tunList.innerHTML = tunnels.map(t => {
    if (t.endpoint === activeTunnel) found = true;
    return `
    <div class="tunnel-entry${activeTunnel === t.endpoint ? ' active' : ''}"
         data-ep="${esc(t.endpoint)}">
      <div class="t-dot ${t.type}"></div>
      <span class="t-name" title="${esc(t.endpoint)}">${esc(t.endpoint)}</span>
      <span class="t-workers">${t.connections}</span>
    </div>
  `}).join('');

  if (activeTunnel && !found) {
    selectTunnel(null);
  } else if (activeTunnel) {
    renderTunnelOverview();
  }
}

// ── Boot ───────────────────────────────────────
// Wire hamburger toggle via JS (avoids relying on inline onclick + defer race)
if ($hamburger) $hamburger.addEventListener('click', toggleSidebar);

document.addEventListener('click', (e) => {
  const menu = document.getElementById('brand-menu');
  if (menu && menu.classList.contains('open')) {
    menu.classList.remove('open');
  }
});

// Delegated handler for tunnel selection (replaces the removed inline
// onclick on each .tunnel-entry — see renderTunnels()).
$tunList.addEventListener('click', (e) => {
  const entry = e.target.closest('.tunnel-entry');
  if (entry) selectTunnel(entry.dataset.ep);
});
// 1. Load existing requests
fetch('/api/requests').then(r => r.json()).then(data => {
  if (data && data.length) {
    allReqs = data;
    data.forEach(r => reqIdSet.add(r.id));
    totalEver = Math.max(...data.map(r => r.id), 0);
  }
}).catch(() => {});

// 2. Real-time SSE for new requests
const sse = new EventSource('/api/requests/stream');
sse.onmessage = e => {
  try { addReq(JSON.parse(e.data), true); } catch(_) {}
};
sse.onerror = () => {};

// 3. Real-time SSE for status + tunnels (server pushes every ~1s)
const statusSse = new EventSource('/api/status/stream');
statusSse.onmessage = e => {
  try {
    const s = JSON.parse(e.data);
    $uptime.textContent = fmtUptime(s.uptime_sec);
    renderTunnels(s.tunnels || []);
  } catch(_) {}
};
statusSse.onerror = () => {};
