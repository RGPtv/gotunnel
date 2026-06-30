'use strict';

// ── CSRF ─────────────────────────────────────────────────────
function getCsrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)gotunnel_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

// ── Helpers ──────────────────────────────────────────────────
function fmtTime(ts) {
  const d = new Date(ts);
  return isNaN(d) ? '—' : d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function fmtDur(ms) {
  if (ms >= 1000) return (ms / 1000).toFixed(2) + 's';
  return ms + 'ms';
}

/** Safely escape a value for HTML contexts. */
function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Reveal-button icon helpers ────────────────────────────────
/** Eye-open or eye-slash SVG string. slashed=true → hide icon. */
function _svgEye(slashed, size) {
  size = size || 14;
  if (slashed) {
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
  }
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
}

/** Spinning arc SVG for loading state. */
function _svgSpinner(size) {
  size = size || 14;
  return `<svg class="btn-spinner" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2.5" stroke-dasharray="14 42" stroke-linecap="round"/></svg>`;
}

/**
 * Update a reveal button's icon + accessible label.
 * isRevealed=true  → eye-slash + "Hide"   (value is now visible)
 * isRevealed=false → eye-open  + "Reveal" (value is hidden)
 */
function _setRevealIcon(btn, isRevealed) {
  if (!btn) return;
  const size = btn.classList.contains('ov-sm-btn') ? 12 : 14;
  btn.innerHTML = _svgEye(isRevealed, size);
  const label = isRevealed ? 'Hide' : 'Reveal';
  btn.title = label;
  btn.setAttribute('aria-label', label);
}

/**
 * Put a button into / out of loading state.
 * loading=true  → disable + show spinner
 * loading=false → re-enable + restore reveal icon (fallbackRevealed sets which icon)
 */
function _setBtnLoading(btn, loading, fallbackRevealed) {
  if (!btn) return;
  if (loading) {
    const size = btn.classList.contains('ov-sm-btn') ? 12 : 14;
    btn.innerHTML = _svgSpinner(size);
    btn.disabled  = true;
  } else {
    btn.disabled = false;
    if (fallbackRevealed !== undefined) _setRevealIcon(btn, fallbackRevealed);
  }
}

/** Return a safe numeric string from a request ID. Prevents attribute injection. */
function safeId(id) {
  const n = parseInt(id, 10);
  return isNaN(n) ? '0' : String(n);
}

function statusClass(code) {
  if (code >= 500) return 's5';
  if (code >= 400) return 's4';
  if (code >= 300) return 's3';
  if (code >= 200) return 's2';
  return '';
}

const _KNOWN_METHODS = new Set(['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE']);
function methodStr(m) {
  const u = String(m || '').toUpperCase();
  return _KNOWN_METHODS.has(u) ? u : 'OTHER';
}

function copyToClipboard(text) {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  return new Promise((res, rej) => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;pointer-events:none';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    ok ? res() : rej(new Error('Copy failed'));
  });
}

function fmtUptime(s) {
  s = Math.floor(s);
  if (s < 60)   return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}

// ── State ────────────────────────────────────────────────────
// ── Theme Init ─────────────────────────────────────────────────
(function () {
  var saved = localStorage.getItem('gotunnel-theme');
  var theme = saved || 'dark';
  document.documentElement.setAttribute('data-theme', theme);
})();

let activeTunnel     = null;
let currentTab       = 'overview';
let reqsByTunnel     = {};
let lastTunnels      = [];
let _expandedIds     = new Set();   // preserve expanded rows across re-renders
let _filterMethod    = '';          // '' = all, 'GET', 'POST', …
let _filterStatus    = '';          // '' = all, '2xx', '3xx', '4xx', '5xx'
let _filterSearch    = '';          // path substring search
let _tokenHideTimer  = null;
let _apikeyHideTimer = null;
let _baUserHideTimer = null;
let _baPassHideTimer = null;
let _curlHideTimer   = null;
let _apikeyEnabled   = false;
let _baEnabled       = false;
let _aiEnabled       = false;
let _baPending       = false;

// ── Local persistence ─────────────────────────────────────────
const REQ_CACHE_MAX    = 300;

function _mergeReqs(existing, incoming) {
  const seen = new Set(existing.map(r => r.id));
  const merged = existing.slice();
  incoming.forEach(r => { if (!seen.has(r.id)) { merged.push(r); seen.add(r.id); } });
  merged.sort((a, b) => b.id - a.id);
  return merged;
}

// ── DOM refs ─────────────────────────────────────────────────
const $list    = document.getElementById('req-list');
const $count   = document.getElementById('t-count');
const $tunList = document.getElementById('tunnel-list');
const $uptime  = document.getElementById('uptime');

// ── Mobile drawer ─────────────────────────────────────────────
const $sidebar       = document.getElementById('sidebar');
const $mobileOverlay = document.getElementById('mobile-overlay');
const $hamburger     = document.getElementById('nav-hamburger');
const $mobileTabs    = document.getElementById('mobile-tabs');
const $navActiveTun  = document.getElementById('nav-active-tunnel');
const $sidebarName   = document.getElementById('sidebar-tun-name');

function openMobileMenu() {
  if (!$sidebar) return;
  if ($sidebarName) $sidebarName.textContent = activeTunnel || '';
  $sidebar.classList.add('open');
  $mobileOverlay?.classList.add('show');
  document.body.style.overflow = 'hidden';
  $hamburger?.setAttribute('aria-expanded', 'true');
}
function closeMobileMenu() {
  if (!$sidebar) return;
  $sidebar.classList.remove('open');
  $mobileOverlay?.classList.remove('show');
  document.body.style.overflow = '';
  $hamburger?.setAttribute('aria-expanded', 'false');
}

// ── Navigation ────────────────────────────────────────────────
function switchTab(tab) {
  if (!activeTunnel) return;
  currentTab = tab;
  ['overview', 'inspector'].forEach(t => {
    document.getElementById('tab-' + t)?.classList.toggle('active', t === tab);
    document.getElementById('tab-' + t)?.setAttribute('aria-selected', String(t === tab));
    document.getElementById('mob-tab-' + t)?.classList.toggle('active', t === tab);
    document.getElementById('mob-tab-' + t)?.setAttribute('aria-selected', String(t === tab));
    const v = document.getElementById('view-' + t);
    if (v) v.style.display = t === tab ? 'flex' : 'none';
  });
  if (tab === 'inspector') _renderList();
}

function selectTunnel(ep) {
  closeMobileMenu();
  _baPending = false;
  activeTunnel = ep;
  if ($navActiveTun) $navActiveTun.textContent = ep || '';
  if ($sidebarName)  $sidebarName.textContent  = ep || '';

  const viewEmpty = document.getElementById('view-empty');
  const navTabs   = document.getElementById('nav-tabs');

  if (!ep) {
    document.body.classList.remove('has-tunnel');
    if (viewEmpty) viewEmpty.style.display = 'flex';
    if (navTabs)   navTabs.style.display   = 'none';
    if ($mobileTabs) $mobileTabs.style.display = 'none';
    ['view-overview','view-inspector'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
    _clearTunnelInfo();
    return;
  }

  document.body.classList.add('has-tunnel');
  if (viewEmpty) viewEmpty.style.display = 'none';
  if (navTabs)   navTabs.style.display   = 'flex';
  if ($mobileTabs && window.innerWidth <= 768) $mobileTabs.style.display = 'flex';

  document.querySelectorAll('.tunnel-item').forEach(el =>
    el.classList.toggle('active', el.dataset.ep === ep));

  const t = lastTunnels.find(x => x.endpoint === ep);
  if (t) _applyTunnelInfo(t);
  switchTab(currentTab);
  _renderList();
}

function _clearTunnelInfo() {
  ['tun-proxyurl','tun-clientip','tun-type','tun-conns'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '—';
  });
  const authSection = document.getElementById('tunnel-auth-section');
  if (authSection) authSection.style.display = 'none';
  const tcpSection = document.getElementById('tunnel-tcp-section');
  if (tcpSection) tcpSection.style.display = 'none';
  const tcpEmpty = document.getElementById('tcp-inspector-empty');
  const httpContent = document.getElementById('http-inspector-content');
  if (tcpEmpty) tcpEmpty.style.display = 'none';
  if (httpContent) httpContent.style.display = 'flex';
  _renderList();
}

function _applyTunnelInfo(t) {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v != null ? String(v) : '—') || '—'; };
  set('tun-proxyurl', t.proxy_url);
  set('tun-clientip', t.client_ip);
  set('tun-type',     t.type);
  set('tun-conns',    t.connections ?? 0);

  const authSection = document.getElementById('tunnel-auth-section');
  const tcpSection = document.getElementById('tunnel-tcp-section');
  const tcpEmpty = document.getElementById('tcp-inspector-empty');
  const httpContent = document.getElementById('http-inspector-content');

  if (t.type === 'tcp') {
    if (authSection) authSection.style.display = 'none';
    if (tcpSection) tcpSection.style.display = 'contents';
    if (tcpEmpty) tcpEmpty.style.display = 'flex';
    if (httpContent) httpContent.style.display = 'none';
  } else {
    if (authSection) authSection.style.display = 'contents';
    if (tcpSection) tcpSection.style.display = 'none';
    if (tcpEmpty) tcpEmpty.style.display = 'none';
    if (httpContent) httpContent.style.display = 'flex';
  }

  _apikeyEnabled = !!t.apikey_enabled;
  _aiEnabled     = !!t.aimode_enabled;

  _applyApikeyState(_apikeyEnabled, true);
  if (!_baPending) {
    _baEnabled = !!t.basicauth_enabled;
    _applyBasicAuthState(_baEnabled);
  }
  _applyAiModeState(_aiEnabled);
}

// ── Toast ─────────────────────────────────────────────────────
function showToast(msg, type = 'info', duration = 3000) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast' + (type !== 'info' ? ' ' + type : '');

  const msgSpan = document.createElement('span');
  msgSpan.className = 'toast-msg';
  msgSpan.textContent = msg;   // textContent — no XSS risk

  const closeBtn = document.createElement('button');
  closeBtn.className = 'toast-close';
  closeBtn.setAttribute('aria-label', 'Dismiss notification');
  closeBtn.innerHTML = '&times;';

  const dismiss = () => {
    toast.style.transition = 'opacity .2s, transform .2s';
    toast.style.opacity    = '0';
    toast.style.transform  = 'translateY(6px)';
    setTimeout(() => toast.remove(), 220);
  };

  closeBtn.addEventListener('click', dismiss);
  toast.append(msgSpan, closeBtn);
  container.appendChild(toast);

  const timer = setTimeout(dismiss, duration);
  // Pause auto-dismiss on hover so users can read longer messages
  toast.addEventListener('mouseenter', () => clearTimeout(timer));
  toast.addEventListener('mouseleave', () => setTimeout(dismiss, 1500));
}

// ── Token ─────────────────────────────────────────────────────
function tokenReveal() {
  const val = document.getElementById('home-token-val');
  const btn = document.getElementById('home-token-reveal');
  if (!val) return;
  if (!val.classList.contains('masked')) { _maskToken(); return; }
  _setBtnLoading(btn, true);
  fetch('/api/token', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t || 'Server error ' + r.status); }); return r.json(); })
    .then(d => {
      if (!d.token) { _setBtnLoading(btn, false, false); showToast('Token not available', 'error'); return; }
      val.textContent = d.token;  // textContent — safe
      val.classList.remove('masked');
      _setBtnLoading(btn, false, true);
      clearTimeout(_tokenHideTimer);
      _tokenHideTimer = setTimeout(_maskToken, 30000);
    })
    .catch(err => { _setBtnLoading(btn, false, false); showToast('Could not fetch token: ' + (err.message || 'unknown error'), 'error'); });
}

function _maskToken() {
  const val = document.getElementById('home-token-val');
  const btn = document.getElementById('home-token-reveal');
  if (!val) return;
  val.textContent = '••••••••••••••';
  val.classList.add('masked');
  _setRevealIcon(btn, false);
  clearTimeout(_tokenHideTimer);
}

function tokenCopy() {
  fetch('/api/token', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => { if (!d.token) throw new Error(); return copyToClipboard(d.token); })
    .then(() => showToast('Token copied to clipboard', 'success'))
    .catch(() => showToast('Could not copy token', 'error'));
}

function tokenRegenerate() {
  if (!confirm('Generate a new Auth Token? Old clients will be disconnected.')) return;
  fetch('/api/token/regen', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t || 'Server error ' + r.status); }); return r.json(); })
    .then(d => {
      if (!d.token) { showToast('Token not available', 'error'); return; }
      const val = document.getElementById('home-token-val');
      const btn = document.getElementById('home-token-reveal');
      if (val) { val.textContent = d.token; val.classList.remove('masked'); }
      _setRevealIcon(btn, true);
      clearTimeout(_tokenHideTimer);
      _tokenHideTimer = setTimeout(_maskToken, 30000);
      showToast('New Auth Token generated', 'success');
    })
    .catch(err => showToast('Could not regenerate token: ' + (err.message || 'unknown error'), 'error'));
}

// ── API Key ───────────────────────────────────────────────────
function _applyApikeyState(enabled, skipServer) {
  const toggle      = document.getElementById('apikey-toggle');
  const badge       = document.getElementById('apikey-badge');
  const controls    = document.getElementById('apikey-controls');
  const disabledMsg = document.getElementById('apikey-disabled-msg');
  if (toggle) toggle.checked = enabled;
  if (badge)  { badge.textContent = enabled ? 'On' : 'Off'; badge.className = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled'); }
  if (controls)    controls.style.display    = enabled ? 'block' : 'none';
  if (disabledMsg) disabledMsg.style.display = enabled ? 'none'  : 'block';
  if (enabled && !skipServer) _maskApiKey();
}

function apikeyToggleChanged() {
  const toggle = document.getElementById('apikey-toggle');
  if (!toggle || !activeTunnel) return;
  const enabled = toggle.checked;
  fetch('/api/tunnels/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled, regenerate: false })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(() => { _apikeyEnabled = enabled; _applyApikeyState(enabled, false); showToast('API key auth ' + (enabled ? 'enabled' : 'disabled'), enabled ? 'success' : 'info'); })
    .catch(err => { showToast('Failed to update API key: ' + (err.message || 'unknown error'), 'error'); toggle.checked = _apikeyEnabled; });
}

function apiReveal() {
  const val = document.getElementById('api-val');
  const btn = document.getElementById('api-reveal');
  if (!val || !activeTunnel) return;
  if (!val.classList.contains('masked')) { _maskApiKey(); return; }
  _setBtnLoading(btn, true);
  fetch('/api/tunnels/apikey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      if (!d.apikey) { _setBtnLoading(btn, false, false); return; }
      val.textContent = d.apikey;   // textContent — safe
      val.classList.remove('masked');
      _setBtnLoading(btn, false, true);
      clearTimeout(_apikeyHideTimer);
      _apikeyHideTimer = setTimeout(_maskApiKey, 30000);
    })
    .catch(() => { _setBtnLoading(btn, false, false); showToast('Could not fetch API key', 'error'); });
}

function _maskApiKey() {
  const val = document.getElementById('api-val');
  const btn = document.getElementById('api-reveal');
  if (!val) return;
  val.textContent = '••••••••••••••••••••••••••••••••';
  val.classList.add('masked');
  _setRevealIcon(btn, false);
  clearTimeout(_apikeyHideTimer);
}

function apiCopy() {
  if (!activeTunnel) return;
  fetch('/api/tunnels/apikey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => { if (!d.apikey) throw new Error('No key'); return copyToClipboard(d.apikey); })
    .then(() => showToast('API key copied to clipboard', 'success'))
    .catch(() => showToast('Could not copy API key', 'error'));
}

function apiRegenerate() {
  if (!activeTunnel) return;
  if (!confirm('Generate a new API key? The old key will immediately stop working.')) return;
  fetch('/api/tunnels/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled: true, regenerate: true })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(d => {
      if (d.apikey) {
        const val = document.getElementById('api-val');
        if (val) { val.textContent = d.apikey; val.classList.remove('masked'); }
        clearTimeout(_apikeyHideTimer);
        _apikeyHideTimer = setTimeout(_maskApiKey, 30000);
      }
      showToast('New API key generated', 'success');
    })
    .catch(err => showToast('Failed to regenerate API key: ' + (err.message || ''), 'error'));
}

function apikeyCustomInputChanged() {
  const input   = document.getElementById('apikey-custom-input');
  const saveBtn = document.getElementById('apikey-custom-save');
  const bar     = document.getElementById('apikey-strength-bar');
  const label   = document.getElementById('apikey-strength-label');
  if (!input) return;
  const val = input.value.trim();
  if (saveBtn) saveBtn.disabled = val.length === 0;
  if (!bar || !label) return;
  bar.style.display = val.length > 0 ? 'flex' : 'none';
  let score = 0;
  if (val.length >= 8)  score++;
  if (val.length >= 20) score++;
  if (/[^a-zA-Z0-9]/.test(val)) score++;
  if (val.length >= 32) score++;
  const colors = ['#ef4444','#f59e0b','#3b82f6','#22c55e'];
  const labels = ['Weak — too short','Fair — try longer','Good','Strong'];
  [1,2,3,4].forEach(i => {
    const s = document.getElementById('aks-' + i);
    if (s) s.style.background = i <= score ? colors[score - 1] : 'var(--border)';
  });
  label.textContent = val.length > 0 ? labels[Math.max(0, score - 1)] : '';
}

function apikeyCustomSave() {
  const input = document.getElementById('apikey-custom-input');
  if (!input || !activeTunnel) return;
  const key = input.value.trim();
  if (!key) return;
  fetch('/api/tunnels/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled: true, regenerate: false, apikey: key })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(() => {
      input.value = '';
      apikeyCustomInputChanged();
      const bar = document.getElementById('apikey-strength-bar');
      if (bar) bar.style.display = 'none';
      _maskApiKey();
      showToast('Custom API key saved', 'success');
    })
    .catch(err => showToast('Failed to save custom API key: ' + (err.message || ''), 'error'));
}

// ── AI Mode ───────────────────────────────────────────────────
function _applyAiModeState(enabled) {
  const toggle = document.getElementById('aimode-toggle');
  const badge  = document.getElementById('aimode-badge');
  if (toggle) toggle.checked = enabled;
  if (badge)  { badge.textContent = enabled ? 'On' : 'Off'; badge.className = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled'); }
  const feats = {
    'ai-feat-body':  [enabled ? 'Unlimited' : '10 MB',    enabled],
    'ai-feat-flush': [enabled ? 'Immediate'  : '32 KB',   enabled],
    'ai-feat-cors':  [enabled ? 'Enabled'    : 'Disabled', enabled],
    'ai-feat-buf':   [enabled ? 'Disabled'   : 'Enabled', !enabled],
  };
  Object.entries(feats).forEach(([id, [text, on]]) => {
    const el = document.getElementById(id);
    if (el) { el.textContent = text; el.className = 'feat-pill ' + (on ? 'on' : 'off'); }
  });
}

function aiModeToggleChanged() {
  const toggle = document.getElementById('aimode-toggle');
  if (!toggle || !activeTunnel) return;
  const enabled = toggle.checked;
  fetch('/api/tunnels/aimode', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(() => { _aiEnabled = enabled; _applyAiModeState(enabled); showToast('AI optimization ' + (enabled ? 'enabled' : 'disabled'), enabled ? 'success' : 'info'); })
    .catch(err => { showToast('Failed to update AI mode: ' + (err.message || ''), 'error'); toggle.checked = _aiEnabled; });
}

// ── Basic Auth ────────────────────────────────────────────────
function _applyBasicAuthState(enabled) {
  const toggle      = document.getElementById('basicauth-toggle');
  const badge       = document.getElementById('basicauth-badge');
  const credView    = document.getElementById('basicauth-cred-view');
  const controls    = document.getElementById('basicauth-controls');
  const disabledMsg = document.getElementById('basicauth-disabled-msg');
  if (toggle) toggle.checked = enabled;
  if (badge)  { badge.textContent = enabled ? 'On' : 'Off'; badge.className = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled'); }
  if (credView)    credView.style.display    = enabled ? 'block' : 'none';
  if (controls)    controls.style.display    = 'none';
  if (disabledMsg) disabledMsg.style.display = enabled ? 'none'  : 'block';
}

function basicAuthToggleChanged() {
  const toggle = document.getElementById('basicauth-toggle');
  if (!toggle || !activeTunnel) return;
  const enabled = toggle.checked;
  if (enabled) {
    _baPending = true;
    _applyBasicAuthState(false);
    const controls    = document.getElementById('basicauth-controls');
    const disabledMsg = document.getElementById('basicauth-disabled-msg');
    if (controls)    controls.style.display    = 'block';
    if (disabledMsg) disabledMsg.style.display = 'none';
    toggle.checked = true;
    // Always start with password hidden when the form opens
    const passInput = document.getElementById('basicauth-pass');
    if (passInput) passInput.type = 'password';
    _setRevealIcon(document.getElementById('ba-toggle-pass-vis'), false);
    const msgEl = document.getElementById('basicauth-msg');
    if (msgEl) { msgEl.textContent = 'Enter credentials and click Apply to enable.'; msgEl.style.display = 'block'; msgEl.style.color = 'var(--text-3)'; }
    showToast('Enter credentials and click Apply to enable Basic Auth', 'info');
    return;
  }
  fetch('/api/tunnels/basicauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled: false })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(() => { _baEnabled = false; _applyBasicAuthState(false); showToast('Basic auth disabled', 'info'); })
    .catch(err => { showToast('Failed to disable basic auth: ' + (err.message || ''), 'error'); toggle.checked = _baEnabled; });
}

function baOpenEdit() {
  _baPending = true;   // ← THE FIX: prevents SSE ticks from reverting the form

  // Re-mask credentials before switching to edit view
  const userVal = document.getElementById('ba-user-val');
  const passVal = document.getElementById('ba-pass-val');
  const revealAllBtn = document.getElementById('ba-reveal-all');
  if (userVal && !userVal.classList.contains('masked-cred')) {
    userVal.textContent = '••••••'; userVal.classList.add('masked-cred');
    clearTimeout(_baUserHideTimer);
  }
  if (passVal && !passVal.classList.contains('masked-cred')) {
    passVal.textContent = '••••••••'; passVal.classList.add('masked-cred');
    clearTimeout(_baPassHideTimer);
  }
  _setRevealAllBtn(revealAllBtn, false);

  // Hide the curl block immediately when entering edit mode
  clearTimeout(_curlHideTimer);
  const curlBlock = document.getElementById('ba-curl-block');
  if (curlBlock) { curlBlock.classList.remove('curl-fading'); curlBlock.style.display = 'none'; }

  document.getElementById('basicauth-cred-view')?.style.setProperty('display', 'none');
  document.getElementById('basicauth-controls')?.style.setProperty('display', 'block');

  // Clear any stale error message
  const msgEl = document.getElementById('basicauth-msg');
  if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }

  // Reset password field and eye icon
  const passInput = document.getElementById('basicauth-pass');
  if (passInput) { passInput.value = ''; passInput.type = 'password'; }
  _setRevealIcon(document.getElementById('ba-toggle-pass-vis'), false);
  baPassStrength();

  // Pre-fill username from server so the user only needs to re-enter the password
  if (activeTunnel) {
    fetch('/api/tunnels/basicauth-creds', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
      body: JSON.stringify({ endpoint: activeTunnel })
    })
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(d => {
        const userInput = document.getElementById('basicauth-user');
        if (userInput && d.username) {
          userInput.value = d.username;
          document.getElementById('basicauth-pass')?.focus();
        } else {
          document.getElementById('basicauth-user')?.focus();
        }
      })
      .catch(() => { document.getElementById('basicauth-user')?.focus(); });
  }
}

function baCancelEdit() {
  _baPending = false;
  // Clear form cleanly
  const userInput = document.getElementById('basicauth-user');
  const passInput = document.getElementById('basicauth-pass');
  const msgEl     = document.getElementById('basicauth-msg');
  if (userInput) userInput.value = '';
  if (passInput) { passInput.value = ''; passInput.type = 'password'; }
  _setRevealIcon(document.getElementById('ba-toggle-pass-vis'), false);
  baPassStrength();
  if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
  if (!_baEnabled) {
    const toggle = document.getElementById('basicauth-toggle');
    if (toggle) toggle.checked = false;
    _applyBasicAuthState(false);
    return;
  }
  document.getElementById('basicauth-cred-view')?.style.setProperty('display', 'block');
  document.getElementById('basicauth-controls')?.style.setProperty('display', 'none');
}

function basicAuthSave() {
  if (!activeTunnel) return;
  const userInput = document.getElementById('basicauth-user');
  const passInput = document.getElementById('basicauth-pass');
  const saveBtn   = document.getElementById('ba-save-btn');
  const msgEl     = document.getElementById('basicauth-msg');
  if (!userInput || !passInput) return;
  const username = userInput.value.trim();
  const password = passInput.value;
  const showMsg  = (t, color) => { if (msgEl) { msgEl.textContent = t; msgEl.style.display = 'block'; msgEl.style.color = color; } };
  if (!username || !password) { showMsg('Username and password are required.', 'var(--red)'); return; }
  if (username.includes(':'))   { showMsg('Username must not contain a colon.', 'var(--red)'); return; }
  if (username.length > 128 || password.length > 128) { showMsg('Credentials exceed maximum length.', 'var(--red)'); return; }
  if (msgEl) msgEl.style.display = 'none';
  if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Saving…'; }
  fetch('/api/tunnels/basicauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled: true, username, password })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(() => {
      _baPending = false; _baEnabled = true; _applyBasicAuthState(true);
      userInput.value = ''; passInput.value = '';
      passInput.type = 'password';
      _setRevealIcon(document.getElementById('ba-toggle-pass-vis'), false);
      baPassStrength();
      if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save'; }
      showToast('Basic auth credentials saved', 'success');
    })
    .catch(err => {
      if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save'; }
      showMsg(err.message || 'Failed to save credentials', 'var(--red)');
    });
}

// ── Single combined credentials reveal ───────────────────────
function _setRevealAllBtn(btn, isRevealed) {
  if (!btn) return;
  const iconEl  = btn.querySelector('.ba-reveal-icon');
  const labelEl = btn.querySelector('.ba-reveal-label');
  if (iconEl)  iconEl.innerHTML = _svgEye(isRevealed, 13);
  if (labelEl) labelEl.textContent = isRevealed ? 'Hide credentials' : 'Show credentials';
  btn.setAttribute('aria-label', isRevealed ? 'Hide credentials' : 'Show credentials');
}

function _setRevealAllLoading(btn, loading, fallbackRevealed) {
  if (!btn) return;
  const iconEl = btn.querySelector('.ba-reveal-icon');
  btn.disabled = loading;
  if (loading) {
    if (iconEl) iconEl.innerHTML = _svgSpinner(13);
  } else if (fallbackRevealed !== undefined) {
    _setRevealAllBtn(btn, fallbackRevealed);
  }
}

function baRevealAll() {
  const userVal = document.getElementById('ba-user-val');
  const passVal = document.getElementById('ba-pass-val');
  const btn     = document.getElementById('ba-reveal-all');
  if (!userVal || !passVal) return;

  // If both already revealed → hide both
  const bothRevealed = !userVal.classList.contains('masked-cred') && !passVal.classList.contains('masked-cred');
  if (bothRevealed) {
    userVal.textContent = '••••••';   userVal.classList.add('masked-cred');
    passVal.textContent = '••••••••'; passVal.classList.add('masked-cred');
    _setRevealAllBtn(btn, false);
    clearTimeout(_baUserHideTimer);
    clearTimeout(_baPassHideTimer);
    return;
  }

  if (!activeTunnel) return;
  _setRevealAllLoading(btn, true);
  fetch('/api/tunnels/basicauth-creds', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      if (d.username) { userVal.textContent = d.username; userVal.classList.remove('masked-cred'); }
      if (d.password) { passVal.textContent = d.password; passVal.classList.remove('masked-cred'); }
      _setRevealAllLoading(btn, false, true);
      clearTimeout(_baUserHideTimer);
      clearTimeout(_baPassHideTimer);
      const hide = () => {
        userVal.textContent = '••••••';   userVal.classList.add('masked-cred');
        passVal.textContent = '••••••••'; passVal.classList.add('masked-cred');
        _setRevealAllBtn(btn, false);
      };
      _baUserHideTimer = setTimeout(hide, 15000);
      _updateCurlBlock(d);
    })
    .catch(() => { _setRevealAllLoading(btn, false, false); showToast('Could not fetch credentials', 'error'); });
}

function baReveal(field) {
  const valEl = document.getElementById(field === 'user' ? 'ba-user-val' : 'ba-pass-val');
  const btnEl = document.getElementById(field === 'user' ? 'ba-user-reveal' : 'ba-pass-reveal');
  if (!valEl || !activeTunnel) return;
  if (!valEl.classList.contains('masked-cred')) {
    valEl.textContent = field === 'user' ? '••••••' : '••••••••';
    valEl.classList.add('masked-cred');
    _setRevealIcon(btnEl, false);
    return;
  }
  _setBtnLoading(btnEl, true);
  fetch('/api/tunnels/basicauth-creds', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      const val = field === 'user' ? d.username : d.password;
      if (!val) { _setBtnLoading(btnEl, false, false); return; }
      valEl.textContent = val;   // textContent — safe
      valEl.classList.remove('masked-cred');
      _setBtnLoading(btnEl, false, true);
      const hide = () => {
        valEl.textContent = field === 'user' ? '••••••' : '••••••••';
        valEl.classList.add('masked-cred');
        _setRevealIcon(btnEl, false);
      };
      if (field === 'user') _baUserHideTimer = setTimeout(hide, 15000);
      else                  _baPassHideTimer = setTimeout(hide, 15000);
      _updateCurlBlock(d);
    })
    .catch(() => { _setBtnLoading(btnEl, false, false); showToast('Could not fetch credentials', 'error'); });
}

function _updateCurlBlock(d) {
  const block    = document.getElementById('ba-curl-block');
  const codeEl   = document.getElementById('ba-curl-code');
  const proxyUrl = document.getElementById('tun-proxyurl')?.textContent || '<tunnel-url>';
  if (!block || !codeEl) return;
  // Use textContent — proxyUrl and creds come from server, not DOM strings
  codeEl.textContent = `curl -u '${d.username || '…'}:${(d.password || '…').replace(/'/g, "'\\''")}' ${proxyUrl}`;

  // Reset any ongoing fade and show fresh
  clearTimeout(_curlHideTimer);
  block.classList.remove('curl-fading');
  block.style.display = 'block';

  // Auto-hide after 15s with a smooth fade
  _curlHideTimer = setTimeout(() => {
    block.classList.add('curl-fading');
    setTimeout(() => {
      block.style.display = 'none';
      block.classList.remove('curl-fading');
    }, 500);
  }, 15000);
}

function baCopyCurl() {
  const code = document.getElementById('ba-curl-code')?.textContent;
  if (!code) return;
  copyToClipboard(code)
    .then(() => showToast('curl command copied', 'success'))
    .catch(() => showToast('Failed to copy', 'error'));
}

const _adjectives = ['swift','bright','dark','golden','silver','scarlet','azure','jade','cosmic','stellar'];
const _nouns      = ['hawk','tide','forge','spark','pulse','orbit','veil','apex','drift','echo'];
function baGenUser() {
  const el = document.getElementById('basicauth-user');
  if (!el) return;
  const adj  = _adjectives[Math.floor(Math.random() * _adjectives.length)];
  const noun = _nouns[Math.floor(Math.random() * _nouns.length)];
  const num  = Math.floor(Math.random() * 900) + 100;
  el.value   = `${adj}-${noun}-${num}`;
}

const _charset = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*-_=+';
function baGenPass() {
  const el = document.getElementById('basicauth-pass');
  if (!el) return;
  const arr = new Uint8Array(20);
  crypto.getRandomValues(arr);
  el.value = Array.from(arr, b => _charset[b % _charset.length]).join('');
  baPassStrength();
}

function baTogglePassVis() {
  const input = document.getElementById('basicauth-pass');
  const btn   = document.getElementById('ba-toggle-pass-vis');
  if (!input) return;
  const isPass = input.type === 'password';
  input.type = isPass ? 'text' : 'password';
  // isPass=true means it WAS hidden, now revealed → show eye-slash (click to hide)
  // isPass=false means it WAS visible, now hidden → show eye-open (click to reveal)
  _setRevealIcon(btn, isPass);
}

function baPassStrength() {
  const input = document.getElementById('basicauth-pass');
  const label = document.getElementById('ba-strength-label');
  if (!input) return;
  const pass = input.value;
  let score = 0;
  if (pass.length >= 8)  score++;
  if (pass.length >= 14) score++;
  if (/[^a-zA-Z0-9]/.test(pass)) score++;
  if (pass.length >= 20 && /[^a-zA-Z0-9]/.test(pass)) score++;
  const colors = ['#ef4444','#f59e0b','#3b82f6','#22c55e'];
  const labels = ['Weak','Fair','Good','Strong'];
  [1,2,3,4].forEach(i => {
    const s = document.getElementById('bas-' + i);
    if (s) s.style.background = pass.length > 0 && i <= score ? colors[score - 1] : 'var(--border)';
  });
  if (label) label.textContent = pass.length > 0 ? labels[Math.max(0, score - 1)] : '\u00a0';
}

// ── Inspector Filtering ───────────────────────────────────────
const _METHOD_FILTERS = ['GET','POST','PUT','PATCH','DELETE'];

/** Return the filtered subset of requests for the active tunnel. */
function _getFilteredReqs() {
  const reqs = reqsByTunnel[activeTunnel] || [];
  return reqs.filter(r => {
    if (_filterMethod && methodStr(r.method) !== _filterMethod) return false;
    if (_filterStatus) {
      const sc = Math.floor((r.status || 0) / 100);
      if (_filterStatus === '2xx' && sc !== 2) return false;
      if (_filterStatus === '3xx' && sc !== 3) return false;
      if (_filterStatus === '4xx' && sc !== 4) return false;
      if (_filterStatus === '5xx' && sc !== 5) return false;
    }
    if (_filterSearch) {
      const needle = _filterSearch.toLowerCase();
      const path   = (r.path || '').toLowerCase();
      const ip     = (r.client_ip || '').toLowerCase();
      if (!path.includes(needle) && !ip.includes(needle)) return false;
    }
    return true;
  });
}

function _updateFilterUI() {
  // Method pills
  _METHOD_FILTERS.forEach(m => {
    const el = document.getElementById('filt-method-' + m);
    if (el) el.classList.toggle('active', _filterMethod === m);
  });
  const resetEl = document.getElementById('filt-method-all');
  if (resetEl) resetEl.classList.toggle('active', _filterMethod === '');

  // Status pills
  ['2xx','3xx','4xx','5xx'].forEach(s => {
    const el = document.getElementById('filt-status-' + s);
    if (el) el.classList.toggle('active', _filterStatus === s);
  });
  const sAll = document.getElementById('filt-status-all');
  if (sAll) sAll.classList.toggle('active', _filterStatus === '');

  // Active filter badge
  const hasFilter = _filterMethod || _filterStatus || _filterSearch;
  const chip = document.getElementById('filter-chip');
  if (chip) {
    const active = !!hasFilter;
    chip.style.display = active ? 'flex' : 'none';
    chip.classList.toggle('show', active);
    const parts = [_filterMethod, _filterStatus, _filterSearch].filter(Boolean);
    const label = document.getElementById('filter-label');
    if (label) label.textContent = parts.length ? parts.join(' · ') : 'all';
  }
}

function setMethodFilter(m) {
  _filterMethod = (_filterMethod === m) ? '' : m;  // toggle off if same
  _updateFilterUI();
  _renderList();
}

function setStatusFilter(s) {
  _filterStatus = (_filterStatus === s) ? '' : s;
  _updateFilterUI();
  _renderList();
}

function clearAllFilters() {
  _filterMethod = ''; _filterStatus = ''; _filterSearch = '';
  const searchEl = document.getElementById('inspector-search');
  if (searchEl) searchEl.value = '';
  _updateFilterUI();
  _renderList();
}

// ── Body formatting ───────────────────────────────────────────
function _formatBody(raw) {
  if (!raw) return null;
  let text;
  try { text = atob(raw); } catch { text = raw; }
  if (!text || !text.trim()) return null;
  // Try JSON pretty-print
  try {
    const parsed = JSON.parse(text);
    return { text: JSON.stringify(parsed, null, 2), lang: 'json' };
  } catch {}
  return { text, lang: 'text' };
}

// ── Request rendering ─────────────────────────────────────────
function buildReqRow(r, isNew) {
  const row = document.createElement('div');
  row.className = 'req-row' + (isNew ? ' new-row' : '');
  row.setAttribute('role', 'listitem');

  // ── SECURITY: all user-controlled values are escaped or sanitized ──
  // r.status: could be any server value → esc()
  // r.id:     used in id= / data- attrs → safeId() forces it to an integer string
  // r.method: methodStr() constrains to known values or 'OTHER'
  // r.path, r.client_ip, r.ts: → esc()
  // r.duration_ms: numeric, but wrapped in esc(fmtDur()) for safety

  const sid    = safeId(r.id);
  const sc     = statusClass(r.status);
  const mth    = methodStr(r.method);
  const status = r.status != null ? esc(String(r.status)) : '—';
  const dur    = r.duration_ms != null ? esc(fmtDur(r.duration_ms)) : '—';

  row.innerHTML =
    `<span class="r-time">${esc(fmtTime(r.ts))}</span>` +
    `<span class="r-clientip">${esc(r.client_ip || '—')}</span>` +
    `<span class="r-method ${esc(mth)}">${esc(mth)}</span>` +
    `<span class="r-path" title="${esc(r.path)}">${esc(r.path)}</span>` +
    `<span class="r-status ${sc}">${status}</span>` +
    `<span class="r-dur">${dur}</span>` +
    `<div class="r-actions">` +
      `<button class="replay-btn" data-replay-id="${sid}" aria-label="Replay request">↺ Replay</button>` +
      `<span class="expand-icon${_expandedIds.has(r.id) ? ' open' : ''}" id="exp-${sid}">` +
        `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>` +
      `</span>` +
    `</div>`;

  const detail = document.createElement('div');
  detail.className = 'req-detail' + (_expandedIds.has(r.id) ? ' open' : '');
  detail.id = 'detail-' + sid;
  _populateDetail(detail, r);

  row.addEventListener('click', e => {
    // Don't toggle expand when clicking the replay button
    if (e.target.closest('.replay-btn')) return;
    const open = detail.classList.toggle('open');
    document.getElementById('exp-' + sid)?.classList.toggle('open', open);
    if (open) _expandedIds.add(r.id); else _expandedIds.delete(r.id);
  });

  return [row, detail];
}

function _populateDetail(detail, r) {
  const mkHeaders = obj =>
    Object.entries(obj || {}).length
      ? Object.entries(obj).map(([k, v]) =>
          `<div class="header-row"><span class="header-key">${esc(k)}</span><span class="header-val">${esc(Array.isArray(v) ? v.join(', ') : v)}</span></div>`
        ).join('')
      : `<span style="color:var(--text-3);font-size:11px">No headers</span>`;

  const body = _formatBody(r.req_body);
  let bodyHtml;
  if (body) {
    const cls = body.lang === 'json' ? 'body-preview json' : 'body-preview';
    bodyHtml = `<div class="${cls}">${esc(body.text)}</div>`;
    if (body.lang === 'json') bodyHtml = `<div class="body-preview-label">JSON</div>` + bodyHtml;
  } else {
    bodyHtml = `<span style="color:var(--text-3);font-size:11px">No body captured</span>`;
  }

  const contentType = (r.req_headers?.['Content-Type'] || r.req_headers?.['content-type'] || '');
  const size = r.req_body ? Math.ceil((r.req_body.length * 3) / 4) : 0;
  const sizeTxt = size > 0 ? esc(`${size < 1024 ? size + ' B' : (size/1024).toFixed(1) + ' KB'}`) : '';

  detail.innerHTML =
    `<div class="detail-grid">` +
      `<div class="detail-pane">` +
        `<div class="detail-pane-title">Request Headers</div>` +
        `<div class="header-table">${mkHeaders(r.req_headers)}</div>` +
        `<div class="detail-pane-title" style="margin-top:16px">` +
          `Request Body` +
          (sizeTxt ? `<span style="margin-left:6px;font-size:9px;color:var(--text-3);font-weight:400">${sizeTxt}</span>` : '') +
        `</div>` +
        `${bodyHtml}` +
      `</div>` +
      `<div class="detail-pane">` +
        `<div class="detail-pane-title">Response Headers</div>` +
        `<div class="header-table">${mkHeaders(r.resp_headers)}</div>` +
      `</div>` +
    `</div>`;
}

function _renderList() {
  if (!$list) return;
  const empty  = document.getElementById('empty-state');
  const reqs   = _getFilteredReqs();
  const total  = (reqsByTunnel[activeTunnel] || []).length;

  // Count display: filtered / total
  if ($count) {
    const filtered = reqs.length;
    $count.textContent = (filtered < total)
      ? `${filtered} / ${total}`
      : String(total);
  }

  if (reqs.length === 0) {
    $list.innerHTML = '';
    if (empty) {
      empty.style.display = 'flex';
      // Distinguish "no requests at all" from "filtered to zero"
      const hasAny = total > 0;
      empty.querySelector('p').textContent = hasAny ? 'No matching requests' : 'Waiting for requests';
      const sub = empty.querySelector('span');
      if (sub) sub.textContent = hasAny
        ? 'Try clearing or changing filters'
        : 'Requests will appear here in real time';
    }
    return;
  }

  if (empty) empty.style.display = 'none';

  // Preserve scroll position
  const tableWrap = $list.closest('.table-wrap');
  const scrollTop = tableWrap?.scrollTop ?? 0;

  const frag = document.createDocumentFragment();
  // Cap DOM to 200 rows to prevent memory bloat; newer items first
  const visible = reqs.slice(0, 200);
  visible.forEach(r => {
    const [row, detail] = buildReqRow(r, false);
    frag.appendChild(row);
    frag.appendChild(detail);
  });

  $list.innerHTML = '';
  $list.appendChild(frag);

  // Append overflow notice if we capped
  if (reqs.length > 200) {
    const note = document.createElement('div');
    note.style.cssText = 'text-align:center;padding:12px;font-size:11px;color:var(--text-3)';
    note.textContent = `Showing 200 of ${reqs.length} requests. Use filters to narrow results.`;
    $list.appendChild(note);
  }

  // Restore scroll
  if (tableWrap) tableWrap.scrollTop = scrollTop;
}

function prependReq(r) {
  if (!reqsByTunnel[r.endpoint]) reqsByTunnel[r.endpoint] = [];
  if (reqsByTunnel[r.endpoint].some(x => x.id === r.id)) return; // dedup
  reqsByTunnel[r.endpoint].unshift(r);
  if (reqsByTunnel[r.endpoint].length > REQ_CACHE_MAX) {
    reqsByTunnel[r.endpoint] = reqsByTunnel[r.endpoint].slice(0, REQ_CACHE_MAX);
  }

  // Update count even if we're on a different tab/tunnel
  if (r.endpoint === activeTunnel && $count) {
    const filtered = _getFilteredReqs().length;
    const total    = reqsByTunnel[activeTunnel].length;
    $count.textContent = filtered < total ? `${filtered} / ${total}` : String(total);
  }

  if (r.endpoint !== activeTunnel || currentTab !== 'inspector') return;

  // Only prepend if this request passes current filters
  const passes = _getFilteredReqs().some(x => x.id === r.id);
  if (!passes) return;

  const empty = document.getElementById('empty-state');
  if (empty) empty.style.display = 'none';
  if (!$list) return;

  const [row, detail] = buildReqRow(r, true);
  $list.insertBefore(detail, $list.firstChild);
  $list.insertBefore(row,    $list.firstChild);

  // Trim DOM to cap
  const rows = $list.querySelectorAll('.req-row');
  if (rows.length > 200) {
    // Remove the last row + its adjacent detail
    const last = rows[rows.length - 1];
    last.nextElementSibling?.remove();
    last.remove();
  }
}

function clearReqs() {
  if (activeTunnel) {
    reqsByTunnel[activeTunnel] = [];
  }
  _expandedIds.clear();
  _renderList();
}

function replayReq(id) {
  if (!activeTunnel) return;
  fetch('/api/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ id: parseInt(id, 10) })
  })
    .then(r => {
      if (!r.ok) {
        if (r.status === 404) throw new Error('Request not found on server (may have expired or server restarted)');
        return r.text().then(t => { throw new Error(t || 'Server error'); });
      }
      return r.text();
    })
    .then(() => showToast('Request replayed', 'success'))
    .catch(err => showToast('Replay failed: ' + (err.message || 'unknown error'), 'error'));
}

// ── Tunnel list ───────────────────────────────────────────────
function renderTunnels(tunnels) {
  if (!$tunList) return;
  lastTunnels = tunnels || [];
  lastTunnels.sort((a, b) => (a.endpoint || '').localeCompare(b.endpoint || ''));

  // Clean up request cache for tunnels that no longer exist
  const activeEndpoints = new Set(lastTunnels.map(t => t.endpoint));
  Object.keys(reqsByTunnel).forEach(ep => {
    if (!activeEndpoints.has(ep)) delete reqsByTunnel[ep];
  });

  if (!lastTunnels.length) {
    $tunList.innerHTML = '';
    const msg = document.createElement('div');
    msg.className = 'tunnel-empty-msg';
    msg.textContent = 'No active tunnels';   // textContent — safe
    $tunList.appendChild(msg);
    if (activeTunnel) { activeTunnel = null; selectTunnel(null); }
    return;
  }

  const current = activeTunnel;
  $tunList.innerHTML = '';

  lastTunnels.forEach(t => {
    const item = document.createElement('div');
    item.className = 'tunnel-item' + (t.endpoint === current ? ' active' : '');
    item.dataset.ep = t.endpoint;
    item.setAttribute('role', 'listitem');
    item.setAttribute('tabindex', '0');
    item.setAttribute('aria-label', 'Tunnel: ' + t.endpoint);

    const dot   = document.createElement('span');  dot.className = 'tunnel-dot'; dot.setAttribute('aria-hidden','true');
    const ep    = document.createElement('span');  ep.className  = 'tunnel-ep';  ep.textContent = t.endpoint;
    const badge = document.createElement('span');  badge.className = 'tunnel-type-badge'; badge.textContent = t.type || 'http';
    item.append(dot, ep, badge);
    $tunList.appendChild(item);
  });

  if (current) {
    const stillExists = lastTunnels.some(t => t.endpoint === current);
    if (!stillExists) selectTunnel(lastTunnels[0].endpoint);
    else {
      const t = lastTunnels.find(x => x.endpoint === current);
      if (t) _applyTunnelInfo(t);
    }
  } else if (lastTunnels.length === 1) {
    selectTunnel(lastTunnels[0].endpoint);
  }
}

// ── Event listeners ───────────────────────────────────────────
$hamburger?.addEventListener('click', () =>
  $sidebar?.classList.contains('open') ? closeMobileMenu() : openMobileMenu());
$mobileOverlay?.addEventListener('click', closeMobileMenu);
document.getElementById('sidebar-close')?.addEventListener('click', closeMobileMenu);

// Escape key: close mobile menu or brand dropdown
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if ($sidebar?.classList.contains('open')) { closeMobileMenu(); return; }
  const menu = document.getElementById('brand-menu');
  if (menu?.classList.contains('open')) {
    menu.classList.remove('open');
    document.getElementById('nav-brand')?.setAttribute('aria-expanded', 'false');
  }
});

window.addEventListener('resize', () => {
  if (window.innerWidth > 768) {
    closeMobileMenu();
    if ($mobileTabs) $mobileTabs.style.display = 'none';
  } else {
    if ($mobileTabs && activeTunnel) $mobileTabs.style.display = 'flex';
  }
});

// Brand dropdown
document.getElementById('nav-brand')?.addEventListener('click', e => {
  e.stopPropagation();
  const menu  = document.getElementById('brand-menu');
  const brand = document.getElementById('nav-brand');
  const open  = menu?.classList.toggle('open');
  brand?.setAttribute('aria-expanded', String(!!open));
});
document.addEventListener('click', () => {
  const menu  = document.getElementById('brand-menu');
  if (menu?.classList.contains('open')) {
    menu.classList.remove('open');
    document.getElementById('nav-brand')?.setAttribute('aria-expanded', 'false');
  }
});
document.getElementById('menu-home')?.addEventListener('click', () => {
  selectTunnel(null);
  document.getElementById('brand-menu')?.classList.remove('open');
  document.getElementById('nav-brand')?.setAttribute('aria-expanded', 'false');
});
document.getElementById('menu-home')?.addEventListener('keydown', e => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault(); selectTunnel(null);
    document.getElementById('brand-menu')?.classList.remove('open');
  }
});

// Logout — POST with CSRF to prevent CSRF-based forced logout
document.getElementById('logout-btn')?.addEventListener('click', () => {
  fetch('/logout', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } })
    .finally(() => { window.location.href = '/login'; });
});

// Token
document.getElementById('home-token-reveal')?.addEventListener('click', tokenReveal);
document.getElementById('home-token-copy')?.addEventListener('click',   tokenCopy);
document.getElementById('home-token-regen')?.addEventListener('click',  tokenRegenerate);

// Desktop / mobile tabs
['overview','inspector'].forEach(t => {
  document.getElementById('tab-' + t)?.addEventListener('click', () => switchTab(t));
  document.getElementById('mob-tab-' + t)?.addEventListener('click', () => switchTab(t));
});

// API Key
document.getElementById('apikey-toggle')?.addEventListener('change',       apikeyToggleChanged);
document.getElementById('api-reveal')?.addEventListener('click',            apiReveal);
document.getElementById('api-copy')?.addEventListener('click',              apiCopy);
document.getElementById('api-regen')?.addEventListener('click',             apiRegenerate);
document.getElementById('apikey-custom-input')?.addEventListener('input',   apikeyCustomInputChanged);
document.getElementById('apikey-custom-save')?.addEventListener('click',    apikeyCustomSave);

// Basic Auth
document.getElementById('basicauth-toggle')?.addEventListener('change',  basicAuthToggleChanged);
document.getElementById('ba-reveal-all')?.addEventListener('click',      baRevealAll);
document.getElementById('ba-edit-btn')?.addEventListener('click',        baOpenEdit);
document.getElementById('ba-save-btn')?.addEventListener('click',        basicAuthSave);
document.getElementById('ba-cancel-btn')?.addEventListener('click',      baCancelEdit);
document.getElementById('ba-gen-user')?.addEventListener('click',        baGenUser);
document.getElementById('ba-gen-pass')?.addEventListener('click',        baGenPass);
document.getElementById('ba-toggle-pass-vis')?.addEventListener('click', baTogglePassVis);
document.getElementById('basicauth-pass')?.addEventListener('input',     baPassStrength);
document.getElementById('ba-curl-copy')?.addEventListener('click',       baCopyCurl);

// Clear validation error as soon as the user edits either credential field
['basicauth-user', 'basicauth-pass'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => {
    const msgEl = document.getElementById('basicauth-msg');
    if (msgEl && msgEl.style.color === 'var(--red)') { msgEl.style.display = 'none'; }
  });
});

// AI Mode
document.getElementById('aimode-toggle')?.addEventListener('change', aiModeToggleChanged);

// Inspector controls
document.getElementById('btn-clear')?.addEventListener('click', clearReqs);
document.getElementById('filter-chip')?.addEventListener('click', clearAllFilters);

// Event Log clear button — wipes the locally-cached log display
document.getElementById('srv-log-clear')?.addEventListener('click', () => {
  const logEl   = document.getElementById('srv-event-log');
  const countEl = document.getElementById('srv-log-count');
  if (logEl) {
    logEl.innerHTML = '';
    const msg = document.createElement('div');
    msg.className = 'empty'; msg.textContent = 'No events yet...';
    logEl.appendChild(msg);
    logEl._empty = true;
    logEl._sig   = '';   // force re-render on next SSE tick
  }
  if (countEl) countEl.textContent = '';
});

// Inspector search
document.getElementById('inspector-search')?.addEventListener('input', e => {
  _filterSearch = e.target.value.trim();
  _updateFilterUI();
  _renderList();
});

// Inspector method filter pills (delegated)
document.getElementById('method-filters')?.addEventListener('click', e => {
  const btn = e.target.closest('[data-method]');
  if (!btn) return;
  const m = btn.dataset.method;
  _filterMethod = (_filterMethod === m) ? '' : m;
  _updateFilterUI();
  _renderList();
});

// Inspector status filter pills (delegated)
document.getElementById('status-filters')?.addEventListener('click', e => {
  const btn = e.target.closest('[data-status]');
  if (!btn) return;
  const s = btn.dataset.status;
  _filterStatus = (_filterStatus === s) ? '' : s;
  _updateFilterUI();
  _renderList();
});

// Request replay — event delegation
$list?.addEventListener('click', e => {
  const btn = e.target.closest('.replay-btn');
  if (btn) {
    e.stopPropagation();
    const id = safeId(btn.dataset.replayId);
    replayReq(id);
  }
});

// Tunnel list — event delegation
$tunList?.addEventListener('click', e => {
  const item = e.target.closest('.tunnel-item');
  if (item?.dataset?.ep) selectTunnel(item.dataset.ep);
});
$tunList?.addEventListener('keydown', e => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const item = e.target.closest('.tunnel-item');
  if (item?.dataset?.ep) { e.preventDefault(); selectTunnel(item.dataset.ep); }
});

// ── Boot ─────────────────────────────────────────────────────
(function boot() {
  _renderList();

  // Merge in server's ring buffer
  fetch('/api/requests', { headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => r.ok ? r.json() : [])
    .then(arr => {
      if (!Array.isArray(arr)) return;
      const byEp = {};
      arr.forEach(r => { if (r.endpoint) { if (!byEp[r.endpoint]) byEp[r.endpoint] = []; byEp[r.endpoint].push(r); } });
      Object.keys(byEp).forEach(ep => {
        reqsByTunnel[ep] = _mergeReqs(reqsByTunnel[ep] || [], byEp[ep]);
      });
      _renderList();
    })
    .catch(() => {});

  // Initial tunnel list
  fetch('/api/tunnels', { headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => r.ok ? r.json() : [])
    .then(arr => { if (Array.isArray(arr)) renderTunnels(arr); })
    .catch(() => {});

  let _lastUptime = -1;
  // Status SSE — uptime + tunnels + logs
  function connectStatus() {
    const evs = new EventSource('/api/status/stream');
    evs.onmessage = e => {
      try {
        const d = JSON.parse(e.data);
        if (d.uptime_sec != null) {
          if (_lastUptime !== -1 && d.uptime_sec < _lastUptime) {
            Object.keys(reqsByTunnel).forEach(ep => { reqsByTunnel[ep] = []; });
            _expandedIds.clear();
            const logEl = document.getElementById('srv-event-log');
            if (logEl) { logEl.innerHTML = '<div class="empty">No events yet...</div>'; logEl._empty = true; }
            _renderList();
          }
          _lastUptime = d.uptime_sec;
          if ($uptime) $uptime.textContent = fmtUptime(d.uptime_sec);
        }
        if (Array.isArray(d.tunnels)) renderTunnels(d.tunnels);

        const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val || '—'; };
        setTxt('srv-http',      d.server);
        setTxt('srv-tun',       d.tun_addr);
        setTxt('srv-https',     d.https_addr);
        setTxt('srv-dash-addr', d.inspect_addr
          ? (d.inspect_addr.startsWith(':') ? 'http://localhost' + d.inspect_addr : 'http://' + d.inspect_addr)
          : '—');
        setTxt('srv-dash-user', d.dash_user);
        // NOTE: d.dash_pass is always "[redacted]" — the server intentionally
        // never sends the real password over the SSE stream. No value is stored
        // on window or any global. The dashboard password field is display-only.

        if (Array.isArray(d.logs)) {
          const logEl    = document.getElementById('srv-event-log');
          const countEl  = document.getElementById('srv-log-count');
          if (logEl) {
            if (d.logs.length === 0) {
              if (!logEl._empty) {
                logEl.innerHTML = '';
                const msg = document.createElement('div');
                msg.className = 'empty'; msg.textContent = 'No events yet...';
                logEl.appendChild(msg);
                logEl._empty = true;
              }
              if (countEl) countEl.textContent = '';
            } else {
              const lastLog = d.logs[d.logs.length - 1];
              const sig     = d.logs.length + ':' + (lastLog?.time || '');
              if (logEl._sig !== sig) {
                logEl._sig   = sig;
                logEl._empty = false;
                logEl.innerHTML = '';
                if (countEl) countEl.textContent = d.logs.length;
                const frag = document.createDocumentFragment();
                d.logs.forEach(l => {
                  const row = document.createElement('div');
                  row.className = 'hv-log-row';

                  // ── Timestamp ──
                  const ts = document.createElement('span');
                  ts.className   = 'hv-log-ts';
                  ts.textContent = fmtTime(l.time);

                  // ── Level icon ──
                  let lvlClass = 'info', sym = 'ℹ';
                  switch (l.level) {
                    case 1: lvlClass = 'warn';  sym = '⚠'; break;
                    case 2: lvlClass = 'error'; sym = '✗'; break;
                    case 3: lvlClass = 'ok';    sym = '✓'; break;
                  }
                  const ic = document.createElement('span');
                  ic.className   = 'hv-log-ic';
                  ic.textContent = sym;

                  // ── Level label ──
                  const lvl = document.createElement('span');
                  lvl.className   = 'hv-log-lvl ' + lvlClass;
                  lvl.textContent = lvlClass.toUpperCase();

                  // ── Body ──
                  const body = document.createElement('span');
                  body.className = 'hv-log-body';

                  if (l.tunnel) {
                    const tb = document.createElement('span');
                    tb.className   = 'hv-log-tunnel';
                    tb.textContent = l.tunnel;
                    tb.title       = 'Tunnel: ' + l.tunnel;
                    body.appendChild(tb);
                  }

                  // Structured HTTP entry
                  if (l.method && l.status) {
                    const mth = String(l.method || '').toUpperCase();
                    const mEl = document.createElement('span');
                    mEl.className   = 'hv-log-method ' + (mth || '');
                    mEl.textContent = mth;
                    body.appendChild(mEl);

                    if (l.path) {
                      const pEl = document.createElement('span');
                      pEl.className   = 'hv-log-path';
                      pEl.textContent = l.path;
                      pEl.title       = l.path;
                      body.appendChild(pEl);
                    }

                    const sc   = Math.floor(l.status / 100);
                    const sEl  = document.createElement('span');
                    sEl.className   = 'hv-log-status s' + sc;
                    sEl.textContent = l.status;
                    body.appendChild(sEl);

                    if (l.duration && l.duration !== '0s') {
                      const dEl = document.createElement('span');
                      dEl.className   = 'hv-log-dur';
                      dEl.textContent = l.duration;
                      body.appendChild(dEl);
                    }

                    if (l.clientIP) {
                      const ipEl = document.createElement('span');
                      ipEl.className   = 'hv-log-ip';
                      ipEl.textContent = l.clientIP;
                      body.appendChild(ipEl);
                    }
                  } else {
                    // Plain message fallback
                    const msgEl = document.createElement('span');
                    msgEl.className   = 'hv-log-msg';
                    msgEl.textContent = l.message;
                    body.appendChild(msgEl);
                  }

                  row.append(ts, ic, lvl, body);
                  frag.appendChild(row);
                });
                logEl.appendChild(frag);
                logEl.scrollTop = logEl.scrollHeight;
              }
            }
          }
        }
      } catch {}
    };
    evs.onerror = () => { evs.close(); setTimeout(connectStatus, 3000); };
  }

  // Request SSE — one CapturedRequest per proxied request
  function connectRequests() {
    const evs = new EventSource('/api/requests/stream');
    evs.onmessage = e => {
      try { prependReq(JSON.parse(e.data)); } catch {}
    };
    evs.onerror = () => { evs.close(); setTimeout(connectRequests, 3000); };
  }

  connectStatus();
  connectRequests();
})();

// ── Dark mode ─────────────────────────────────────────────────
(function () {
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const root = document.documentElement;
    const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('gotunnel-theme', next);
  });
})();
