'use strict';

// ── CSRF ─────────────────────────────────────────────────────
/** Read the CSRF token set by the server in the gotunnel_csrf cookie. */
function getCsrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)gotunnel_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

// ── State ────────────────────────────────────────────────────
let activeTunnel      = null;
let currentTab        = 'overview';
let reqs              = [];
let lastTunnels       = [];   // cached from /api/status/stream or /api/tunnels
let _tokenHideTimer   = null;
let _apikeyHideTimer  = null;
let _baUserHideTimer  = null;
let _baPassHideTimer  = null;
let _apikeyEnabled    = false;
let _baEnabled        = false;
let _aiEnabled        = false;

// ── DOM refs ─────────────────────────────────────────────────
const $list     = document.getElementById('req-list');
const $count    = document.getElementById('t-count');
const $empty    = document.getElementById('empty-state');
const $tunList  = document.getElementById('tunnel-list');
const $uptime   = document.getElementById('uptime');

// ── Mobile drawer ─────────────────────────────────────────────
const $sidebar        = document.getElementById('sidebar');
const $mobileOverlay  = document.getElementById('mobile-overlay');
const $hamburger      = document.getElementById('nav-hamburger');
const $mobileTabs     = document.getElementById('mobile-tabs');
const $navActiveTun   = document.getElementById('nav-active-tunnel');

function openMobileMenu() {
  if (!$sidebar) return;
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

  const tabOverview  = document.getElementById('tab-overview');
  const tabInspector = document.getElementById('tab-inspector');
  tabOverview?.classList.toggle('active', tab === 'overview');
  tabInspector?.classList.toggle('active', tab === 'inspector');
  tabOverview?.setAttribute('aria-selected',  String(tab === 'overview'));
  tabInspector?.setAttribute('aria-selected', String(tab === 'inspector'));

  const mobTabOvr = document.getElementById('mob-tab-overview');
  const mobTabIns = document.getElementById('mob-tab-inspector');
  mobTabOvr?.classList.toggle('active', tab === 'overview');
  mobTabIns?.classList.toggle('active', tab === 'inspector');
  mobTabOvr?.setAttribute('aria-selected',  String(tab === 'overview'));
  mobTabIns?.setAttribute('aria-selected', String(tab === 'inspector'));

  const viewOvr = document.getElementById('view-overview');
  const viewIns = document.getElementById('view-inspector');
  if (viewOvr) viewOvr.style.display = tab === 'overview'  ? 'flex' : 'none';
  if (viewIns) viewIns.style.display = tab === 'inspector' ? 'flex' : 'none';
}

function selectTunnel(ep) {
  closeMobileMenu();
  activeTunnel = ep;

  // Update active tunnel name shown in mobile nav
  if ($navActiveTun) $navActiveTun.textContent = ep ? ep : '';

  const viewEmpty = document.getElementById('view-empty');
  const navTabs   = document.getElementById('nav-tabs');

  if (!ep) {
    if (viewEmpty) viewEmpty.style.display = 'flex';
    if (navTabs)   navTabs.style.display   = 'none';
    if ($mobileTabs) $mobileTabs.style.display = 'none';

    const viewOvr = document.getElementById('view-overview');
    const viewIns = document.getElementById('view-inspector');
    if (viewOvr) viewOvr.style.display = 'none';
    if (viewIns) viewIns.style.display = 'none';

    _clearTunnelInfo();
    return;
  }

  if (viewEmpty) viewEmpty.style.display = 'none';
  if (navTabs)   navTabs.style.display   = 'flex';

  // Only show mobile tabs on mobile-sized screens
  if ($mobileTabs) {
    $mobileTabs.style.display = window.innerWidth <= 768 ? 'flex' : 'none';
  }

  // Highlight active item in tunnel list
  document.querySelectorAll('.tunnel-item').forEach(el => {
    el.classList.toggle('active', el.dataset.ep === ep);
  });

  if (ep) {
    // Look up info from the cached tunnel list (populated by status stream).
    // If not yet available it will be applied on the next status tick.
    const t = lastTunnels.find(x => x.endpoint === ep);
    if (t) _applyTunnelInfo(t);
    switchTab(currentTab);
  }
}

// ── Helpers ──────────────────────────────────────────────────
function fmtTime(ts) {
  // ts is an ISO 8601 string from Go's time.Time JSON marshaling, e.g. "2024-01-15T14:23:01.123Z"
  const d = new Date(ts);
  return isNaN(d) ? '—' : d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function fmtDur(ms) {
  if (ms >= 1000) return (ms / 1000).toFixed(2) + 's';
  return ms + 'ms';
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function statusClass(code) {
  if (code >= 500) return 's5';
  if (code >= 400) return 's4';
  if (code >= 300) return 's3';
  if (code >= 200) return 's2';
  return '';
}

function methodStr(m) {
  const known = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE'];
  const u = String(m).toUpperCase();
  return known.includes(u) ? u : u.slice(0, 10);
}

function copyToClipboard(text) {
  return navigator.clipboard
    ? navigator.clipboard.writeText(text)
    : new Promise((res, rej) => {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        document.execCommand('copy') ? res() : rej();
        ta.remove();
      });
}

function _clearTunnelInfo() {
  ['tun-proxyurl','tun-clientip','tun-type','tun-conns'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '—';
  });
  const authSection = document.getElementById('tunnel-auth-section');
  if (authSection) authSection.style.display = 'none';
  reqs = [];
  _renderList();
}

/**
 * Apply a TunnelEntry (snake_case fields from Go) to the overview panel.
 * Called whenever the tunnel list updates while a tunnel is selected,
 * and when selectTunnel() picks an item from the cached list.
 */
function _applyTunnelInfo(t) {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v != null ? String(v) : '—') || '—'; };
  set('tun-proxyurl', t.proxy_url);
  set('tun-clientip', t.client_ip);
  set('tun-type',     t.type);
  set('tun-conns',    t.connections ?? 0);

  const authSection = document.getElementById('tunnel-auth-section');
  if (authSection) authSection.style.display = 'block';

  _apikeyEnabled = !!t.apikey_enabled;
  _baEnabled     = !!t.basicauth_enabled;
  _aiEnabled     = !!t.aimode_enabled;

  _applyApikeyState(_apikeyEnabled, false);
  _applyBasicAuthState(_baEnabled);
  _applyAiModeState(_aiEnabled);
}

// ── Toast notifications ───────────────────────────────────────
function showToast(msg, type = 'info', duration = 3000) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast' + (type !== 'info' ? ' ' + type : '');
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = 'opacity .3s, transform .3s';
    toast.style.opacity    = '0';
    toast.style.transform  = 'translateY(6px)';
    setTimeout(() => toast.remove(), 320);
  }, duration);
}

// ── Token (session) ───────────────────────────────────────────
function tokenReveal() {
  const val = document.getElementById('nav-token-val');
  const btn = document.getElementById('token-reveal-btn');
  if (!val) return;

  if (!val.classList.contains('masked')) {
    _maskToken(); return;
  }

  fetch('/api/token', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      if (!d.token) return;
      val.textContent = d.token;
      val.classList.remove('masked');
      val.style.display = '';
      if (btn) btn.title = 'Hide';
      clearTimeout(_tokenHideTimer);
      _tokenHideTimer = setTimeout(_maskToken, 30000);
    })
    .catch(() => showToast('Could not fetch token', 'error'));
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
  fetch('/api/token', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      if (!d.token) throw new Error();
      return copyToClipboard(d.token);
    })
    .then(() => showToast('Token copied to clipboard', 'success'))
    .catch(() => showToast('Could not copy token', 'error'));
}

// ── API Key ───────────────────────────────────────────────────
function _applyApikeyState(enabled, skipServer) {
  const toggle  = document.getElementById('apikey-toggle');
  const badge   = document.getElementById('apikey-badge');
  const controls = document.getElementById('apikey-controls');
  const disabledMsg = document.getElementById('apikey-disabled-msg');

  if (toggle) toggle.checked = enabled;
  if (badge) {
    badge.textContent = enabled ? 'On' : 'Off';
    badge.className   = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled');
  }
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
    .then(() => {
      _apikeyEnabled = enabled;
      _applyApikeyState(enabled, false);
      showToast('API key auth ' + (enabled ? 'enabled' : 'disabled'), 'success');
    })
    .catch(err => {
      showToast('Failed to update API key: ' + (err.message || 'unknown error'), 'error');
      toggle.checked = _apikeyEnabled; // revert
    });
}

function apiReveal() {
  const val = document.getElementById('api-val');
  const btn = document.getElementById('api-reveal');
  if (!val || !activeTunnel) return;

  if (!val.classList.contains('masked')) { _maskApiKey(); return; }

  // POST + CSRF: prevents CSRF-based forced reads of the API key
  fetch('/api/tunnels/apikey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      if (!d.apikey) return;
      val.textContent = d.apikey;
      val.classList.remove('masked');
      if (btn) btn.title = 'Hide key';
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
  if (!activeTunnel) return;
  fetch('/api/tunnels/apikey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      if (!d.apikey) throw new Error('No key');
      return copyToClipboard(d.apikey);
    })
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
  const input = document.getElementById('apikey-custom-input');
  const saveBtn = document.getElementById('apikey-custom-save');
  const bar   = document.getElementById('apikey-strength-bar');
  const label = document.getElementById('apikey-strength-label');
  if (!input) return;

  const val = input.value.trim();
  if (saveBtn) saveBtn.disabled = val.length === 0;
  if (!bar || !label) return;

  bar.style.display = val.length > 0 ? 'flex' : 'none';
  const segs = [1,2,3,4].map(i => document.getElementById('aks-' + i));

  let score = 0, tip = '';
  if (val.length >= 8)  score++;
  if (val.length >= 20) score++;
  if (/[^a-zA-Z0-9]/.test(val)) score++;
  if (val.length >= 32) score++;

  const colors = ['#ef4444','#f59e0b','#3b82f6','#22c55e'];
  const labels = ['Weak — too short','Fair — try longer','Good','Strong'];
  segs.forEach((s, i) => { if (s) s.style.background = i < score ? colors[score - 1] : 'var(--border)'; });
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
  if (badge) {
    badge.textContent = enabled ? 'On' : 'Off';
    badge.className   = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled');
  }

  const feats = {
    'ai-feat-body':  [enabled ? 'Unlimited' : '10 MB',   enabled],
    'ai-feat-flush': [enabled ? 'Immediate'  : '32 KB',  enabled],
    'ai-feat-cors':  [enabled ? 'Enabled'    : 'Disabled', enabled],
    'ai-feat-buf':   [enabled ? 'Disabled'   : 'Enabled',  enabled],
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
    .then(() => {
      _aiEnabled = enabled;
      _applyAiModeState(enabled);
      showToast('AI optimization ' + (enabled ? 'enabled' : 'disabled'), 'success');
    })
    .catch(err => {
      showToast('Failed to update AI mode: ' + (err.message || ''), 'error');
      toggle.checked = _aiEnabled;
    });
}

// ── Basic Auth ────────────────────────────────────────────────
function _applyBasicAuthState(enabled) {
  const toggle   = document.getElementById('basicauth-toggle');
  const badge    = document.getElementById('basicauth-badge');
  const credView = document.getElementById('basicauth-cred-view');
  const controls = document.getElementById('basicauth-controls');
  const disabledMsg = document.getElementById('basicauth-disabled-msg');

  if (toggle) toggle.checked = enabled;
  if (badge) {
    badge.textContent = enabled ? 'On' : 'Off';
    badge.className   = 'card-section-badge ' + (enabled ? 'enabled' : 'disabled');
  }
  if (credView)    credView.style.display    = enabled ? 'block' : 'none';
  if (controls)    controls.style.display    = 'none';
  if (disabledMsg) disabledMsg.style.display = enabled ? 'none'  : 'block';
}

function basicAuthToggleChanged() {
  const toggle = document.getElementById('basicauth-toggle');
  if (!toggle || !activeTunnel) return;
  const enabled = toggle.checked;

  if (enabled) {
    // Show the edit form so user can set credentials first
    _applyBasicAuthState(false);
    const controls  = document.getElementById('basicauth-controls');
    const credView  = document.getElementById('basicauth-cred-view');
    const disabledMsg = document.getElementById('basicauth-disabled-msg');
    if (controls)    controls.style.display    = 'block';
    if (credView)    credView.style.display    = 'none';
    if (disabledMsg) disabledMsg.style.display = 'none';
    toggle.checked = true;

    const msgEl = document.getElementById('basicauth-msg');
    if (msgEl) { msgEl.textContent = 'Enter credentials and click Apply to enable.'; msgEl.style.display = 'block'; msgEl.style.color = 'var(--text-3)'; }
    return;
  }

  // Disable
  fetch('/api/tunnels/basicauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled: false })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(() => {
      _baEnabled = false;
      _applyBasicAuthState(false);
      showToast('Basic auth disabled', 'success');
    })
    .catch(err => {
      showToast('Failed to disable basic auth: ' + (err.message || ''), 'error');
      toggle.checked = _baEnabled;
    });
}

function baOpenEdit() {
  const credView = document.getElementById('basicauth-cred-view');
  const controls = document.getElementById('basicauth-controls');
  if (credView) credView.style.display = 'none';
  if (controls) controls.style.display = 'block';
}

function baCancelEdit() {
  const credView = document.getElementById('basicauth-cred-view');
  const controls = document.getElementById('basicauth-controls');
  if (!_baEnabled) {
    const toggle = document.getElementById('basicauth-toggle');
    if (toggle) toggle.checked = false;
    _applyBasicAuthState(false);
    return;
  }
  if (credView) credView.style.display = 'block';
  if (controls) controls.style.display = 'none';
}

function basicAuthSave() {
  if (!activeTunnel) return;
  const userInput = document.getElementById('basicauth-user');
  const passInput = document.getElementById('basicauth-pass');
  const msgEl     = document.getElementById('basicauth-msg');
  if (!userInput || !passInput) return;

  const username = userInput.value.trim();
  const password = passInput.value;

  if (!username || !password) {
    if (msgEl) { msgEl.textContent = 'Username and password are required.'; msgEl.style.display = 'block'; msgEl.style.color = 'var(--red)'; }
    return;
  }
  if (username.includes(':')) {
    if (msgEl) { msgEl.textContent = 'Username must not contain a colon.'; msgEl.style.display = 'block'; msgEl.style.color = 'var(--red)'; }
    return;
  }
  if (username.length > 128 || password.length > 128) {
    if (msgEl) { msgEl.textContent = 'Credentials exceed maximum length.'; msgEl.style.display = 'block'; msgEl.style.color = 'var(--red)'; }
    return;
  }

  if (msgEl) msgEl.style.display = 'none';

  fetch('/api/tunnels/basicauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, enabled: true, username, password })
  })
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t); }); return r.json(); })
    .then(() => {
      _baEnabled = true;
      _applyBasicAuthState(true);
      userInput.value = '';
      passInput.value = '';
      baPassStrength();
      showToast('Basic auth credentials saved', 'success');
    })
    .catch(err => {
      const txt = err.message || 'Failed to save credentials';
      if (msgEl) { msgEl.textContent = txt; msgEl.style.display = 'block'; msgEl.style.color = 'var(--red)'; }
    });
}

function baReveal(field) {
  const valEl  = document.getElementById(field === 'user' ? 'ba-user-val'  : 'ba-pass-val');
  const btnEl  = document.getElementById(field === 'user' ? 'ba-user-reveal' : 'ba-pass-reveal');
  const timer  = field === 'user' ? _baUserHideTimer : _baPassHideTimer;

  if (!valEl || !activeTunnel) return;

  if (!valEl.classList.contains('masked-cred')) {
    valEl.textContent = field === 'user' ? '••••••' : '••••••••';
    valEl.classList.add('masked-cred');
    clearTimeout(timer);
    return;
  }

  fetch('/api/tunnels/basicauth-creds', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(d => {
      const val = field === 'user' ? d.username : d.password;
      if (!val) return;
      valEl.textContent = val;
      valEl.classList.remove('masked-cred');
      if (btnEl) btnEl.title = 'Hide';
      const hide = () => {
        valEl.textContent = field === 'user' ? '••••••' : '••••••••';
        valEl.classList.add('masked-cred');
        if (btnEl) btnEl.title = 'Reveal';
      };
      if (field === 'user') _baUserHideTimer = setTimeout(hide, 15000);
      else                  _baPassHideTimer = setTimeout(hide, 15000);

      _updateCurlBlock(d);
    })
    .catch(() => showToast('Could not fetch credentials', 'error'));
}

function _updateCurlBlock(d) {
  const block    = document.getElementById('ba-curl-block');
  const codeEl   = document.getElementById('ba-curl-code');
  const proxyUrl = document.getElementById('tun-proxyurl')?.textContent || '<tunnel-url>';
  if (!block || !codeEl) return;
  const userPart  = d.username || '…';
  const passPart  = (d.password || '…').replace(/'/g, "'\\''");
  codeEl.textContent = `curl -u '${userPart}:${passPart}' ${proxyUrl}`;
  block.style.display = 'block';
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
  const arr    = new Uint8Array(20);
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
  if (btn) btn.title = isPass ? 'Hide password' : 'Show password';
}

function baPassStrength() {
  const input = document.getElementById('basicauth-pass');
  const label = document.getElementById('ba-strength-label');
  if (!input) return;

  const pass = input.value;
  const segs = [1,2,3,4].map(i => document.getElementById('bas-' + i));

  let score = 0;
  if (pass.length >= 8)  score++;
  if (pass.length >= 14) score++;
  if (/[^a-zA-Z0-9]/.test(pass)) score++;
  if (pass.length >= 20 && /[^a-zA-Z0-9]/.test(pass)) score++;

  const colors = ['#ef4444','#f59e0b','#3b82f6','#22c55e'];
  const labels = ['Weak','Fair','Good','Strong'];
  segs.forEach((s, i) => { if (s) s.style.background = pass.length > 0 && i < score ? colors[score - 1] : 'var(--border)'; });
  if (label) label.textContent = pass.length > 0 ? labels[Math.max(0, score - 1)] : '\u00a0';
}

// ── Request rendering ─────────────────────────────────────────
function buildReqRow(r, isNew) {
  const row = document.createElement('div');
  row.className = 'req-row' + (isNew ? ' new-row' : '');
  row.setAttribute('role', 'listitem');

  const sc  = statusClass(r.status);
  const mth = methodStr(r.method);

  row.innerHTML =
    `<span class="r-time">${esc(fmtTime(r.ts))}</span>` +
    `<span class="r-clientip">${esc(r.client_ip || '—')}</span>` +
    `<span class="r-method ${mth}">${mth}</span>` +
    `<span class="r-path" title="${esc(r.path)}">${esc(r.path)}</span>` +
    `<span class="r-status ${sc}">${r.status || '—'}</span>` +
    `<span class="r-dur">${r.duration_ms != null ? esc(fmtDur(r.duration_ms)) : '—'}</span>` +
    `<div class="r-actions">` +
      `<button class="replay-btn" data-replay-id="${r.id}" aria-label="Replay request">↺ Replay</button>` +
      `<span class="expand-icon" id="exp-${r.id}">` +
        `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>` +
      `</span>` +
    `</div>`;

  const detail = document.createElement('div');
  detail.className = 'req-detail';
  detail.id = 'detail-' + r.id;
  detail.innerHTML = _buildDetail(r);

  row.addEventListener('click', () => {
    detail.classList.toggle('open');
    document.getElementById('exp-' + r.id)?.classList.toggle('open');
  });

  return [row, detail];
}

function _buildDetail(r) {
  const reqHeaders = Object.entries(r.req_headers || {})
    .map(([k, v]) => `<div class="header-row"><span class="header-key">${esc(k)}</span><span class="header-val">${esc(v)}</span></div>`)
    .join('') || '<span style="color:var(--text-3);font-size:11px">No headers</span>';

  const resHeaders = Object.entries(r.resp_headers || {})
    .map(([k, v]) => `<div class="header-row"><span class="header-key">${esc(k)}</span><span class="header-val">${esc(v)}</span></div>`)
    .join('') || '<span style="color:var(--text-3);font-size:11px">No headers</span>';

  // req_body is base64-encoded (Go []byte JSON marshaling)
  let bodyText = null;
  if (r.req_body) {
    try { bodyText = atob(r.req_body); } catch { bodyText = r.req_body; }
  }
  const bodyHtml = bodyText
    ? `<div class="body-preview">${esc(bodyText)}</div>`
    : `<span style="color:var(--text-3);font-size:11px">No body captured</span>`;

  return `<div class="detail-grid">
    <div class="detail-pane">
      <div class="detail-pane-title">Request Headers</div>
      <div class="header-table">${reqHeaders}</div>
    </div>
    <div class="detail-pane">
      <div class="detail-pane-title">Response Headers</div>
      <div class="header-table">${resHeaders}</div>
      <div class="detail-pane-title" style="margin-top:12px">Request Body</div>
      ${bodyHtml}
    </div>
  </div>`;
}

function _renderList() {
  if (!$list) return;
  $list.innerHTML = '';
  const empty = document.getElementById('empty-state');

  if (reqs.length === 0) {
    if (empty) empty.style.display = 'flex';
    if ($count) $count.textContent = '0';
    return;
  }
  if (empty) empty.style.display = 'none';
  if ($count) $count.textContent = reqs.length;

  const frag = document.createDocumentFragment();
  reqs.forEach(r => {
    const [row, detail] = buildReqRow(r, false);
    frag.appendChild(row);
    frag.appendChild(detail);
  });
  $list.appendChild(frag);
}

function prependReq(r) {
  reqs.unshift(r);
  if ($count) $count.textContent = reqs.length;
  const empty = document.getElementById('empty-state');
  if (empty) empty.style.display = 'none';

  if (!$list) return;
  const [row, detail] = buildReqRow(r, true);
  $list.insertBefore(detail, $list.firstChild);
  $list.insertBefore(row, $list.firstChild);
}

function clearReqs() {
  reqs = [];
  _renderList();
}

function replayReq(id) {
  if (!activeTunnel) return;
  fetch('/api/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    body: JSON.stringify({ endpoint: activeTunnel, id: id })
  })
    .then(r => { if (!r.ok) throw new Error(); return r.json(); })
    .then(() => showToast('Request replayed', 'success'))
    .catch(() => showToast('Replay failed', 'error'));
}

// ── Tunnel list rendering ─────────────────────────────────────
/**
 * Render the sidebar tunnel list.
 * @param {Array} tunnels - flat array of TunnelEntry objects (snake_case fields).
 */
function renderTunnels(tunnels) {
  if (!$tunList) return;
  lastTunnels = tunnels || [];

  if (!lastTunnels.length) {
    $tunList.innerHTML = '<div class="tunnel-empty-msg">No active tunnels</div>';
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
    item.setAttribute('aria-label', `Tunnel: ${t.endpoint}`);
    item.innerHTML =
      `<span class="tunnel-dot" aria-hidden="true"></span>` +
      `<span class="tunnel-ep">${esc(t.endpoint)}</span>` +
      `<span class="tunnel-type-badge">${esc(t.type || 'http')}</span>`;
    $tunList.appendChild(item);
  });

  // Re-apply info for the currently selected tunnel (fields may have updated)
  if (current) {
    const stillExists = lastTunnels.some(t => t.endpoint === current);
    if (!stillExists) {
      selectTunnel(lastTunnels[0].endpoint);
    } else {
      const t = lastTunnels.find(x => x.endpoint === current);
      if (t) _applyTunnelInfo(t);
    }
  } else if (lastTunnels.length === 1) {
    selectTunnel(lastTunnels[0].endpoint);
  }
}

// ── Uptime ────────────────────────────────────────────────────
function fmtUptime(s) {
  if (s < 60)   return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}

// ── Event listeners ───────────────────────────────────────────
// Mobile drawer
$hamburger?.addEventListener('click', () => {
  $sidebar?.classList.contains('open') ? closeMobileMenu() : openMobileMenu();
});
$mobileOverlay?.addEventListener('click', closeMobileMenu);
document.getElementById('sidebar-close')?.addEventListener('click', closeMobileMenu);

// Close drawer on resize if no longer mobile
window.addEventListener('resize', () => {
  if (window.innerWidth > 768) {
    closeMobileMenu();
    if ($mobileTabs && activeTunnel) $mobileTabs.style.display = 'none';
  } else {
    if ($mobileTabs && activeTunnel) $mobileTabs.style.display = 'flex';
  }
});

// Brand menu
document.getElementById('nav-brand')?.addEventListener('click', e => {
  e.stopPropagation();
  const menu  = document.getElementById('brand-menu');
  const brand = document.getElementById('nav-brand');
  const open  = menu?.classList.toggle('open');
  brand?.setAttribute('aria-expanded', String(!!open));
});
document.addEventListener('click', () => {
  const menu  = document.getElementById('brand-menu');
  const brand = document.getElementById('nav-brand');
  if (menu?.classList.contains('open')) {
    menu.classList.remove('open');
    brand?.setAttribute('aria-expanded', 'false');
  }
});
document.getElementById('menu-home')?.addEventListener('click', () => {
  selectTunnel(null);
  document.getElementById('brand-menu')?.classList.remove('open');
  document.getElementById('nav-brand')?.setAttribute('aria-expanded', 'false');
});
document.getElementById('menu-home')?.addEventListener('keydown', e => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    selectTunnel(null);
    document.getElementById('brand-menu')?.classList.remove('open');
  }
});

// Logout — POST with CSRF to prevent CSRF-based forced logout
document.getElementById('logout-btn')?.addEventListener('click', () => {
  fetch('/logout', {
    method: 'POST',
    headers: { 'X-CSRF-Token': getCsrfToken() }
  })
    .then(() => { window.location.href = '/login'; })
    .catch(() => { window.location.href = '/login'; });
});

// Token
document.getElementById('token-reveal-btn')?.addEventListener('click', tokenReveal);
document.getElementById('token-copy-btn')?.addEventListener('click',   tokenCopy);

// Desktop nav tabs
document.getElementById('tab-overview')?.addEventListener('click',  () => switchTab('overview'));
document.getElementById('tab-inspector')?.addEventListener('click', () => switchTab('inspector'));

// Mobile bottom tabs
document.getElementById('mob-tab-overview')?.addEventListener('click',  () => switchTab('overview'));
document.getElementById('mob-tab-inspector')?.addEventListener('click', () => switchTab('inspector'));

// API Key section
document.getElementById('apikey-toggle')?.addEventListener('change',      apikeyToggleChanged);
document.getElementById('api-reveal')?.addEventListener('click',           apiReveal);
document.getElementById('api-copy')?.addEventListener('click',             apiCopy);
document.getElementById('api-regen')?.addEventListener('click',            apiRegenerate);
document.getElementById('apikey-custom-input')?.addEventListener('input',  apikeyCustomInputChanged);
document.getElementById('apikey-custom-save')?.addEventListener('click',   apikeyCustomSave);

// Basic Auth section
document.getElementById('basicauth-toggle')?.addEventListener('change',    basicAuthToggleChanged);
document.getElementById('ba-user-reveal')?.addEventListener('click',       () => baReveal('user'));
document.getElementById('ba-pass-reveal')?.addEventListener('click',       () => baReveal('pass'));
document.getElementById('ba-edit-btn')?.addEventListener('click',          baOpenEdit);
document.getElementById('ba-save-btn')?.addEventListener('click',          basicAuthSave);
document.getElementById('ba-cancel-btn')?.addEventListener('click',        baCancelEdit);
document.getElementById('ba-gen-user')?.addEventListener('click',          baGenUser);
document.getElementById('ba-gen-pass')?.addEventListener('click',          baGenPass);
document.getElementById('ba-toggle-pass-vis')?.addEventListener('click',   baTogglePassVis);
document.getElementById('basicauth-pass')?.addEventListener('input',       baPassStrength);
document.getElementById('ba-curl-copy')?.addEventListener('click',         baCopyCurl);

// AI Mode
document.getElementById('aimode-toggle')?.addEventListener('change', aiModeToggleChanged);

// Inspector clear
document.getElementById('btn-clear')?.addEventListener('click', clearReqs);

// Request replay — event delegation on the list
$list?.addEventListener('click', e => {
  const btn = e.target.closest('.replay-btn');
  if (btn) {
    e.stopPropagation();
    const id = parseInt(btn.dataset.replayId, 10);
    if (!isNaN(id)) replayReq(id);
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
  // ── Initial tunnel list ───────────────────────────────────
  // /api/tunnels returns a flat JSON array of TunnelEntry objects.
  fetch('/api/tunnels', { headers: { 'X-CSRF-Token': getCsrfToken() } })
    .then(r => r.ok ? r.json() : [])
    .then(arr => { if (Array.isArray(arr)) renderTunnels(arr); })
    .catch(() => {});

  // ── Status stream (/api/status/stream) ─────────────────────
  // Emits a JSON object every second with uptime_sec + tunnels array.
  // Plain data: events (no named event type).
  function connectStatus() {
    const evs = new EventSource('/api/status/stream');
    evs.onmessage = e => {
      try {
        const d = JSON.parse(e.data);
        if ($uptime && d.uptime_sec != null) $uptime.textContent = fmtUptime(d.uptime_sec);
        if (Array.isArray(d.tunnels)) renderTunnels(d.tunnels);
      } catch {}
    };
    evs.onerror = () => { evs.close(); setTimeout(connectStatus, 3000); };
  }

  // ── Request stream (/api/requests/stream) ──────────────────
  // Emits one CapturedRequest JSON object per proxied request.
  // Plain data: events (no named event type).
  function connectRequests() {
    const evs = new EventSource('/api/requests/stream');
    evs.onmessage = e => {
      try {
        const r = JSON.parse(e.data);
        if (r.endpoint === activeTunnel) prependReq(r);
      } catch {}
    };
    evs.onerror = () => { evs.close(); setTimeout(connectRequests, 3000); };
  }

  connectStatus();
  connectRequests();
})();
