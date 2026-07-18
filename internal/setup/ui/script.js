'use strict';

/* ── Apply saved theme before first paint ─────────────────────────────────── */
(function () {
  const saved = localStorage.getItem('gotunnel-theme');
  const sys   = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', saved || sys);
})();

document.addEventListener('DOMContentLoaded', () => {

  // ── Theme toggle ─────────────────────────────────────────────────────────────
  document.getElementById('theme-toggle').addEventListener('click', () => {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    const next = dark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('gotunnel-theme', next);
  });

  // ── Shared state ─────────────────────────────────────────────────────────────
  let currentStep = 1;

  const state = {
    username: '', password: '',
    domain: '', httpAddr: ':80', tunAddr: ':2222',
    enableHTTPS: false, certFile: '', keyFile: '',
    wildcard: false, noTLS: false,
    dashboardPort: 4040,
    tokenMode: 'auto', token: '',
    poolSize: 512,
  };

  // ── DOM refs ──────────────────────────────────────────────────────────────────
  const formPanel      = document.getElementById('form-panel');
  const httpsToggle    = document.getElementById('https-toggle');
  const httpsRow       = document.getElementById('https-row');
  const httpsFields    = document.getElementById('https-fields');
  const wildcardToggle = document.getElementById('wildcard-toggle');
  const wildcardRow    = document.getElementById('wildcard-row');
  const noTLSToggle    = document.getElementById('notls-toggle');
  const noTLSRow       = document.getElementById('notls-row');
  const tabAuto        = document.getElementById('tab-auto');
  const tabCustom      = document.getElementById('tab-custom');
  const tokenAutoHint  = document.getElementById('token-auto-hint');
  const tokenCustomWrap= document.getElementById('token-custom-wrap');
  const passInput      = document.getElementById('admin-password');

  // ── Utility ───────────────────────────────────────────────────────────────────
  function showAlert(stepId, msg) {
    const wrap = document.getElementById(`step${stepId}-alert`);
    const text = document.getElementById(`step${stepId}-alert-text`);
    if (!wrap) return;
    if (text) text.textContent = msg; else wrap.textContent = msg;
    wrap.classList.add('visible');
    wrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function clearAlert(stepId) {
    const el = document.getElementById(`step${stepId}-alert`);
    if (el) el.classList.remove('visible');
  }

  function setErr(id, msg, show) {
    const el = document.getElementById(id);
    if (!el) return;
    if (msg) el.textContent = msg;
    el.classList.toggle('visible', show);
  }

  function markField(idOrEl, validity) {
    const el = typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
    if (!el) return;
    el.classList.remove('valid', 'invalid');
    if (validity) el.classList.add(validity);
  }

  function esc(str) {
    return String(str)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Step navigation ───────────────────────────────────────────────────────────
  function goToStep(target, back = false) {
    const curr = document.getElementById(`step-${currentStep}`);
    const next = document.getElementById(`step-${target}`);
    if (!curr || !next) return;

    curr.classList.remove('active', 'going-back');
    next.classList.remove('active', 'going-back');
    if (back) next.classList.add('going-back');
    void next.offsetWidth; // force reflow so animation restarts
    next.classList.add('active');

    currentStep = target;
    updateSidebar();
    clearAlert(target);
    if (formPanel) formPanel.scrollTop = 0;
  }

  function updateSidebar() {
    document.querySelectorAll('.stepper-item').forEach(item => {
      const s = parseInt(item.dataset.step, 10);
      item.classList.remove('active', 'done');
      if (s === currentStep)    item.classList.add('active');
      else if (s < currentStep) item.classList.add('done');
    });
  }

  // ── Password strength ─────────────────────────────────────────────────────────
  const strSegs = [1,2,3,4].map(i => document.getElementById(`str-${i}`));
  const strLabel = document.getElementById('strength-label');

  const strMeta = [
    { cls: '',       label: '' },
    { cls: 'weak',   label: 'Weak' },
    { cls: 'medium', label: 'Fair' },
    { cls: 'strong', label: 'Good' },
    { cls: 'strong', label: 'Strong' },
  ];

  function calcStrength(p) {
    if (!p) return 0;
    let s = 0;
    if (p.length >= 8)  s++;
    if (p.length >= 12) s++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(4, s);
  }

  passInput.addEventListener('input', () => {
    const score = calcStrength(passInput.value);
    const m = strMeta[score];
    strSegs.forEach((seg, i) => {
      seg.className = 'str-seg';
      if (i < score) seg.classList.add(m.cls);
    });
    if (passInput.value) {
      strLabel.textContent = m.label;
      strLabel.style.color =
        score <= 1 ? 'var(--red)' : score === 2 ? 'var(--amber)' : 'var(--green)';
    } else {
      strLabel.textContent = '';
    }
  });

  // ── Password reveal ───────────────────────────────────────────────────────────
  document.querySelectorAll('.pass-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.target);
      const isPass = input.type === 'password';
      input.type = isPass ? 'text' : 'password';
      btn.querySelector('.eye-show').classList.toggle('hidden', !isPass);
      btn.querySelector('.eye-hide').classList.toggle('hidden', isPass);
      btn.setAttribute('aria-label', isPass ? 'Hide password' : 'Show password');
    });
  });

  // ── HTTPS / NoTLS mutual-exclusion ───────────────────────────────────────────
  httpsToggle.addEventListener('change', () => {
    const on = httpsToggle.checked;
    httpsRow.classList.toggle('on', on);
    httpsToggle.setAttribute('aria-checked', String(on));
    httpsFields.classList.toggle('open', on);
    httpsFields.setAttribute('aria-hidden', String(!on));
    if (on && noTLSToggle.checked) {
      noTLSToggle.checked = false;
      noTLSRow.classList.remove('on');
      noTLSToggle.setAttribute('aria-checked', 'false');
    }
  });

  wildcardToggle.addEventListener('change', () => {
    const on = wildcardToggle.checked;
    wildcardRow.classList.toggle('on', on);
    wildcardToggle.setAttribute('aria-checked', String(on));
    // Wildcard → dashboard on port 443; hide the separate port field
    const dash = document.getElementById('dashboard-section');
    if (dash) dash.classList.toggle('hidden', on);
  });

  noTLSToggle.addEventListener('change', () => {
    const on = noTLSToggle.checked;
    noTLSRow.classList.toggle('on', on);
    noTLSToggle.setAttribute('aria-checked', String(on));
    if (on && httpsToggle.checked) {
      httpsToggle.checked = false;
      httpsRow.classList.remove('on');
      httpsToggle.setAttribute('aria-checked', 'false');
      httpsFields.classList.remove('open');
      httpsFields.setAttribute('aria-hidden', 'true');
    }
  });

  // ── Token mode tabs ───────────────────────────────────────────────────────────
  tabAuto.addEventListener('click', () => {
    tabAuto.classList.add('active');
    tabCustom.classList.remove('active');
    tokenCustomWrap.classList.remove('open');
    tokenCustomWrap.setAttribute('aria-hidden', 'true');
    tokenAutoHint.classList.remove('hidden');
  });

  tabCustom.addEventListener('click', () => {
    tabCustom.classList.add('active');
    tabAuto.classList.remove('active');
    tokenCustomWrap.classList.add('open');
    tokenCustomWrap.setAttribute('aria-hidden', 'false');
    tokenAutoHint.classList.add('hidden');
    document.getElementById('token-custom-input').focus();
  });

  // ── Step 1 validation ─────────────────────────────────────────────────────────
  function validateStep1() {
    let ok = true;

    const u = document.getElementById('admin-username').value.trim();
    if (!u) {
      setErr('err-username', 'Username cannot be empty.', true);
      markField('admin-username', 'invalid'); ok = false;
    } else {
      setErr('err-username', '', false); markField('admin-username', 'valid');
    }

    const p = passInput.value;
    if (p.length < 8) {
      setErr('err-password', 'Password must be at least 8 characters.', true);
      markField(passInput, 'invalid'); ok = false;
    } else {
      setErr('err-password', '', false); markField(passInput, 'valid');
    }

    const c = document.getElementById('admin-confirm').value;
    if (!c) {
      setErr('err-confirm', 'Please confirm your password.', true);
      markField('admin-confirm', 'invalid'); ok = false;
    } else if (c !== p) {
      setErr('err-confirm', 'Passwords do not match.', true);
      markField('admin-confirm', 'invalid'); ok = false;
    } else {
      setErr('err-confirm', '', false); markField('admin-confirm', 'valid');
    }

    return ok;
  }

  document.getElementById('btn-step1-next').addEventListener('click', () => {
    clearAlert(1);
    if (!validateStep1()) return;
    state.username = document.getElementById('admin-username').value.trim();
    state.password = passInput.value;
    goToStep(2);
  });

  // ── Step 2 validation ─────────────────────────────────────────────────────────
  const domainRe = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

  function validateStep2() {
    let ok = true;

    const domain = document.getElementById('domain').value.trim();
    if (!domain || !domainRe.test(domain)) {
      setErr('err-domain', 'Enter a valid domain (e.g. tunnel.example.com).', true);
      markField('domain', 'invalid'); ok = false;
    } else {
      setErr('err-domain', '', false); markField('domain', 'valid');
    }

    if (httpsToggle.checked) {
      const cert = document.getElementById('cert-file').value.trim();
      if (!cert) {
        setErr('err-cert', 'Certificate path is required when HTTPS is enabled.', true);
        markField('cert-file', 'invalid'); ok = false;
      } else {
        setErr('err-cert', '', false); markField('cert-file', 'valid');
      }
      const key = document.getElementById('key-file').value.trim();
      if (!key) {
        setErr('err-key', 'Private key path is required when HTTPS is enabled.', true);
        markField('key-file', 'invalid'); ok = false;
      } else {
        setErr('err-key', '', false); markField('key-file', 'valid');
      }
    }

    if (!wildcardToggle.checked) {
      const port = parseInt(document.getElementById('dashboard-port').value, 10);
      if (!port || port < 1 || port > 65535) {
        setErr('err-port', 'Please enter a valid port (1–65535).', true);
        markField('dashboard-port', 'invalid'); ok = false;
      } else {
        setErr('err-port', '', false); markField('dashboard-port', 'valid');
      }
    }

    if (tabCustom.classList.contains('active')) {
      const tok = document.getElementById('token-custom-input').value.trim();
      if (!tok) {
        setErr('err-token', 'Token cannot be empty when using a custom token.', true);
        markField('token-custom-input', 'invalid'); ok = false;
      } else {
        setErr('err-token', '', false); markField('token-custom-input', 'valid');
      }
    }

    const pool = parseInt(document.getElementById('pool-size').value, 10);
    if (!pool || pool < 1) {
      setErr('err-pool', 'Pool size must be at least 1.', true);
      markField('pool-size', 'invalid'); ok = false;
    } else {
      setErr('err-pool', '', false); markField('pool-size', 'valid');
    }

    return ok;
  }

  document.getElementById('btn-step2-back').addEventListener('click', () => goToStep(1, true));
  document.getElementById('btn-step3-back').addEventListener('click', () => goToStep(2, true));

  document.getElementById('btn-step2-next').addEventListener('click', () => {
    clearAlert(2);
    if (!validateStep2()) return;

    state.domain        = document.getElementById('domain').value.trim();
    state.httpAddr      = document.getElementById('http-addr').value.trim() || ':80';
    state.tunAddr       = document.getElementById('tun-addr').value.trim() || ':2222';
    state.enableHTTPS   = httpsToggle.checked;
    state.certFile      = document.getElementById('cert-file').value.trim();
    state.keyFile       = document.getElementById('key-file').value.trim();
    state.wildcard      = wildcardToggle.checked;
    state.noTLS         = noTLSToggle.checked;
    state.dashboardPort = wildcardToggle.checked
      ? 443
      : parseInt(document.getElementById('dashboard-port').value, 10) || 4040;
    state.tokenMode     = tabCustom.classList.contains('active') ? 'custom' : 'auto';
    state.token         = state.tokenMode === 'custom'
      ? document.getElementById('token-custom-input').value.trim()
      : 'auto';
    state.poolSize      = parseInt(document.getElementById('pool-size').value, 10) || 512;

    renderReview();
    goToStep(3);
  });

  // ── Review ────────────────────────────────────────────────────────────────────
  function badge(text, cls) { return `<span class="badge ${cls}">${esc(text)}</span>`; }
  function raw(text)        { return esc(text); }

  function reviewSection(title, rows) {
    const rowsHtml = rows.map(([k, v]) =>
      `<div class="review-row"><span class="review-key">${esc(k)}</span><span class="review-val">${v}</span></div>`
    ).join('');
    return `<div class="review-section">
      <div class="review-section-label">${esc(title)}</div>
      <div class="review-card">${rowsHtml}</div>
    </div>`;
  }

  function renderReview() {
    let html = '';

    html += reviewSection('Administrator', [
      ['Username', raw(state.username)],
      ['Password', raw('••••••••')],
    ]);

    html += reviewSection('Network', [
      ['Domain',         raw(state.domain)],
      ['HTTP Address',   badge(state.httpAddr,  'badge-purple')],
      ['Tunnel Address', badge(state.tunAddr,   'badge-purple')],
    ]);

    const tlsRows = [
      ['HTTPS', state.enableHTTPS ? badge('Enabled','badge-green') : badge('Disabled','badge-gray')],
    ];
    if (state.enableHTTPS) {
      tlsRows.push(['Certificate', raw(state.certFile)]);
      tlsRows.push(['Private Key',  raw(state.keyFile)]);
      tlsRows.push(['Wildcard', state.wildcard ? badge('Yes','badge-green') : badge('No','badge-gray')]);
    }
    tlsRows.push(['No TLS Mode', state.noTLS ? badge('Enabled','badge-green') : badge('Disabled','badge-gray')]);
    html += reviewSection('SSL / TLS', tlsRows);

    html += reviewSection('Dashboard', [
      ['Port', state.wildcard
        ? badge('443 (via HTTPS wildcard)', 'badge-green')
        : badge(':' + state.dashboardPort, 'badge-blue')],
    ]);

    html += reviewSection('Auth Token', [
      ['Mode', state.tokenMode === 'auto'
        ? badge('Auto-generate once', 'badge-green')
        : badge('Custom', 'badge-purple')],
      ...(state.tokenMode === 'custom' ? [['Token', raw(state.token)]] : []),
    ]);

    html += reviewSection('Advanced', [
      ['Pool Size', raw(String(state.poolSize))],
    ]);

    document.getElementById('review-grid').innerHTML = html;
  }

  // ── Submit ────────────────────────────────────────────────────────────────────
  const finishBtn     = document.getElementById('btn-finish');
  const finishLabel   = document.getElementById('finish-label');
  const finishSpinner = document.getElementById('finish-spinner');

  finishBtn.addEventListener('click', async () => {
    clearAlert(3);
    finishBtn.disabled = true;
    finishLabel.textContent = 'Saving…';
    finishSpinner.classList.remove('hidden');

    const payload = {
      username:       state.username,
      password:       state.password,
      domain:         state.domain,
      http_addr:      state.httpAddr,
      tun_addr:       state.tunAddr,
      enable_https:   state.enableHTTPS,
      cert_file:      state.certFile,
      key_file:       state.keyFile,
      wildcard:       state.wildcard,
      no_tls:         state.noTLS,
      dashboard_port: state.dashboardPort,
      token_mode:     state.tokenMode,
      token:          state.token,
      pool_size:      state.poolSize,
    };

    try {
      const res = await fetch('/api/setup/complete', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `Server error (${res.status})`);
      }
      const data = await res.json();
      showSuccess(data.redirect_url || '/login');
    } catch (err) {
      showAlert(3, err.message || 'Failed to save configuration. Please try again.');
      finishBtn.disabled = false;
      finishLabel.textContent = 'Generate Config';
      finishSpinner.classList.add('hidden');
    }
  });

  // ── Success overlay ───────────────────────────────────────────────────────────
  function showSuccess(redirectURL) {
    document.getElementById('success-overlay').classList.add('visible');
    let n = 8;
    const el = document.getElementById('countdown');
    el.textContent = n;
    const t = setInterval(() => {
      n--;
      el.textContent = n;
      if (n <= 0) { clearInterval(t); window.location.href = redirectURL; }
    }, 1000);
  }

});
