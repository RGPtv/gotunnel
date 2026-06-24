'use strict';

// ── Theme Init ─────────────────────────────────────────────────
(function () {
  var saved = localStorage.getItem('gotunnel-theme');
  var theme = saved || 'dark';
  document.documentElement.setAttribute('data-theme', theme);
})();

(function () {
  const form      = document.getElementById('login-form');
  const submitBtn = document.getElementById('submit-btn');
  const submitLbl = document.getElementById('submit-label');
  const spinner   = document.getElementById('submit-spinner');
  const errorMsg  = document.getElementById('error-msg');
  const passInput = document.getElementById('password');
  const toggleBtn = document.getElementById('toggle-pass');
  const iconShow  = document.getElementById('pass-icon-show');
  const iconHide  = document.getElementById('pass-icon-hide');
  const themeBtn  = document.getElementById('theme-toggle');

  // ── Dark mode toggle ─────────────────────────────────────
  themeBtn?.addEventListener('click', () => {
    const root = document.documentElement;
    const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('gotunnel-theme', next);
  });

  // ── Show error from URL param ────────────────────────────
  const params = new URLSearchParams(window.location.search);
  const errCode = params.get('error');
  if (errCode && errorMsg) {
    const messages = {
      invalid:    'Incorrect username or password.',
      locked:     'Too many failed attempts. Please wait before trying again.',
      session:    'Your session has expired. Please sign in again.',
      csrf:       'Request validation failed. Please refresh and try again.',
    };
    errorMsg.textContent = messages[errCode] || 'Sign-in failed. Please try again.';
    errorMsg.style.display = 'flex';
  }

  // ── Form submit: show loading state ─────────────────────
  form?.addEventListener('submit', e => {
    const username = document.getElementById('username')?.value.trim();
    const password = passInput?.value;

    // Client-side basic validation before submitting
    if (!username || !password) {
      e.preventDefault();
      if (errorMsg) {
        errorMsg.textContent = 'Please enter both username and password.';
        errorMsg.style.display = 'flex';
      }
      return;
    }

    // Disable button and show spinner during server round-trip
    if (submitBtn) submitBtn.disabled = true;
    if (submitLbl) submitLbl.textContent = 'Signing in…';
    if (spinner)   spinner.style.display = 'inline-flex';
  });

  // ── Password visibility toggle ───────────────────────────
  toggleBtn?.addEventListener('click', () => {
    if (!passInput) return;
    const isHidden = passInput.type === 'password';
    passInput.type = isHidden ? 'text' : 'password';
    if (iconShow) iconShow.style.display = isHidden ? 'none'  : '';
    if (iconHide) iconHide.style.display = isHidden ? ''      : 'none';
    toggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
    // Return focus to input after toggle
    passInput.focus();
  });

  // ── Focus the username field on load ─────────────────────
  const userInput = document.getElementById('username');
  if (userInput && !userInput.value) userInput.focus();
})();
