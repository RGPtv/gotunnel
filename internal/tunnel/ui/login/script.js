'use strict';

(function () {
  const saved = localStorage.getItem('gotunnel-theme');
  const theme = saved || 'dark';
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

  const showError = message => {
    if (!errorMsg) return;
    errorMsg.textContent = message;
    errorMsg.classList.remove('hidden');
  };

  themeBtn?.addEventListener('click', () => {
    const root = document.documentElement;
    const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('gotunnel-theme', next);
  });

  const params = new URLSearchParams(window.location.search);
  const errCode = params.get('error');
  if (errCode) {
    const messages = {
      invalid: 'Incorrect username or password.',
      locked:  'Too many failed attempts. Please wait before trying again.',
      session: 'Your session has expired. Please sign in again.',
      csrf:    'Request validation failed. Please refresh and try again.',
    };
    showError(messages[errCode] || 'Sign-in failed. Please try again.');
  }

  form?.addEventListener('submit', e => {
    const username = document.getElementById('username')?.value.trim();
    const password = passInput?.value;

    if (!username || !password) {
      e.preventDefault();
      showError('Please enter both username and password.');
      return;
    }

    if (submitBtn) submitBtn.disabled = true;
    if (submitLbl) submitLbl.textContent = 'Signing in...';
    spinner?.classList.remove('hidden');
  });

  toggleBtn?.addEventListener('click', () => {
    if (!passInput) return;
    const isHidden = passInput.type === 'password';
    passInput.type = isHidden ? 'text' : 'password';
    iconShow?.classList.toggle('hidden', isHidden);
    iconHide?.classList.toggle('hidden', !isHidden);
    toggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
    toggleBtn.setAttribute('title', isHidden ? 'Hide password' : 'Show password');
    passInput.focus();
  });

  const userInput = document.getElementById('username');
  if (userInput && !userInput.value) userInput.focus();
})();
