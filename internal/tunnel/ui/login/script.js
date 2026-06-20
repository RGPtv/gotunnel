'use strict';

if (new URLSearchParams(window.location.search).has('error')) {
  document.getElementById('err').classList.add('show');
}
