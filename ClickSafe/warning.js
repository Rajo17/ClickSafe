// warning.js

const params = new URLSearchParams(location.search);
const badUrl = params.get('badUrl');
const reason = params.get('reason') || 'No detailed reason available';

document.getElementById('reason').textContent = reason;

document.getElementById('proceed').addEventListener('click', () => {
  if (badUrl) {
    location.href = badUrl;
  } else {
    alert('No URL to proceed to');
  }
});

document.getElementById('back').addEventListener('click', () => {
  history.back();
});