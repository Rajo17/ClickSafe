// popup.js

document.addEventListener('DOMContentLoaded', () => {
  const apikeyInput = document.getElementById('apikey');
  const saveBtn = document.getElementById('save');
  const statusDiv = document.getElementById('status');

  // Load existing key (if any)
  chrome.storage.local.get('vtApiKey', (data) => {
    if (data.vtApiKey) {
      apikeyInput.value = data.vtApiKey;
      statusDiv.textContent = 'API key already saved ✓';
      statusDiv.className = 'success';
    }
  });

  saveBtn.addEventListener('click', () => {
    const key = apikeyInput.value.trim();
    if (!key || key.length < 40) {  // rough length check
      statusDiv.textContent = 'Please enter a valid API key';
      statusDiv.className = 'error';
      return;
    }

    chrome.storage.local.set({ vtApiKey: key }, () => {
      statusDiv.textContent = 'API key saved successfully! You can close this popup.';
      statusDiv.className = 'success';
      saveBtn.textContent = 'Saved ✓';
      saveBtn.disabled = true;

      // Optional: notify background script that key is ready
      chrome.runtime.sendMessage({ action: 'apiKeyUpdated' });
    });
  });
});