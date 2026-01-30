let VT_API_KEY = null;
const VT_CACHE_DAYS = 7;
const VT_CACHE_KEY_PREFIX = "vt_url_";
const BLOCK_THRESHOLD = 1; 

let domainCategories = null;
let pendingNavigations = new Map();

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install' || details.reason === 'update') {
    chrome.storage.local.get('vtApiKey', (data) => {
      if (!data.vtApiKey) {
        // Open popup automatically on first install if no key
        chrome.action.openPopup();  // Note: this API is Chrome 99+, may not work in all versions
        // Alternative: open options/popup in new tab
        chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') });
      }
    });
  }
});

async function loadVtApiKey() {
  const data = await chrome.storage.local.get('vtApiKey');
  VT_API_KEY = data.vtApiKey || null;
  if (!VT_API_KEY) {
    console.warn("[VT] No API key set yet. VT checks skipped. Open extension popup to configure.");
  }
}

loadVtApiKey();

chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'apiKeyUpdated') {
    loadVtApiKey();
  }
});

async function loadCategories() {
  try {
    const response = await fetch(chrome.runtime.getURL('categories.json'));
    domainCategories = await response.json();
    console.log("[URL Logger] Categories loaded:", Object.keys(domainCategories).length);
  } catch (err) {
    console.error("Failed to load categories.json", err);
    domainCategories = { "default": "Uncategorized" };
  }
}

function normalizeHost(host) {
  return host ? host.toLowerCase().replace(/^www\./, '') : '';
}

function getCategory(hostname) {
  if (!domainCategories) return "Loading...";
  const norm = normalizeHost(hostname);
  return domainCategories[norm] || domainCategories.default || "Uncategorized";
}

async function getVtUrlReport(fullUrl) {
  if (!VT_API_KEY) {
    console.warn("[VT] Skipping check - no API key configured");
    return { error: "No VirusTotal API key set" };
  }
  const cacheKey = VT_CACHE_KEY_PREFIX + fullUrl;
  const cached = await chrome.storage.local.get(cacheKey).then(r => r[cacheKey]);

  if (cached && (Date.now() - cached.timestamp) / 86400000 < VT_CACHE_DAYS) {
    return cached.report;
  }

  try {
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VT_API_KEY
      },
      body: `url=${encodeURIComponent(fullUrl)}`
    });

    if (!submitRes.ok) throw new Error(`Submit ${submitRes.status}`);

    const submitData = await submitRes.json();
    let analysisId = submitData.data?.id;
    if (!analysisId?.startsWith('u-')) throw new Error("Bad ID");

    const urlHash = analysisId.slice(2, 66);

    const reportRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlHash}`, {
      method: "GET",
      headers: {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
      }
    });

    if (!reportRes.ok) throw new Error(`Report ${reportRes.status}`);

    const reportData = await reportRes.json();
    const attributes = reportData.data?.attributes || {};

    chrome.storage.local.set({ [cacheKey]: { report: attributes, timestamp: Date.now() } });

    return attributes;
  } catch (err) {
    console.error("[VT Error]", fullUrl, err);
    return { error: err.message };
  }
}

async function showWarning(tabId, badUrl, reason) {
  const warningUrl = chrome.runtime.getURL('warning.html') + 
    '?badUrl=' + encodeURIComponent(badUrl) + 
    '&reason=' + encodeURIComponent(reason);

  await chrome.tabs.update(tabId, { url: warningUrl });
  console.log(`[Block] Redirected tab ${tabId} to warning: ${reason}`);
}

console.log("[URL Logger] Started —", new Date().toISOString());
loadCategories();

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;
  pendingNavigations.set(details.tabId, details.url);
}, { url: [{ schemes: ["http", "https"] }] });

chrome.webNavigation.onCommitted.addListener(async details => {
  if (details.frameId !== 0) return;

  const finalUrl = details.url;
  const originalUrl = pendingNavigations.get(details.tabId) || finalUrl;
  pendingNavigations.delete(details.tabId);

  let origin = "", hostname = "", path = "", categoryFinal = "Uncategorized";
  let originalHostname = "", categoryOriginal = "Uncategorized";
  let vtFinal = null, vtOriginal = null;
  let isMalicious = false;
  let maliciousReason = "";

  try {
    const finalObj = new URL(finalUrl);
    origin = finalObj.origin;
    hostname = finalObj.hostname;
    path = finalObj.pathname + finalObj.search + finalObj.hash;
    categoryFinal = getCategory(hostname);
  } catch {}

  try {
    if (originalUrl !== finalUrl) {
      const origObj = new URL(originalUrl);
      originalHostname = origObj.hostname;
      categoryOriginal = getCategory(originalHostname);
    }
  } catch {}

  if (categoryFinal === "Uncategorized" || categoryFinal === domainCategories.default) {
    vtFinal = await getVtUrlReport(finalUrl);
  }

  if (originalUrl !== finalUrl &&
      (categoryOriginal === "Uncategorized" || categoryOriginal === domainCategories.default)) {
    vtOriginal = await getVtUrlReport(originalUrl);
  }

  const evaluateMalicious = (report, which) => {
    if (!report || report.error) return false;
    const stats = report.last_analysis_stats || {};
    const maliciousCount = stats.malicious || 0;

    if (maliciousCount >= BLOCK_THRESHOLD) {
      isMalicious = true;
      maliciousReason += `\n→ ${which} URL is malicious:\n` +
                         `  - Malicious engines: ${maliciousCount}\n` +
                         `  - Suspicious: ${stats.suspicious || 0}\n` +
                         `  - Reputation: ${report.reputation || 0}\n` +
                         `  - Categories: ${Object.values(report.categories || {}).join(", ") || "none"}`;
      return true;
    }
    return false;
  };

  evaluateMalicious(vtOriginal, "Redirect source / original");
  evaluateMalicious(vtFinal,   "Final / landing");

  const time = new Date().toISOString();
  const tabId = details.tabId;

  let log = `[URL Logger] ${time}  tab=${tabId.toString().padStart(4)}` +
            `  origin: ${origin.padEnd(45)}` +
            `  path: ${path.padEnd(55)}` +
            `  category: ${categoryFinal.padEnd(20)}`;

  if (originalUrl !== finalUrl) {
    log += `  ← from: ${originalUrl} (${categoryOriginal})`;
  }

  if (vtOriginal || vtFinal) {
    log += `\n[VT checked] ${vtOriginal ? 'original + ' : ''}final`;
  }

  if (isMalicious) {
    log += ` → BLOCKED (malicious detected)`;
    console.log(log);
    console.log("[BLOCK REASON]", maliciousReason);

    await showWarning(tabId, finalUrl, maliciousReason.trim());
  } else {
    log += " → allowed (clean or categorized)";
    console.log(log);
  }

}, { url: [{ schemes: ["http", "https"] }] });