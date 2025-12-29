// manifest.json (v3) snippet logic
/*
{
  "name": "Cookie Cooked Protection",
  "version": "1.0",
  "manifest_version": 3,
  "permissions": ["webRequest", "storage", "activeTab"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background.js" }
}
*/

// background.js
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        const headers = details.responseHeaders;
        let insecureCookies = [];

        for (let header of headers) {
            if (header.name.toLowerCase() === 'set-cookie') {
                const value = header.value.toLowerCase();
                const flags = [];
                if (!value.includes('httponly')) flags.push('HttpOnly');
                if (!value.includes('secure')) flags.push('Secure');
                if (!value.includes('samesite')) flags.push('SameSite');

                if (flags.length > 0) {
                    insecureCookies.push({ url: details.url, missing: flags });
                }
            }
        }

        if (insecureCookies.length > 0) {
            chrome.action.setBadgeText({ text: '!' });
            chrome.action.setBadgeBackgroundColor({ color: '#E74C3C' });
            console.error('Insecure Cookies Detected:', insecureCookies);
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);
