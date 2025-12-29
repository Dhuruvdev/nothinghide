// Browser Extension Logic (manifest v3)
// background.js

chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        details.responseHeaders.forEach((header) => {
            if (header.name.toLowerCase() === 'set-cookie') {
                const value = header.value.toLowerCase();
                const issues = [];
                
                if (!value.includes('httponly')) issues.push('Missing HttpOnly');
                if (!value.includes('secure')) issues.push('Missing Secure');
                if (!value.includes('samesite')) issues.push('Missing SameSite');

                if (issues.length > 0) {
                    chrome.action.setBadgeText({ text: '!' });
                    chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
                    console.warn(`Insecure Cookie Detected on ${details.url}: ${issues.join(', ')}`);
                }
            }
        });
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);
