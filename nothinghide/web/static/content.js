// Content script to notify the dashboard that the extension is installed
window.COOKED_EXTENSION_ACTIVE = true;
document.documentElement.setAttribute('data-cooked-extension-installed', 'true');
console.log("Cookie Cooked Extension: Handshake complete.");