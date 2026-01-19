document.addEventListener('DOMContentLoaded', () => {
    const securityData = {
        mouse_moves: 0,
        scroll_events: 0,
        paste_detected: false,
        hesitation_time: 0,
        start_time: Date.now(),
        focus_lost_count: 0
    };

    document.addEventListener('mousemove', () => securityData.mouse_moves++);
    document.addEventListener('scroll', () => securityData.scroll_events++);
    document.addEventListener('paste', () => securityData.paste_detected = true);
    window.addEventListener('blur', () => securityData.focus_lost_count++);

    // Fingerprinting
    const getFingerprint = () => {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        const debugInfo = gl ? gl.getExtension('WEBGL_debug_renderer_info') : null;
        
        return {
            screen: `${window.screen.width}x${window.screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            user_agent: navigator.userAgent,
            webgl_renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'none'
        };
    };

    // Global security collector
    window.getNCaptchaPayload = () => {
        securityData.hesitation_time = (Date.now() - securityData.start_time) / 1000;
        return {
            biometrics: securityData,
            fingerprint: getFingerprint()
        };
    };
});

function initBeatTap(containerId, onComplete) {
    const container = document.getElementById(containerId);
    container.innerHTML = `
        <div class="beat-tap-box">
            <p>Security Check: Tap the beat</p>
            <div class="beat-circle">
                <div class="beat-glow"></div>
            </div>
            <div class="beat-status">Waiting...</div>
        </div>
    `;

    const glow = container.querySelector('.beat-glow');
    const status = container.querySelector('.beat-status');
    let taps = [];
    let startTime = Date.now();
    
    // Simple 1s rhythm
    const animate = () => {
        const elapsed = (Date.now() - startTime) % 1000;
        const scale = 1 + Math.sin((elapsed / 1000) * Math.PI) * 0.5;
        glow.style.transform = `scale(${scale})`;
        requestAnimationFrame(animate);
    };
    animate();

    container.onclick = () => {
        const elapsed = (Date.now() - startTime) % 1000;
        const diff = Math.min(elapsed, 1000 - elapsed); // distance to peak
        taps.push(diff);
        
        if (taps.length === 1) status.innerText = "One more...";
        if (taps.length === 2) {
            const avgDiff = taps.reduce((a, b) => a + b) / 2;
            if (avgDiff < 150) {
                status.innerText = "Verified";
                onComplete(true);
            } else {
                status.innerText = "Failed rhythm. Try again.";
                taps = [];
            }
        }
    };
}
