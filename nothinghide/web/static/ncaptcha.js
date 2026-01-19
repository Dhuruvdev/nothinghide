(function() {
    const securityData = {
        mouse_moves: 0,
        scroll_events: 0,
        paste_detected: false,
        hesitation_time: 0,
        start_time: Date.now(),
        focus_lost_count: 0,
        teleport_detected: false,
        clicks: 0
    };

    let lastX, lastY, lastTime;

    document.addEventListener('mousemove', (e) => {
        securityData.mouse_moves++;
        if (lastX !== undefined) {
            const dx = e.clientX - lastX;
            const dy = e.clientY - lastY;
            const dt = Date.now() - lastTime || 1;
            const speed = Math.sqrt(dx*dx + dy*dy) / dt;
            // Human speed limit check
            if (speed > 15) securityData.teleport_detected = true;
        }
        lastX = e.clientX;
        lastY = e.clientY;
        lastTime = Date.now();
    });

    document.addEventListener('scroll', () => securityData.scroll_events++);
    document.addEventListener('paste', () => securityData.paste_detected = true);
    document.addEventListener('click', () => securityData.clicks++);
    window.addEventListener('blur', () => securityData.focus_lost_count++);

    // Global security collector
    window.getNCaptchaPayload = () => {
        securityData.hesitation_time = (Date.now() - securityData.start_time) / 1000;
        
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        const debugInfo = gl ? gl.getExtension('WEBGL_debug_renderer_info') : null;
        
        return {
            biometrics: securityData,
            fingerprint: {
                screen: `${window.screen.width}x${window.screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                user_agent: navigator.userAgent,
                webdriver: navigator.webdriver || false,
                incognito: !window.indexedDB,
                webgl_renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'none',
                platform: navigator.platform,
                memory: navigator.deviceMemory || 'unknown',
                languages: navigator.languages
            }
        };
    };

    window.initBeatTap = (containerId, onComplete) => {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        container.innerHTML = `
            <div style="background: #f8f9fa; border: 1px dashed #4d90fe; padding: 20px; text-align: center; border-radius: 8px;">
                <div style="font-size: 13px; color: #3c4043; margin-bottom: 15px; font-weight: 500;">
                    Rhythm Challenge: Tap when the ring flashes blue
                </div>
                <div id="beat-circle" style="width: 64px; height: 64px; background: #fff; border: 3px solid #e0e0e0; border-radius: 50%; margin: 0 auto; position: relative; cursor: pointer; transition: all 0.1s; display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                    <div id="beat-ring" style="position: absolute; top: -6px; left: -6px; right: -6px; bottom: -6px; border: 4px solid #4d90fe; border-radius: 50%; opacity: 0; transition: opacity 0.15s cubic-bezier(0.4, 0, 0.2, 1);"></div>
                    <div style="width: 10px; height: 10px; background: #4d90fe; border-radius: 50%;"></div>
                </div>
                <div id="beat-status" style="margin-top: 15px; font-size: 11px; color: #70757a; font-weight: bold; text-transform: uppercase;">Waiting...</div>
            </div>
        `;

        const ring = container.querySelector('#beat-ring');
        const status = container.querySelector('#beat-status');
        const circle = container.querySelector('#beat-circle');
        let taps = [];
        let startTime = Date.now();
        let flashInterval;

        const flash = () => {
            ring.style.opacity = '1';
            setTimeout(() => { ring.style.opacity = '0'; }, 200);
        };

        flashInterval = setInterval(flash, 1500);

        circle.onclick = (e) => {
            e.stopPropagation();
            const now = Date.now();
            const elapsedSinceStart = now - startTime;
            const cyclePos = elapsedSinceStart % 1500;
            const distToFlash = Math.min(cyclePos, 1500 - cyclePos);
            
            taps.push(distToFlash);
            circle.style.transform = 'scale(0.9)';
            setTimeout(() => { circle.style.transform = 'scale(1)'; }, 100);

            if (taps.length === 1) status.innerText = "Captured. Again...";
            if (taps.length === 2) status.innerText = "One more...";
            if (taps.length === 3) {
                clearInterval(flashInterval);
                const avgDist = taps.reduce((a, b) => a + b) / 3;
                if (avgDist < 350) {
                    status.innerText = "Rhythm Verified";
                    status.style.color = "#00aa00";
                    onComplete(true);
                } else {
                    status.innerText = "Failed. Recalibrating...";
                    taps = [];
                    setTimeout(() => {
                        flashInterval = setInterval(flash, 1500);
                        status.innerText = "Try again...";
                    }, 1000);
                }
            }
        };
    };
})();
