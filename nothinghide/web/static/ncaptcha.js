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
            <div class="captcha-widget" style="background: #ffffff; border: 1px solid #dfe1e5; padding: 20px; text-align: center; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); max-width: 300px; margin: 0 auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
                <div style="display: flex; align-items: center; justify-content: center; margin-bottom: 20px;">
                    <img src="/static/captcha-icon.png" style="width: 40px; height: 40px; margin-right: 12px; object-fit: contain;">
                    <div style="text-align: left;">
                        <div style="font-size: 14px; color: #202124; font-weight: 600;">Secure Verification</div>
                        <div style="font-size: 11px; color: #5f6368;">Powered by NothingHide AI</div>
                    </div>
                </div>
                <div style="font-size: 13px; color: #3c4043; margin-bottom: 20px; line-height: 1.4;">
                    Rhythm Challenge: Tap the circle when the blue ring flashes.
                </div>
                <div id="beat-circle" style="width: 80px; height: 80px; background: #fff; border: 1px solid #dadce0; border-radius: 50%; margin: 0 auto; position: relative; cursor: pointer; transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                    <div id="beat-ring" style="position: absolute; top: -8px; left: -8px; right: -8px; bottom: -8px; border: 4px solid #4d90fe; border-radius: 50%; opacity: 0; transition: opacity 0.1s ease-in-out;"></div>
                    <div style="width: 14px; height: 14px; background: #4d90fe; border-radius: 50%; box-shadow: 0 0 10px rgba(77, 144, 254, 0.4);"></div>
                </div>
                <div id="beat-status" style="margin-top: 20px; font-size: 11px; color: #70757a; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">Waiting for rhythm...</div>
                <div style="margin-top: 15px; border-top: 1px solid #f1f3f4; padding-top: 10px; display: flex; align-items: center; justify-content: center;">
                    <span style="font-size: 10px; color: #9aa0a6;">Advanced Human Verification v4.2</span>
                </div>
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
            setTimeout(() => { ring.style.opacity = '0'; }, 150);
        };

        flashInterval = setInterval(flash, 1500);

        circle.onclick = (e) => {
            e.stopPropagation();
            const now = Date.now();
            const elapsedSinceStart = now - startTime;
            const cyclePos = elapsedSinceStart % 1500;
            const distToFlash = Math.min(cyclePos, 1500 - cyclePos);
            
            taps.push(distToFlash);
            circle.style.transform = 'scale(0.92)';
            circle.style.boxShadow = 'inset 0 2px 4px rgba(0,0,0,0.1)';
            setTimeout(() => { 
                circle.style.transform = 'scale(1)'; 
                circle.style.boxShadow = '0 2px 4px rgba(0,0,0,0.05)';
            }, 100);

            if (taps.length === 1) status.innerText = "First tap recorded...";
            if (taps.length === 2) status.innerText = "Keep the rhythm...";
            if (taps.length === 3) {
                clearInterval(flashInterval);
                const avgDist = taps.reduce((a, b) => a + b) / 3;
                if (avgDist < 350) {
                    status.innerText = "Verification Successful";
                    status.style.color = "#1a73e8";
                    circle.style.borderColor = "#1a73e8";
                    onComplete(true);
                } else {
                    status.innerText = "Rhythm mismatch. Retrying...";
                    status.style.color = "#d93025";
                    taps = [];
                    setTimeout(() => {
                        status.style.color = "#70757a";
                        flashInterval = setInterval(flash, 1500);
                        status.innerText = "Try again...";
                    }, 1200);
                }
            }
        };
    };
})();
