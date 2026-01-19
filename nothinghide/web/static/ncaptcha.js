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
            <div class="captcha-widget" style="background: #ffffff; border: 1px solid #000000; padding: 15px; text-align: left; border-radius: 4px; box-shadow: none; max-width: 350px; margin: 0 auto; font-family: 'Space Mono', monospace; border-left: 4px solid #000000;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 10px;">
                    <div style="display: flex; align-items: center;">
                        <img src="/static/captcha-icon.png" style="width: 24px; height: 24px; margin-right: 10px; object-fit: contain; filter: grayscale(1);">
                        <div style="font-size: 12px; color: #000; font-weight: bold; letter-spacing: 1px; text-transform: uppercase;">Security Verification</div>
                    </div>
                    <div style="font-size: 9px; color: #666; font-style: italic;">v4.2.0-secure</div>
                </div>
                
                <div style="display: flex; align-items: center; gap: 15px; padding: 5px 0;">
                    <div id="beat-circle" style="width: 50px; height: 50px; background: #fff; border: 2px solid #000; border-radius: 4px; position: relative; cursor: pointer; transition: all 0.1s; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                        <div id="beat-ring" style="position: absolute; top: -5px; left: -5px; right: -5px; bottom: -5px; border: 2px solid #000; border-radius: 4px; opacity: 0; transition: opacity 0.1s;"></div>
                        <div style="width: 8px; height: 8px; background: #000; border-radius: 1px;"></div>
                    </div>
                    
                    <div style="flex-grow: 1;">
                        <div style="font-size: 11px; color: #000; margin-bottom: 4px; font-weight: bold;">RHYTHM SENSOR</div>
                        <div id="beat-status" style="font-size: 10px; color: #666; text-transform: uppercase;">TAP IN SYNC WITH PULSE</div>
                    </div>
                </div>
                
                <div style="margin-top: 15px; display: flex; align-items: center; justify-content: space-between; font-size: 9px; color: #999; border-top: 1px solid #f1f1f1; padding-top: 8px;">
                    <span>NOTHINGHIDE INTELLIGENCE</span>
                    <span style="color: #000; font-weight: bold;">[ ENCRYPTED ]</span>
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
            setTimeout(() => { ring.style.opacity = '0'; }, 100);
        };

        flashInterval = setInterval(flash, 1500);

        circle.onclick = (e) => {
            e.stopPropagation();
            const now = Date.now();
            const elapsedSinceStart = now - startTime;
            const cyclePos = elapsedSinceStart % 1500;
            const distToFlash = Math.min(cyclePos, 1500 - cyclePos);
            
            taps.push(distToFlash);
            circle.style.backgroundColor = '#000';
            setTimeout(() => { 
                circle.style.backgroundColor = '#fff';
            }, 50);

            if (taps.length === 1) status.innerText = "CAPTURING PULSE [1/3]";
            if (taps.length === 2) status.innerText = "CAPTURING PULSE [2/3]";
            if (taps.length === 3) {
                clearInterval(flashInterval);
                const avgDist = taps.reduce((a, b) => a + b) / 3;
                if (avgDist < 400) {
                    status.innerText = "IDENTITY VERIFIED";
                    status.style.color = "#000";
                    circle.style.borderColor = "#000";
                    onComplete(true);
                } else {
                    status.innerText = "SYNC FAILED. REBOOTING...";
                    status.style.color = "#ff0000";
                    taps = [];
                    setTimeout(() => {
                        status.style.color = "#666";
                        flashInterval = setInterval(flash, 1500);
                        status.innerText = "READY FOR SYNC";
                    }, 1000);
                }
            }
        };
    };
})();
