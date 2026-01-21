(function() {
    console.log('NCaptcha: Core engine loading...');
    const securityData = {
        mouse_moves: 0,
        scroll_events: 0,
        paste_detected: false,
        hesitation_time: 0,
        start_time: Date.now(),
        focus_lost_count: 0,
        teleport_detected: false,
        clicks: 0,
        entropy: {
            jitter: [],
            velocity_variance: 0
        }
    };

    let lastX, lastY, lastTime;

    document.addEventListener('mousemove', (e) => {
        securityData.mouse_moves++;
        const now = Date.now();
        if (lastX !== undefined) {
            const dx = e.clientX - lastX;
            const dy = e.clientY - lastY;
            const dt = now - lastTime || 1;
            const velocity = Math.sqrt(dx*dx + dy*dy) / dt;
            
            securityData.entropy.jitter.push(velocity);
            if (securityData.entropy.jitter.length > 50) securityData.entropy.jitter.shift();
            
            if (velocity > 25) securityData.teleport_detected = true;
        }
        lastX = e.clientX;
        lastY = e.clientY;
        lastTime = now;
    });

    document.addEventListener('scroll', () => securityData.scroll_events++);
    document.addEventListener('paste', () => securityData.paste_detected = true);
    document.addEventListener('click', () => securityData.clicks++);
    window.addEventListener('blur', () => securityData.focus_lost_count++);

    // Global security collector
    window.getNCaptchaPayload = () => {
        securityData.hesitation_time = (Date.now() - securityData.start_time) / 1000;
        
        if (securityData.entropy.jitter.length > 10) {
            const mean = securityData.entropy.jitter.reduce((a, b) => a + b) / securityData.entropy.jitter.length;
            securityData.entropy.velocity_variance = securityData.entropy.jitter.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / securityData.entropy.jitter.length;
        }

        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        const debugInfo = gl ? gl.getExtension('WEBGL_debug_renderer_info') : null;
        
        return {
            biometrics: securityData,
            fingerprint: {
                screen: `${window.screen.width}x${window.screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                user_agent: navigator.userAgent,
                webdriver: navigator.webdriver || (navigator.languages === undefined) || !!window.cdc_adoQtmx08zj3jaxu_Array,
                incognito: !window.indexedDB,
                webgl_renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'none',
                platform: navigator.platform,
                memory: navigator.deviceMemory || 'unknown',
                hardware_concurrency: navigator.hardwareConcurrency || 'unknown',
                languages: navigator.languages,
                touch_support: ('ontouchstart' in window) || (navigator.maxTouchPoints > 0)
            }
        };
    };

    window.initInteractiveChallenge = (containerId, type, onComplete) => {
        console.log('NCaptcha: initInteractiveChallenge called', type);
        const container = document.getElementById(containerId);
        if (!container) return;

        const gridImages = [
            'https://images.unsplash.com/photo-1541963463532-d68292c34b19?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1503676260728-1c00da094a0b?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1497633762265-9d179a990aa6?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1495446815901-a7297e633e8d?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1532012197267-da84d127e765?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1481627834876-b7833e8f5570?auto=format&fit=crop&w=150&q=80',
            'https://images.unsplash.com/photo-1535905557558-afc4877a26fc?auto=format&fit=crop&w=150&q=80'
        ];

        container.innerHTML = `
            <div class="h-captcha-clone" style="width: 380px; background: #fff; border: 1px solid #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 2px;">
                <div style="background: #2196f3; color: #fff; padding: 15px; position: relative;">
                    <div style="font-size: 14px; margin-bottom: 5px;">Select all images with</div>
                    <div style="font-size: 22px; font-weight: bold; text-transform: uppercase;">Books</div>
                    <div style="position: absolute; right: 15px; top: 15px; background: #fff; color: #2196f3; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; font-size: 20px; border-radius: 2px;">?</div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 2px; padding: 2px; background: #eee;">
                    ${gridImages.map((src, i) => `
                        <div class="captcha-tile" data-index="${i}" style="aspect-ratio: 1; background: url('${src}') center/cover; cursor: pointer; position: relative;">
                            <div class="tile-overlay" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(33, 150, 243, 0.4); display: none; align-items: center; justify-content: center; color: #fff; font-size: 24px;">✓</div>
                        </div>
                    `).join('')}
                </div>
                <div style="padding: 10px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #eee;">
                    <div style="display: flex; gap: 10px;">
                        <span style="font-size: 20px; cursor: pointer; opacity: 0.6;">🔄</span>
                        <span style="font-size: 20px; cursor: pointer; opacity: 0.6;">🎧</span>
                        <span style="font-size: 20px; cursor: pointer; opacity: 0.6;">ℹ️</span>
                    </div>
                    <button id="verify-captcha" style="background: #2196f3; color: #fff; border: none; padding: 10px 24px; border-radius: 2px; font-weight: bold; cursor: pointer;">VERIFY</button>
                </div>
                <div style="font-size: 10px; color: #999; text-align: right; padding: 5px 15px;">
                    Protected by <b>NCaptcha</b>
                </div>
            </div>
        `;

        const tiles = container.querySelectorAll('.captcha-tile');
        const selected = new Set();
        
        tiles.forEach(tile => {
            tile.onclick = () => {
                const idx = tile.dataset.index;
                if (selected.has(idx)) {
                    selected.delete(idx);
                    tile.querySelector('.tile-overlay').style.display = 'none';
                } else {
                    selected.add(idx);
                    tile.querySelector('.tile-overlay').style.display = 'flex';
                }
            };
        });

        container.querySelector('#verify-captcha').onclick = () => {
            if (selected.size > 0) {
                onComplete(true);
            }
        };
    };
    console.log('NCaptcha: Core engine ready.');
})();
