(function() {
    'use strict';
    
    // Security Registry for bot signals
    const registry = {
        moves: [],
        clicks: [],
        scrolls: 0,
        startTime: Date.now(),
        lastPos: null,
        jitter: [],
        isAutomated: false
    };

    // Tracking heuristics
    document.addEventListener('mousemove', (e) => {
        const now = Date.now();
        if (registry.lastPos) {
            const dx = e.clientX - registry.lastPos.x;
            const dy = e.clientY - registry.lastPos.y;
            const dt = now - registry.lastPos.t || 1;
            const velocity = Math.sqrt(dx*dx + dy*dy) / dt;
            registry.jitter.push(velocity);
            if (registry.jitter.length > 100) registry.jitter.shift();
        }
        registry.lastPos = { x: e.clientX, y: e.clientY, t: now };
        registry.moves.push({ x: e.clientX, y: e.clientY, t: now });
        if (registry.moves.length > 500) registry.moves.shift();
    });

    // Integrity checks
    const checkIntegrity = () => {
        const tests = [
            () => navigator.webdriver,
            () => !!window.cdc_adoQtmx08zj3jaxu_Array,
            () => !!window.domAutomation,
            () => !window.indexedDB,
            () => navigator.languages.length === 0
        ];
        return tests.some(t => { try { return t(); } catch(e) { return true; } });
    };

    window.NCaptchaCore = {
        getPayload: () => {
            const v = registry.jitter.length > 10 ? 
                registry.jitter.reduce((a,b) => a + Math.pow(b - (registry.jitter.reduce((x,y)=>x+y)/registry.jitter.length), 2), 0) / registry.jitter.length : 100;
            
            return {
                biometrics: {
                    variance: v,
                    count: registry.moves.length,
                    duration: (Date.now() - registry.startTime) / 1000,
                    integrity: !checkIntegrity()
                },
                fingerprint: {
                    ua: navigator.userAgent,
                    res: `${window.screen.width}x${window.screen.height}`,
                    tz: Intl.DateTimeFormat().resolvedOptions().timeZone
                }
            };
        },

        renderChallenge: (containerId, onComplete) => {
            const container = document.getElementById(containerId);
            if (!container) return;

            const grid = [
                'https://images.unsplash.com/photo-1541963463532-d68292c34b19?w=150',
                'https://images.unsplash.com/photo-1503676260728-1c00da094a0b?w=150',
                'https://images.unsplash.com/photo-1497633762265-9d179a990aa6?w=150',
                'https://images.unsplash.com/photo-1512820790803-83ca734da794?w=150',
                'https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?w=150',
                'https://images.unsplash.com/photo-1495446815901-a7297e633e8d?w=150',
                'https://images.unsplash.com/photo-1532012197267-da84d127e765?w=150',
                'https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=150',
                'https://images.unsplash.com/photo-1535905557558-afc4877a26fc?w=150'
            ];

            container.innerHTML = `
                <div style="width: 100%; max-width: 400px; background: #fff; border: 1px solid #ccc; font-family: sans-serif; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
                    <div style="background: #2196f3; color: #fff; padding: 15px;">
                        <div style="font-size: 14px;">Please select all images containing</div>
                        <div style="font-size: 24px; font-weight: bold; margin-top: 5px;">BOOKS</div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 4px; padding: 4px; background: #eee;">
                        ${grid.map((src, i) => `
                            <div class="nc-tile" data-idx="${i}" style="aspect-ratio: 1; background: url('${src}') center/cover; cursor: pointer; position: relative; border-radius: 2px;">
                                <div class="nc-mark" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(33, 150, 243, 0.4); display: none; align-items: center; justify-content: center; color: #fff; font-size: 32px;">✓</div>
                            </div>
                        `).join('')}
                    </div>
                    <div style="padding: 10px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #eee;">
                        <div style="display: flex; gap: 12px; font-size: 20px; color: #666;">
                            <span style="cursor: pointer;">🔄</span>
                            <span style="cursor: pointer;">🎧</span>
                        </div>
                        <button id="nc-verify" style="background: #2196f3; color: #fff; border: none; padding: 10px 25px; border-radius: 2px; font-weight: bold; cursor: pointer;">VERIFY</button>
                    </div>
                </div>
            `;

            const selected = new Set();
            container.querySelectorAll('.nc-tile').forEach(t => {
                t.onclick = () => {
                    const idx = t.dataset.idx;
                    const mark = t.querySelector('.nc-mark');
                    if (selected.has(idx)) {
                        selected.delete(idx);
                        mark.style.display = 'none';
                    } else {
                        selected.add(idx);
                        mark.style.display = 'flex';
                    }
                };
            });

            container.querySelector('#nc-verify').onclick = () => {
                if (selected.size > 0) onComplete(true);
            };
        }
    };
})();
